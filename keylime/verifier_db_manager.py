"""Shared database session management and utilities for the verifier.

This module provides DB session management, agent state helpers, and other
shared utilities used by verifier controllers, the push agent monitor, and
the polling engine. It was extracted from cloud_verifier_tornado.py to
decouple controllers from the legacy polling code.
"""

import sys
import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import config, keylime_logging, push_agent_monitor
from keylime.agentstates import AgentAttestState, AgentAttestStates
from keylime.config import DEFAULT_TIMEOUT
from keylime.da import record
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierAttestations, VerifierMbpolicy
from keylime.failure import set_severity_config
from keylime.models.verifier import Attestation, EvidenceItem
from keylime.shared_data import (
    cache_policy,
    cleanup_agent_policy_cache,
    get_cached_policy,
    initialize_agent_policy_cache,
)

logger = keylime_logging.init_logging("verifier")


# Module-level globals that are initialized lazily to avoid loading
# verifier configuration when this module is imported by other components
engine: Optional[Engine] = None
rmc: Optional[Any] = None
_session_manager: Optional[SessionManager] = None
_verifier_config_initialized = False
_init_lock = threading.Lock()


def _initialize_verifier_config() -> None:
    """
    Initialize verifier-specific configuration.
    This is called lazily to avoid loading verifier config when this module
    is imported by other components (e.g., registrar).

    Thread-safe initialization using double-checked locking pattern.
    """
    global engine, rmc, _session_manager, _verifier_config_initialized

    # Fast path: already initialized (no lock needed)
    if _verifier_config_initialized:
        return

    # Acquire lock for initialization
    with _init_lock:
        # Double-check after acquiring lock
        if _verifier_config_initialized:
            return

        set_severity_config(
            config.getlist("verifier", "severity_labels"), config.getlist("verifier", "severity_policy")
        )

        try:
            engine = make_engine("cloud_verifier")
        except SQLAlchemyError as err:
            logger.error("Error creating SQL engine or session: %s", err)
            sys.exit(1)

        try:
            rmc = record.get_record_mgt_class(config.get("verifier", "durable_attestation_import", fallback=""))
            if rmc:
                rmc = rmc("verifier")
        except record.RecordManagementException as rme:
            logger.error("Error initializing Durable Attestation: %s", rme)
            sys.exit(1)

        # Initialize singleton session manager for this worker process
        _session_manager = SessionManager()

        _verifier_config_initialized = True


def reset_verifier_config() -> None:
    """
    Reset verifier configuration state after fork.

    This should be called by worker processes after forking to clear
    inherited global state and force re-initialization with fresh
    database connections.
    """
    global engine, rmc, _session_manager, _verifier_config_initialized

    if engine:
        engine.dispose()

    engine = None
    rmc = None
    _session_manager = None
    _verifier_config_initialized = False


@contextmanager
def session_context() -> Iterator[Session]:
    """
    Context manager for database sessions that ensures proper cleanup.
    To use:
        with session_context() as session:
            # use session
    """
    _initialize_verifier_config()
    assert _session_manager is not None, "Session manager not initialized"
    with _session_manager.session_context(engine) as session:  # type: ignore
        yield session


def get_AgentAttestStates() -> AgentAttestStates:
    return AgentAttestStates.get_instance()


# The "exclude_db" dict values are removed from the response before adding the dict to the DB
# This is because we want these values to remain ephemeral and not stored in the database.
exclude_db: Dict[str, Any] = {
    "registrar_data": "",
    "nonce": "",
    "b64_encrypted_V": "",
    "provide_V": True,
    "num_retries": 0,
    "pending_event": None,
    "request_timeout": DEFAULT_TIMEOUT,
    # the following 3 items are updated to VerifierDB only when the AgentState is stored
    "boottime": "",
    "ima_pcrs": [],
    "pcr10": "",
    "next_ima_ml_entry": 0,
    "learned_ima_keyrings": {},
    "ssl_context": None,
}


def _from_db_obj(agent_db_obj: VerfierMain) -> Dict[str, Any]:
    fields = [
        "agent_id",
        "v",
        "ip",
        "port",
        "operational_state",
        "public_key",
        "tpm_policy",
        "meta_data",
        "ima_sign_verification_keys",
        "revocation_key",
        "accept_tpm_hash_algs",
        "accept_tpm_encryption_algs",
        "accept_tpm_signing_algs",
        "hash_alg",
        "enc_alg",
        "sign_alg",
        "boottime",
        "ima_pcrs",
        "pcr10",
        "next_ima_ml_entry",
        "learned_ima_keyrings",
        "supported_version",
        "mtls_cert",
        "ak_tpm",
        "attestation_count",
        "last_received_quote",
        "last_successful_attestation",
        "tpm_clockinfo",
        "accept_attestations",
    ]
    agent_dict = {}
    for field in fields:
        agent_dict[field] = getattr(agent_db_obj, field, None)

    # add default fields that are ephemeral
    for key, val in exclude_db.items():
        agent_dict[key] = val

    return agent_dict


def verifier_read_policy_from_cache(stored_agent: VerfierMain) -> str:
    checksum = ""
    name = "empty"
    agent_id = str(stored_agent.agent_id)

    # Initialize agent policy cache if it doesn't exist
    initialize_agent_policy_cache(agent_id)

    if stored_agent.ima_policy:
        checksum = str(stored_agent.ima_policy.checksum)
        name = stored_agent.ima_policy.name

    # Check if policy is already cached
    cached_policy = get_cached_policy(agent_id, checksum)
    if cached_policy is not None:
        return cached_policy

    # Policy not cached, need to clean up and load from database
    cleanup_agent_policy_cache(agent_id, checksum)

    logger.debug(
        "IMA policy named %s, with checksum %s, used by agent %s is not present on policy cache on this verifier, performing SQLAlchemy load",
        name,
        checksum,
        agent_id,
    )

    # Actually contacts the database and load the (large) ima_policy column for "allowlists" table
    ima_policy = stored_agent.ima_policy.ima_policy
    assert isinstance(ima_policy, str)

    # Cache the policy for future use
    cache_policy(agent_id, checksum, ima_policy)

    return ima_policy


def verifier_db_delete_agent(session: Session, agent_id: str) -> None:
    # Cancel any pending timeout for PUSH mode agents
    push_agent_monitor.cancel_agent_timeout(agent_id)

    get_AgentAttestStates().delete_by_agent_id(agent_id)
    # Delete in FK dependency order:
    # Push-mode tables:
    #   1. evidence_items (FK to attestations)
    #   2. attestations (FK to agent)
    # Legacy/shared tables:
    #   3. VerifierAttestations (legacy attestations table, FK to agent)
    # Agent and policies:
    #   4. agent
    #   5. allowlists/mbpolicies (by name, not FK)
    # NOTE: Authentication sessions are NOT deleted when an agent is removed.
    # This allows agents to maintain their authentication tokens through policy
    # updates (DELETE + POST) and re-enrollment without needing to re-authenticate.
    # Sessions will expire naturally based on their token_expires_at timestamp.
    EvidenceItem.delete_all(agent_id=agent_id, session_=session)
    Attestation.delete_all(agent_id=agent_id, session_=session)
    session.query(VerifierAttestations).filter_by(agent_id=agent_id).delete()
    session.query(VerfierMain).filter_by(agent_id=agent_id).delete()
    session.query(VerifierAllowlist).filter_by(name=agent_id).delete()
    session.query(VerifierMbpolicy).filter_by(name=agent_id).delete()
    session.commit()


def store_attestation_state(agentAttestState: AgentAttestState) -> None:
    # Only store if IMA log was evaluated
    if agentAttestState.get_ima_pcrs():
        agent_id = agentAttestState.agent_id
        try:
            with session_context() as session:
                update_agent = session.get(VerfierMain, agentAttestState.get_agent_id())  # type: ignore[attr-defined]
                assert update_agent
                update_agent.boottime = agentAttestState.get_boottime()  # pyright: ignore
                update_agent.next_ima_ml_entry = agentAttestState.get_next_ima_ml_entry()  # pyright: ignore
                ima_pcrs_dict = agentAttestState.get_ima_pcrs()
                update_agent.ima_pcrs = list(ima_pcrs_dict.keys())  # pyright: ignore
                for pcr_num, value in ima_pcrs_dict.items():
                    setattr(update_agent, f"pcr{pcr_num}", value)
                update_agent.learned_ima_keyrings = agentAttestState.get_ima_keyrings().to_json()  # pyright: ignore
                session.add(update_agent)
                # session.commit() is automatically called by context manager
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error on storing attestation state for agent %s: %s", agent_id, e)
