import base64
import hmac
import secrets
import uuid
from datetime import timedelta
from typing import Any, Dict, Optional, Sequence

from sqlalchemy.orm import Session

from keylime import config, keylime_logging
from keylime.crypto import hash_token_for_log, hash_token_for_storage
from keylime.db.keylime_db import SessionManager, make_engine
from keylime.db.verifier_db import VerfierMain
from keylime.models.base import *
from keylime.models.base import db_manager
from keylime.shared_data import get_shared_memory
from keylime.tpm.errors import (
    HashAlgorithmMismatch,
    IncorrectSignature,
    ObjectNameMismatch,
    QualifyingDataMismatch,
    SignatureAlgorithmMismatch,
)
from keylime.tpm.tpm_main import Tpm

logger = keylime_logging.init_logging("verifier")

_engine = None


def get_session() -> Session:
    global _engine
    if _engine is None:
        _engine = make_engine("cloud_verifier")
    return SessionManager().make_session(_engine)


class AuthSession(PersistableModel):
    # Explicit attribute declarations for type checkers
    session_id: str  # UUID, primary key for clean URLs
    token_hash: str  # SHA-256 hash of token, indexed for authentication lookups
    token: str  # Plaintext token, virtual field (memory only, never persisted)
    active: bool
    agent_id: str
    nonce: bytes
    nonce_created_at: Any
    nonce_expires_at: Any
    hash_algorithm: str
    signing_scheme: str
    ak_attest: bytes
    ak_sign: bytes
    pop_received_at: Any
    token_expires_at: Any

    @classmethod
    def _schema(cls):
        # TODO: Uncomment
        # cls._belongs_to("agent", VerifierAgent, inverse_of="sessions", preload = False)

        cls._persist_as("sessions")
        # session_id is a UUID for clean URLs (36 chars)
        cls._id("session_id", String(36))
        # token_hash is SHA-256 hash of plaintext token for authentication lookups (64 hex chars)
        cls._field("token_hash", String(64))
        # Virtual field for plaintext token - only held in memory, never persisted
        cls._virtual("token", String(64))
        cls._field("active", Boolean)
        cls._field("agent_id", String(80))
        cls._field("nonce", Nonce)
        cls._field("nonce_created_at", Timestamp)
        cls._field("nonce_expires_at", Timestamp)
        cls._virtual("supported_hash_algorithms", List)
        cls._virtual("supported_signing_schemes", List)
        cls._field("hash_algorithm", String(10))
        cls._field("signing_scheme", String(10))
        cls._field("ak_attest", Binary)
        cls._field("ak_sign", Binary)
        cls._field("pop_received_at", Timestamp)
        cls._field("token_expires_at", Timestamp)

    @classmethod
    def _get_sessions_cache(cls) -> Dict[str, Dict[str, Any]]:
        """Get the primary session cache: session_id -> session_data."""
        shared_memory = get_shared_memory()
        return shared_memory.get_or_create_dict("auth_sessions")

    @classmethod
    def _get_token_index(cls) -> Dict[str, str]:
        """Get the token index: token_hash -> session_id."""
        shared_memory = get_shared_memory()
        return shared_memory.get_or_create_dict("auth_sessions_token_index")

    @classmethod
    def cache_session(cls, session_data: Dict[str, Any]) -> None:
        """Store session data in shared memory cache with token index.

        Primary storage is by session_id. A secondary index maps token_hash
        to session_id for fast authentication lookups.
        """
        session_id = session_data.get("session_id")
        token_hash = session_data.get("token_hash")

        if session_id:
            sessions_cache = cls._get_sessions_cache()
            sessions_cache[session_id] = session_data

            # Add token_hash -> session_id index entry
            if token_hash:
                token_index = cls._get_token_index()
                token_index[token_hash] = session_id

    @classmethod
    def uncache_session(cls, session_id: Optional[str] = None, token_hash: Optional[str] = None) -> None:
        """Remove session from cache and token index."""
        sessions_cache = cls._get_sessions_cache()
        token_index = cls._get_token_index()

        if session_id and session_id in sessions_cache:
            # Get token_hash from session data before deleting
            session_data = sessions_cache.get(session_id)
            if session_data and not token_hash:
                token_hash = session_data.get("token_hash")
            del sessions_cache[session_id]

        if token_hash and token_hash in token_index:
            del token_index[token_hash]

    @classmethod
    def _first(cls, **kwargs: Any) -> Optional["AuthSession"]:
        """Query for a single record by field values (uses LIMIT 1).

        More efficient than all()[0] when only one result is needed.
        """
        from keylime.models.base import db_manager  # pylint: disable=import-outside-toplevel

        if cls.schema_awaiting_processing:
            cls.process_schema()

        with db_manager.session_context() as session:
            result = cls._query(session, (), kwargs).first()

        if result:
            return cls(result)  # type: ignore[return-value]
        return None

    @classmethod
    def get_by_token(cls, token: str) -> Optional["AuthSession"]:
        """Look up an authentication session by token.

        First checks the shared memory cache via token index (fast path),
        then falls back to database lookup by indexed token_hash column.

        Uses constant-time comparison (hmac.compare_digest) to prevent
        timing attacks when verifying the token_hash.

        Args:
            token: The plaintext session token to look up

        Returns:
            AuthSession if found, None otherwise
        """
        if not token:
            return None

        computed_token_hash = hash_token_for_storage(token)

        # Fast path: check token index -> session cache
        token_index = cls._get_token_index()
        if computed_token_hash in token_index:
            session_id = token_index[computed_token_hash]
            sessions_cache = cls._get_sessions_cache()
            if session_id in sessions_cache:
                session_data = sessions_cache[session_id]
                stored_hash = session_data.get("token_hash", "")
                # Constant-time comparison to prevent timing attacks
                if hmac.compare_digest(stored_hash, computed_token_hash):
                    # Reconstruct AuthSession from cached data
                    return cls._from_cache(session_data)

        # Slow path: query database by token_hash (uses LIMIT 1)
        auth_session = cls._first(token_hash=computed_token_hash)
        if auth_session is None:
            return None

        # Use constant-time comparison to prevent timing attacks
        if not hmac.compare_digest(auth_session.token_hash, computed_token_hash):  # type: ignore[attr-defined]
            return None
        return auth_session

    @classmethod
    def _from_cache(cls, session_data: Dict[str, Any]) -> "AuthSession":
        """Reconstruct an AuthSession object from cached session data."""
        session = cls.empty()  # type: ignore[return-value]
        session.session_id = session_data["session_id"]  # type: ignore[attr-defined]
        session.token_hash = session_data.get("token_hash", "")  # type: ignore[attr-defined]
        session.token = session_data.get("token", "")  # type: ignore[attr-defined]
        session.agent_id = session_data["agent_id"]
        session.active = session_data.get("active", False)
        session.nonce = session_data.get("nonce")
        session.nonce_created_at = session_data.get("nonce_created_at")
        session.nonce_expires_at = session_data.get("nonce_expires_at")
        session.hash_algorithm = session_data.get("hash_algorithm", "")
        session.signing_scheme = session_data.get("signing_scheme", "")
        session.token_expires_at = session_data.get("token_expires_at")
        session.pop_received_at = session_data.get("pop_received_at")
        return session  # type: ignore[return-value]

    @classmethod
    def get_by_session_id(cls, session_id: str) -> Optional["AuthSession"]:
        """Look up an authentication session by session_id.

        First checks the shared memory cache (fast path), then falls back
        to database lookup by primary key.

        Args:
            session_id: The session UUID to look up

        Returns:
            AuthSession if found, None otherwise
        """
        if not session_id:
            return None

        # Fast path: check cache first
        sessions_cache = cls._get_sessions_cache()
        if session_id in sessions_cache:
            session_data = sessions_cache[session_id]
            return cls._from_cache(session_data)

        # Slow path: query database by primary key
        return cls.get(session_id)

    @classmethod
    def authenticate_agent(cls, token: str):  # type: ignore[no-untyped-def]
        """Authenticate an agent using their session token.

        Uses indexed database lookup by token hash for performance (O(1) instead of O(n)).
        Tokens are hashed before lookup since only hashes are stored in the database.

        Args:
            token: The session token to verify

        Returns:
            VerfierMain object if authenticated, False otherwise
        """
        # Use indexed lookup by token hash (much faster than scanning all sessions)
        auth_session = cls.get_by_token(token)

        if not auth_session:
            return False

        # Validate session is active
        if not getattr(auth_session, "active", False):
            return False

        # Validate session hasn't expired
        token_expires_at = getattr(auth_session, "token_expires_at", None)
        if token_expires_at and token_expires_at < Timestamp.now():
            logger.debug(
                "Authentication attempted with expired token for agent '%s' (expired at %s)",
                getattr(auth_session, "agent_id", "unknown"),
                token_expires_at,
            )
            return False

        # Use old engine to query VerfierMain (legacy model)
        session = get_session()
        agent = (
            session.query(VerfierMain)
            .filter(VerfierMain.agent_id == auth_session.agent_id)  # type: ignore[attr-defined]
            .one_or_none()
        )

        return agent

    @classmethod
    def create(
        cls, agent: Optional[VerfierMain], data: Dict[str, Any], agent_id: Optional[str] = None
    ) -> "AuthSession":
        session = AuthSession.empty()  # type: ignore[return-value]
        # Use provided agent_id if agent is None (for unenrolled agents)
        session.initialise(agent.agent_id if agent else agent_id)  # type: ignore[attr-defined]
        session.receive_capabilities(data, agent)  # type: ignore[attr-defined]
        return session  # type: ignore[return-value]

    @classmethod
    def create_in_memory(cls, agent_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an authentication session in memory (not persisted to DB).

        This is used for the POST /sessions endpoint where we don't yet know
        if the agent is enrolled. Returns a dictionary with session data.
        """
        # Generate UUID for session_id (clean URLs) and token with its hash
        session_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        token_hash = hash_token_for_storage(token)

        # Extract auth capabilities from request
        data = request_data.get("data", {})
        attributes = data.get("attributes", {})
        auth_supported = attributes.get("authentication_supported", [])

        # Verify tpm_pop is supported
        if not any(method.get("authentication_type") == "tpm_pop" for method in auth_supported):
            return {"errors": {"authentication_supported": ["must include tpm_pop authentication type"]}}

        # Generate nonce
        nonce = Nonce.generate(128)
        nonce_lifetime = config.getint("verifier", "nonce_lifetime", fallback=60)
        now = Timestamp.now()
        nonce_expires_at = now + timedelta(seconds=nonce_lifetime)

        # Set default algorithms (will be negotiated with agent config on PATCH)
        hash_algorithm = "sha256"
        signing_scheme = "rsassa"

        # Build response
        response = {
            "data": {
                "type": "session",
                "id": session_id,  # UUID for clean URLs
                "attributes": {
                    "agent_id": agent_id,
                    "authentication_requested": [
                        {
                            "authentication_class": "pop",
                            "authentication_type": "tpm_pop",
                            "chosen_parameters": {"challenge": base64.b64encode(nonce).decode("utf-8")},
                        }
                    ],
                    "created_at": now.isoformat(),
                    "challenges_expire_at": nonce_expires_at.isoformat(),
                },
            }
        }

        return {
            "session_id": session_id,
            "token": token,
            "token_hash": token_hash,
            "agent_id": agent_id,
            "nonce": nonce,
            "nonce_created_at": now,
            "nonce_expires_at": nonce_expires_at,
            "hash_algorithm": hash_algorithm,
            "signing_scheme": signing_scheme,
            "response": response,
        }

    @classmethod
    def create_from_memory(
        cls, session_data: Dict[str, Any], agent: VerfierMain, pop_request: Dict[str, Any]
    ) -> "AuthSession":
        """Create an AuthSession from memory data and verify PoP.

        This is used for the PATCH /sessions/:id endpoint to persist
        the session to the database after verifying the proof of possession.

        """
        session = AuthSession.empty()  # type: ignore[return-value]
        plaintext_token = session_data["token"]
        # Store the plaintext token in the virtual field (memory only)
        session.token = plaintext_token  # type: ignore[attr-defined]
        # session_id is UUID, token_hash is hash of plaintext token
        session.session_id = session_data["session_id"]  # type: ignore[attr-defined]
        session.token_hash = session_data["token_hash"]  # type: ignore[attr-defined]
        session.agent_id = session_data["agent_id"]
        session.nonce = session_data["nonce"]
        session.nonce_created_at = session_data["nonce_created_at"]
        session.nonce_expires_at = session_data["nonce_expires_at"]
        session.hash_algorithm = session_data["hash_algorithm"]
        session.signing_scheme = session_data["signing_scheme"]
        session.active = False

        # Verify the proof of possession
        session.receive_pop(agent, pop_request)  # type: ignore[attr-defined]

        return session  # type: ignore[return-value]

    @classmethod
    def delete_stale_from_memory(cls, agent_id: str) -> None:
        """Delete stale sessions from shared memory for an agent.

        Removes sessions where:
        - nonce_expires_at has passed (for pending auth sessions)
        - token_expires_at has passed (for active sessions with tokens)
        """
        sessions_cache = cls._get_sessions_cache()
        now = Timestamp.now()
        stale_sessions = []

        for session_id, session_data in list(sessions_cache.items()):
            if session_data.get("agent_id") == agent_id:
                # Check nonce expiration (for pending auth sessions)
                nonce_expires = session_data.get("nonce_expires_at")
                # Check token expiration (for active sessions with tokens)
                token_expires = session_data.get("token_expires_at")

                if (nonce_expires and nonce_expires < now) or (token_expires and token_expires < now):
                    stale_sessions.append((session_id, session_data.get("token_hash")))

        for session_id, token_hash in stale_sessions:
            cls.uncache_session(session_id=session_id, token_hash=token_hash)
            logger.debug("Deleted stale session %s for agent '%s'", session_id, agent_id)

    @classmethod
    def delete_stale(cls, agent_id: str) -> None:
        """Delete stale sessions from database for an agent.

        Removes sessions where:
        - nonce_expires_at has passed (for pending auth sessions)
        - token_expires_at has passed (for active sessions with tokens)
        """
        agent_sessions = AuthSession.all(agent_id=agent_id)
        now = Timestamp.now()

        for session in agent_sessions:
            nonce_expires = session.nonce_expires_at  # type: ignore[attr-defined]
            token_expires = session.token_expires_at  # type: ignore[attr-defined]

            # Delete if expired (expiration time is in the past)
            if (nonce_expires and nonce_expires < now) or (token_expires and token_expires < now):
                session.delete()

    @classmethod
    def get_active_session_for_agent(cls, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get the active authentication session for an agent.

        First checks shared memory (fast), then falls back to database (persistence).
        This ensures token extension works even after verifier restarts.

        Args:
            agent_id: The agent identifier

        Returns:
            Session data dictionary if found and active, None otherwise
        """
        sessions_cache = cls._get_sessions_cache()
        now = Timestamp.now()

        # First, try to find active session in shared memory (fast path)
        for _session_id, session_data in list(sessions_cache.items()):
            if (
                session_data.get("agent_id") == agent_id
                and session_data.get("active")
                and session_data.get("token_expires_at", now) > now
            ):
                return session_data  # type: ignore[return-value,no-any-return]

        # If not in shared memory, check database (needed after verifier restart)
        db_sessions = cls.all(agent_id=agent_id, active=True)
        for db_session in db_sessions:
            if db_session.token_expires_at and db_session.token_expires_at > now:  # type: ignore[attr-defined]
                # Reconstruct session data dictionary format expected by callers
                session_id = db_session.session_id  # type: ignore[attr-defined]
                token_hash = db_session.token_hash  # type: ignore[attr-defined]
                session_data = {
                    "session_id": session_id,
                    "token_hash": token_hash,
                    "agent_id": db_session.agent_id,  # type: ignore[attr-defined]
                    "active": db_session.active,  # type: ignore[attr-defined]
                    "token_expires_at": db_session.token_expires_at,  # type: ignore[attr-defined]
                }

                # Re-populate dual-key cache for future fast lookups
                cls.cache_session(session_data)

                logger.debug(
                    "Restored auth session for agent '%s' from database (session_id: %s)",
                    agent_id,
                    session_id[:8] if session_id else "",
                )

                return session_data  # type: ignore[return-value]

        return None

    @classmethod
    def delete_active_session_for_agent(cls, agent_id: str) -> None:
        """Delete active authentication session for an agent.

        Used when an agent fails attestation or is excluded to invalidate
        their authentication token. Also used before creating a new session
        to prevent multiple concurrent active sessions for the same agent.

        Args:
            agent_id: The agent identifier
        """
        sessions_cache = cls._get_sessions_cache()

        deleted_count = 0
        for session_id, session_data in list(sessions_cache.items()):
            if session_data.get("agent_id") == agent_id and session_data.get("active"):
                cls.uncache_session(session_id=session_id, token_hash=session_data.get("token_hash"))
                deleted_count += 1
                logger.info("Deleted active session %s for agent '%s'", session_id, agent_id)

        if deleted_count > 0:
            logger.info("Deleted %d active session(s) for agent '%s' from memory", deleted_count, agent_id)

        # Also delete from database to ensure persistence (single DELETE query)
        if cls.schema_awaiting_processing:
            cls.process_schema()

        with db_manager.session_context() as session:
            agent_id_col = cls.db_table.columns["agent_id"]
            active_col = cls.db_table.columns["active"]
            delete_stmt = cls.db_table.delete().where((agent_id_col == agent_id) & (active_col == True))  # noqa: E712
            result = session.execute(delete_stmt)
            db_deleted_count = result.rowcount
            session.commit()

        if db_deleted_count > 0:
            logger.debug("Deleted %d active database session(s) for agent '%s'", db_deleted_count, agent_id)

    @classmethod
    def clear_expired_sessions_on_startup(cls) -> None:
        """Clear expired authentication sessions from database on verifier startup.

        This is called on verifier startup to clean up expired sessions that
        accumulated while the verifier was down. Valid sessions are preserved
        and will be restored from database to memory when accessed.

        Note: Shared memory is always empty after restart, so no need to clear it.
        Sessions will be lazy-loaded from database as needed.
        """
        if cls.schema_awaiting_processing:
            cls.process_schema()

        # ISO8601 timestamps are lexicographically sortable, so string comparison works
        now_str = Timestamp.now().isoformat(timespec="microseconds")

        # Single DELETE query instead of fetching all + individual deletes
        with db_manager.session_context() as session:
            token_expires_col = cls.db_table.columns["token_expires_at"]
            delete_stmt = cls.db_table.delete().where(token_expires_col < now_str)
            result = session.execute(delete_stmt)
            expired_count = result.rowcount
            session.commit()

        if expired_count > 0:
            logger.info(
                "Cleaned up %d expired authentication session(s) from database on verifier startup", expired_count
            )
        else:
            logger.debug("No expired sessions to clean up on verifier startup")

    def initialise(self, agent_id: str) -> None:
        if "agent_id" not in self.values:
            self.agent_id = agent_id

        if "session_id" not in self.values:
            # Generate UUID for session_id (clean URLs)
            self.session_id = str(uuid.uuid4())
            # Generate a cryptographically secure token
            plaintext_token = secrets.token_urlsafe(32)
            # Store the plaintext token in the virtual field (memory only, not persisted)
            self.token = plaintext_token
            # token_hash is the SHA-256 hash of the token for secure storage
            self.token_hash = hash_token_for_storage(plaintext_token)

        if "active" not in self.values:
            self.active = False

    def receive_capabilities(self, data: Dict[str, Any], agent: Optional[VerfierMain]) -> None:
        if self.nonce:  # type: ignore[attr-defined]
            raise ValueError("AuthSession object cannot be updated as it has already received agent capabilities")

        # Extract authentication_supported from the data structure
        attributes = data.get("data", {}).get("attributes", {})
        auth_supported = attributes.get("authentication_supported", [])

        # For now, we only support tpm_pop, so just verify it's in the list
        # In the future, this could be extended to negotiate other methods
        if not any(method.get("authentication_type") == "tpm_pop" for method in auth_supported):
            self._add_error("authentication_supported", "must include tpm_pop authentication type")
            return

        # Set default supported algorithms for TPM PoP
        # These are the algorithms commonly supported by TPM 2.0
        self.supported_hash_algorithms = [  # pylint: disable=attribute-defined-outside-init
            "sha256",
            "sha384",
            "sha512",
        ]
        self.supported_signing_schemes = ["rsassa", "rsapss", "ecdsa"]  # pylint: disable=attribute-defined-outside-init

        # Generate the nonce the agent should use in the call to TPM2_Certify
        self._set_nonce()  # type: ignore[no-untyped-call]
        # Select algorithms from the list given by the agent
        self._set_algs(data, agent)  # type: ignore[no-untyped-call]

        self._set_timestamps()  # type: ignore[no-untyped-call]

    def receive_pop(self, agent: VerfierMain, data: Dict[str, Any]) -> None:
        if not agent or not agent.agent_id == self.agent_id:  # type: ignore[attr-defined]
            return

        # Set pop_received_at timestamp at the start (required in response even on failure)
        self.pop_received_at = Timestamp.now()

        ak_tpm = base64.b64decode(agent.ak_tpm)  # type: ignore[arg-type]

        # Extract proof from authentication_provided array according to spec
        # Format: data.attributes.authentication_provided[0].data.{message, signature}
        attributes = data.get("data", {}).get("attributes", {})
        auth_provided = attributes.get("authentication_provided", [])

        if not auth_provided or len(auth_provided) == 0:
            self._add_error("authentication_provided", "must include at least one authentication method")
            return

        # Get the first authentication method (should be tpm_pop)
        auth_method = auth_provided[0]
        if auth_method.get("authentication_type") != "tpm_pop":
            self._add_error("authentication_provided", "must include tpm_pop authentication type")
            return

        # Extract message and signature from the proof data
        proof_data = auth_method.get("data", {})
        message = proof_data.get("message")
        signature = proof_data.get("signature")

        if not message or not signature:
            self._add_error("authentication_provided", "must include both message and signature in proof data")
            return

        # Map the spec fields (message/signature) to internal fields (ak_attest/ak_sign)
        self.ak_attest = base64.b64decode(message) if isinstance(message, str) else message
        self.ak_sign = base64.b64decode(signature) if isinstance(signature, str) else signature

        try:
            Tpm.verify_tpm_object(
                ak_tpm,
                ak_tpm,
                self.ak_attest,  # type: ignore[attr-defined]
                self.ak_sign,  # type: ignore[attr-defined]
                qual=self.nonce,  # type: ignore[attr-defined]
                _hash_alg=self.hash_algorithm,  # type: ignore[attr-defined,arg-type]
                _sign_alg=self.signing_scheme,  # type: ignore[attr-defined,arg-type]
            )
        except QualifyingDataMismatch as e:
            logger.error("QualifyingDataMismatch: %s", e)
            self._add_error("ak_attest", "must include the nonce as qualifying data")
        except ObjectNameMismatch as e:
            logger.error("ObjectNameMismatch: %s", e)
            self._add_error("ak_attest", "must include the AK of the agent as the certified object")
        except HashAlgorithmMismatch as e:
            logger.error("HashAlgorithmMismatch: %s", e)
            self._add_error("ak_attest", f"must specify {self.hash_algorithm} as the hash algorithm")
        except SignatureAlgorithmMismatch as e:
            logger.error("SignatureAlgorithmMismatch: %s", e)
            self._add_error("ak_attest", f"must specify {self.signing_scheme} as the signature scheme")
        except IncorrectSignature as e:
            logger.error("IncorrectSignature: %s", e)
            self._add_error("ak_attest", "must verify against ak_attest using the agent's AK")
        except Exception as e:
            logger.error("Unexpected error during TPM verification: %s: %s", type(e).__name__, e)
            self._add_error("verification", f"TPM verification failed: {str(e)}")

        # Set token expiration (only on successful validation)
        session_lifetime = config.getint("verifier", "session_lifetime")
        self.token_expires_at = Timestamp.now() + timedelta(seconds=session_lifetime)
        self.active = True

    def _set_nonce(self):
        if "nonce" not in self.values:
            self.nonce = Nonce.generate(128)

    def _set_algs(self, data, agent):
        # pylint: disable=no-else-break

        supported_hash_algorithms = data.get("supported_hash_algorithms")
        supported_signing_schemes = data.get("supported_signing_schemes")

        # If agent is None (unenrolled), use default algorithms
        if not agent:
            # Use first algorithm from the agent's supported list as default
            if supported_hash_algorithms:
                self.hash_algorithm = supported_hash_algorithms[0]
            if supported_signing_schemes:
                self.signing_scheme = supported_signing_schemes[0]
            return

        # Set hashing algorithm that is first match from the list of hashing supported by the agent tpm
        # and the list of accpeted hashing algorithm
        for hash_alg in agent.accept_tpm_hash_algs:
            if hash_alg in supported_hash_algorithms:
                self.hash_algorithm = hash_alg
                break

        if not self.hash_algorithm:
            self._add_error(
                "supported_hash_algorithms",
                f"does not contain any accepted hashing algorithm for agent '{agent.agent_id}'",
            )

        # Set signing algorithm that is first match from the list of signing supported by the agent tpm
        # and the list of accpeted signing algorithm
        for signing_scheme in agent.accept_tpm_signing_algs:
            if signing_scheme in supported_signing_schemes:
                self.signing_scheme = signing_scheme
                break

        if not self.signing_scheme:
            self._add_error(
                "supported_signing_schemes",
                f"does not contain any accepeted signing scheme for agent '{agent.agent_id}'",
            )

    def _set_timestamps(self):
        nonce_lifetime = config.getint("verifier", "nonce_lifetime", fallback=60)

        if self.changes.get("nonce"):
            self.nonce_created_at = Timestamp.now()
            self.nonce_expires_at = self.nonce_created_at + timedelta(nonce_lifetime)

        if self.changes.get("ak_attest", "ak_sign"):
            self.pop_received_at = Timestamp.now()

    def render(self, only: Optional[Sequence[str]] = None) -> Dict[str, Any]:  # type: ignore[override]
        if not only:
            only = ["token", "active", "nonce", "agent_id", "token_expires_at"]

        output = super().render(only)
        return output
