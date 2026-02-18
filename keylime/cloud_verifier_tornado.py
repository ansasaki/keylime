"""Polling engine for the Cloud Verifier.

This module contains the polling functions that periodically contact agents
to obtain and verify attestation quotes (pull mode). The HTTP handler classes
and main() entry point have been removed; routing is now handled by the
web framework controllers in keylime.web.verifier.

Functions retained here:
- process_agent(): Main polling state machine
- invoke_get_quote(): Request and verify attestation quotes
- invoke_provide_v(): Provide V key to agents
- invoke_notify_error(): Notify individual agents of revocation events
- notify_error(): Broadcast error notifications to all agents
- update_agent_api_version(): Negotiate API version with agents
- activate_agents(): Reactivate agents on verifier startup
- get_agents_by_verifier_id(): Query agents assigned to a verifier
"""

import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Union

import tornado.ioloop
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from keylime import api_version as keylime_api_version
from keylime import (
    cloud_verifier_common,
    config,
    json,
    keylime_logging,
    revocation_notifier,
    tornado_requests,
    verifier_db_manager,
    web_util,
)
from keylime.common import retry, states
from keylime.common.version import str_to_version
from keylime.config import DEFAULT_TIMEOUT
from keylime.db.verifier_db import VerfierMain, VerifierMbpolicy
from keylime.failure import MAX_SEVERITY_LABEL, Component, Event, Failure
from keylime.ima import ima
from keylime.verifier_db_manager import (
    _from_db_obj,
    exclude_db,
    get_AgentAttestStates,
    session_context,
    store_attestation_state,
    verifier_db_delete_agent,
    verifier_read_policy_from_cache,
)

logger = keylime_logging.init_logging("verifier")


async def update_agent_api_version(
    agent: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT
) -> Union[Dict[str, Any], None]:
    """
    Query agent's /version endpoint and negotiate compatible API version.
    """
    agent_id = agent["agent_id"]
    old_version = agent.get("supported_version")

    logger.info("Agent %s API version bump detected, trying to update stored API version", agent_id)
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "GET",
        f"http://{agent['ip']}:{agent['port']}/version",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response.status_code != 200:
        logger.warning(
            "Could not get agent %s supported API version, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        return None

    try:
        json_response = json.loads(response.body)

        # Try new format first (list of versions)
        agent_versions = json_response["results"].get("supported_versions")

        # Fall back to old format (single version)
        if agent_versions is None:
            agent_versions = json_response["results"].get("supported_version")

        if agent_versions:
            # Negotiate compatible version
            negotiated = keylime_api_version.negotiate_version(agent_versions)

            if negotiated is None:
                # No compatible version
                logger.error(
                    "No compatible API version between verifier and agent %s. "
                    "Agent supports: %s, Verifier supports: %s",
                    agent_id,
                    agent_versions,
                    keylime_api_version.all_versions(),
                )
                return None

            # Check if version actually changed
            if negotiated == old_version:
                logger.debug("Agent %s already using negotiated version %s", agent_id, negotiated)
                return agent  # No change needed

            # Validate negotiated version
            if not keylime_api_version.validate_version(negotiated):
                logger.error("Negotiated version %s for agent %s is invalid", negotiated, agent_id)
                return None

            # Check that the negotiated version is greater than current version (prevent downgrade)
            negotiated_tuple = str_to_version(negotiated)
            if not negotiated_tuple:
                logger.error("Agent %s negotiated version %s is invalid", agent_id, negotiated)
                return None

            # Only check for downgrade if there was a previous version and successful attestation.
            # If attestation_count == 0, the stored version might be a fallback guess from the tenant,
            # not a version the agent actually supported, so we allow the "downgrade".
            attestation_count = agent.get("attestation_count", 0)
            if old_version is not None and attestation_count > 0:
                old_version_tuple = str_to_version(old_version)
                if not old_version_tuple:
                    logger.error("Agent %s stored version %s is invalid", agent_id, old_version)
                    return None

                if negotiated_tuple <= old_version_tuple:
                    logger.warning(
                        "Agent %s API version %s is lower or equal to previous version %s",
                        agent_id,
                        negotiated,
                        old_version,
                    )
                    return None

            logger.info("Agent %s new API version %s is supported", agent_id, negotiated)

            with session_context() as session:
                agent["supported_version"] = negotiated

                # Remove keys that should not go to the DB
                agent_db = dict(agent)
                for key in exclude_db:
                    if key in agent_db:
                        del agent_db[key]

                session.query(VerfierMain).filter_by(agent_id=agent_id).update(agent_db)  # pyright: ignore
                # session.commit() is automatically called by context manager

        else:
            logger.warning("Agent %s did not provide version information", agent_id)
            return None

    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error updating API version for agent %s: %s", agent_id, e)
        return None
    except Exception as e:
        logger.exception(e)
        return None

    logger.info("Agent %s API version updated to %s", agent["agent_id"], agent["supported_version"])
    return agent


async def invoke_get_quote(
    agent: Dict[str, Any],
    mb_policy: Optional[str],
    runtime_policy: str,
    need_pubkey: bool,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])

    params = cloud_verifier_common.prepare_get_quote(agent)

    partial_req = "1"
    if need_pubkey:
        partial_req = "0"

    # TODO: remove special handling after initial upgrade
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "GET",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/quotes/integrity"
        f"?nonce={params['nonce']}&mask={params['mask']}"
        f"&partial={partial_req}&ima_ml_entry={params['ima_ml_entry']}",
        **kwargs,
        timeout=timeout,
    )
    response = await res

    if response.status_code != 200:
        # this is a connection error, retry get quote
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.GET_QUOTE_RETRY))
            return

        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent, timeout=timeout)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(process_agent(updated, states.GET_QUOTE_RETRY))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])
                        failure.add_event(
                            "version_not_supported",
                            {"context": "Agent API version not supported", "data": json_response},
                            False,
                        )
                        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                    return

            except Exception as e:
                logger.exception(e)
                failure.add_event(
                    "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
                )
                asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                return

        # catastrophic error, do not continue
        logger.critical(
            "Unexpected Get Quote response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        failure.add_event("no_quote", "Unexpected Get Quote reponse from agent", False)
        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        try:
            json_response = json.loads(response.body)

            # validate the cloud agent response
            if "provide_V" not in agent:
                agent["provide_V"] = True
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent["agent_id"])

            if verifier_db_manager.rmc:
                verifier_db_manager.rmc.record_create(agent, json_response, mb_policy, runtime_policy)

            failure = cloud_verifier_common.process_quote_response(
                agent,
                mb_policy,
                ima.deserialize_runtime_policy(runtime_policy),
                json_response["results"],
                agentAttestState,
            )
            if not failure:
                if agent["provide_V"]:
                    asyncio.ensure_future(process_agent(agent, states.PROVIDE_V))
                else:
                    asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
            else:
                asyncio.ensure_future(process_agent(agent, states.INVALID_QUOTE, failure))

            # store the attestation state
            store_attestation_state(agentAttestState)

        except Exception as e:
            logger.exception(e)
            failure.add_event(
                "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
            )
            asyncio.ensure_future(process_agent(agent, states.FAILED, failure))


async def invoke_provide_v(agent: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> None:
    failure = Failure(Component.INTERNAL, ["verifier"])

    if agent.get("pending_event") is not None:
        agent["pending_event"] = None

    v_json_message = cloud_verifier_common.prepare_v(agent)

    # TODO: remove special handling after initial upgrade
    kwargs = {}
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "POST",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/keys/vkey",
        data=v_json_message,
        **kwargs,
        timeout=timeout,
    )

    response = await res

    if response.status_code != 200:
        if response.status_code in [408, 500, 599]:
            asyncio.ensure_future(process_agent(agent, states.PROVIDE_V_RETRY))
            return

        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent, timeout=timeout)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(process_agent(updated, states.PROVIDE_V_RETRY))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])
                        failure.add_event(
                            "version_not_supported",
                            {"context": "Agent API version not supported", "data": json_response},
                            False,
                        )
                        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                    return

            except Exception as e:
                logger.exception(e)
                failure.add_event(
                    "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
                )
                asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
                return

        # catastrophic error, do not continue
        logger.critical(
            "Unexpected Provide V response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )
        failure.add_event("no_v", {"message": "Unexpected provide V response", "data": response.status_code}, False)
        asyncio.ensure_future(process_agent(agent, states.FAILED, failure))
    else:
        asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))


async def invoke_notify_error(agent: Dict[str, Any], tosend: Dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> None:
    kwargs = {
        "data": tosend,
    }
    if agent["ssl_context"]:
        kwargs["context"] = agent["ssl_context"]

    res = tornado_requests.request(
        "POST",
        f"http://{agent['ip']}:{agent['port']}/v{agent['supported_version']}/notifications/revocation",
        **kwargs,  # type: ignore
        timeout=timeout,
    )
    response = await res

    if response is None:
        logger.warning(
            "Empty Notify Revocation response from cloud agent %s",
            agent["agent_id"],
        )
    elif response.status_code != 200:
        if response.status_code == 400:
            try:
                json_response = json.loads(response.body)
                if "API version not supported" in json_response["status"]:
                    update = update_agent_api_version(agent, timeout=timeout)
                    updated = await update

                    if updated:
                        asyncio.ensure_future(invoke_notify_error(updated, tosend))
                    else:
                        logger.warning("Could not update stored agent %s API version", agent["agent_id"])

                    return

            except Exception as e:
                logger.exception(e)
                return

        logger.warning(
            "Unexpected Notify Revocation response error for cloud agent %s, Error: %s",
            agent["agent_id"],
            response.status_code,
        )


async def notify_error(
    agent: Dict[str, Any],
    msgtype: str = "revocation",
    event: Optional[Event] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> None:
    notifiers = revocation_notifier.get_notifiers()
    if len(notifiers) == 0:
        return

    tosend = cloud_verifier_common.prepare_error(agent, msgtype, event)
    if "webhook" in notifiers:
        revocation_notifier.notify_webhook(tosend)
    if "zeromq" in notifiers:
        revocation_notifier.notify(tosend)
    if "agent" in notifiers:
        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        with session_context() as session:
            try:
                agents = session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
            except Exception as e:
                logger.error("An issue happened querying the verifier for the list of agents to notify: %s", e)
                return

            futures = []
            loop = asyncio.get_event_loop()
            # Notify all agents asynchronously through a thread pool
            with ThreadPoolExecutor() as pool:
                for agent_db_obj in agents:
                    if agent_db_obj.agent_id != agent["agent_id"]:
                        agent = _from_db_obj(agent_db_obj)
                        if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                            agent["ssl_context"] = web_util.generate_agent_tls_context(
                                "verifier", agent["mtls_cert"], logger=logger
                            )
                    func = functools.partial(invoke_notify_error, agent, tosend, timeout=timeout)
                    futures.append(await loop.run_in_executor(pool, func))
                # Wait for all tasks complete in 60 seconds
                try:
                    for f in asyncio.as_completed(futures, timeout=60):
                        await f
                except asyncio.TimeoutError as e:
                    logger.error("Timeout during notifying error to agents: %s", e)


async def process_agent(
    agent: Dict[str, Any], new_operational_state: int, failure: Failure = Failure(Component.INTERNAL, ["verifier"])
) -> None:
    try:  # pylint: disable=R1702
        main_agent_operational_state = agent["operational_state"]
        stored_agent = None

        # First database operation - read agent data and extract all needed data within session context
        mb_policy_data = None
        with session_context() as session:
            try:
                stored_agent = (
                    session.query(VerfierMain)
                    .options(  # type: ignore
                        joinedload(VerfierMain.ima_policy)  # Load full IMA policy object including content
                    )
                    .options(  # type: ignore
                        joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                    )
                    .filter_by(agent_id=str(agent["agent_id"]))
                    .first()
                )

                # Extract MB policy data within session context
                if stored_agent and stored_agent.mb_policy:
                    mb_policy_data = stored_agent.mb_policy.mb_policy

            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # if the stored agent could not be recovered from the database, stop polling
        if not stored_agent:
            logger.warning("Unable to retrieve agent %s from database. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # if the user did terminated this agent
        if stored_agent.operational_state == states.TERMINATED:  # pyright: ignore
            logger.warning("Agent %s terminated by user.", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])

            # Second database operation - delete agent
            with session_context() as session:
                verifier_db_delete_agent(session, agent["agent_id"])
            return

        # if the user tells us to stop polling because the tenant quote check failed
        if stored_agent.operational_state == states.TENANT_FAILED:  # pyright: ignore
            logger.warning("Agent %s has failed tenant quote. Stopping polling", agent["agent_id"])
            if agent["pending_event"] is not None:
                tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])
            return

        # Use the request timeout stored in the agent dict (read from the
        # verifier config)
        # This value is set through the exclude_db dict and is removed before
        # storing the agent data in the DB
        timeout = agent.get("request_timeout", DEFAULT_TIMEOUT)

        # If failed during processing, log regardless and drop it on the floor
        # The administration application (tenant) can GET the status and act accordingly (delete/retry/etc).
        if new_operational_state in (states.FAILED, states.INVALID_QUOTE):
            assert failure, "States FAILED and INVALID QUOTE should only be reached with a failure message"
            assert failure.highest_severity

            if agent.get("severity_level") is None or agent["severity_level"] < failure.highest_severity.severity:
                assert failure.highest_severity_event
                agent["severity_level"] = failure.highest_severity.severity
                agent["last_event_id"] = failure.highest_severity_event.event_id
                agent["operational_state"] = new_operational_state

                # issue notification for invalid quotes
                if new_operational_state == states.INVALID_QUOTE:
                    await notify_error(agent, event=failure.highest_severity_event, timeout=timeout)

                # When the failure is irrecoverable we stop polling the agent
                if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                    if agent["pending_event"] is not None:
                        tornado.ioloop.IOLoop.current().remove_timeout(agent["pending_event"])

                    # Third database operation - update agent with failure state
                    with session_context() as session:
                        for key in exclude_db:
                            if key in agent:
                                del agent[key]
                        session.query(VerfierMain).filter_by(agent_id=agent["agent_id"]).update(
                            agent  # type: ignore[arg-type]
                        )
                        # session.commit() is automatically called by context manager

        # propagate all state, but remove none DB keys first (using exclude_db)
        try:
            agent_db = dict(agent)
            for key in exclude_db:
                if key in agent_db:
                    del agent_db[key]

            # Fourth database operation - update agent state
            with session_context() as session:
                session.query(VerfierMain).filter_by(agent_id=agent_db["agent_id"]).update(agent_db)  # pyright: ignore
                # session.commit() is automatically called by context manager
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent["agent_id"], e)

        # Load agent's IMA policy
        if stored_agent:
            runtime_policy = verifier_read_policy_from_cache(stored_agent)
        else:
            runtime_policy = ""

        # Get agent's measured boot policy
        mb_policy = mb_policy_data

        # If agent was in a failed state we check if we either stop polling
        # or just add it again to the event loop
        if new_operational_state in [states.FAILED, states.INVALID_QUOTE]:
            if not failure.recoverable or failure.highest_severity == MAX_SEVERITY_LABEL:
                logger.warning("Agent %s failed, stopping polling", agent["agent_id"])
                return

            await invoke_get_quote(agent, mb_policy, runtime_policy, False, timeout=timeout)
            return

        # if new, get a quote
        if main_agent_operational_state == states.START and new_operational_state == states.GET_QUOTE:
            agent["num_retries"] = 0
            agent["operational_state"] = states.GET_QUOTE
            await invoke_get_quote(agent, mb_policy, runtime_policy, True, timeout=timeout)
            return

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.PROVIDE_V:
            agent["num_retries"] = 0
            agent["operational_state"] = states.PROVIDE_V
            # Only deploy V key if actually set
            if agent.get("v"):
                await invoke_provide_v(agent, timeout=timeout)
            else:
                await process_agent(agent, states.GET_QUOTE)
            return

        if (
            main_agent_operational_state in (states.PROVIDE_V, states.GET_QUOTE)
            and new_operational_state == states.GET_QUOTE
        ):
            agent["num_retries"] = 0
            interval = config.getfloat("verifier", "quote_interval")
            agent["operational_state"] = states.GET_QUOTE
            if interval == 0:
                await invoke_get_quote(agent, mb_policy, runtime_policy, False, timeout=timeout)
            else:
                logger.debug(
                    "Setting up callback to check agent ID %s again in %f seconds", agent["agent_id"], interval
                )

                pending = tornado.ioloop.IOLoop.current().call_later(
                    # type: ignore  # due to python <3.9
                    interval,
                    invoke_get_quote,
                    agent,
                    mb_policy,
                    runtime_policy,
                    False,
                    timeout=timeout,
                )
                agent["pending_event"] = pending
            return

        maxr = config.getint("verifier", "max_retries")
        interval = config.getfloat("verifier", "retry_interval")
        exponential_backoff = config.getboolean("verifier", "exponential_backoff")

        if main_agent_operational_state == states.GET_QUOTE and new_operational_state == states.GET_QUOTE_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable for quote in %d tries, setting state to FAILED", agent["agent_id"], maxr
                )
                failure.add_event("not_reachable", "agent was not reachable from verifier", False)
                if agent["attestation_count"] > 0:  # only notify on previously good agents
                    await notify_error(
                        agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout
                    )
                else:
                    logger.debug("Communication error for new agent. No notification will be sent")
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.GET_QUOTE

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(
                    # type: ignore  # due to python <3.9
                    next_retry,
                    invoke_get_quote,
                    agent,
                    mb_policy,
                    runtime_policy,
                    True,
                    timeout=timeout,
                )
            return

        if main_agent_operational_state == states.PROVIDE_V and new_operational_state == states.PROVIDE_V_RETRY:
            if agent["num_retries"] >= maxr:
                logger.warning(
                    "Agent %s was not reachable to provide v in %d tries, setting state to FAILED",
                    agent["agent_id"],
                    maxr,
                )
                failure.add_event("not_reachable_v", "agent was not reachable to provide V", False)
                await notify_error(agent, msgtype="comm_error", event=failure.highest_severity_event, timeout=timeout)
                await process_agent(agent, states.FAILED, failure)
            else:
                agent["operational_state"] = states.PROVIDE_V

                agent["num_retries"] += 1
                next_retry = retry.retry_time(exponential_backoff, interval, agent["num_retries"], logger)
                logger.info(
                    "Connection to %s refused after %d/%d tries, trying again in %f seconds",
                    agent["ip"],
                    agent["num_retries"],
                    maxr,
                    next_retry,
                )
                tornado.ioloop.IOLoop.current().call_later(
                    next_retry, invoke_provide_v, agent  # type: ignore  # due to python <3.9
                )
            return
        raise Exception("nothing should ever fall out of this!")

    except Exception as e:
        logger.exception("Polling thread error for agent ID %s", agent["agent_id"])
        failure.add_event(
            "exception", {"context": "Agent caused the verifier to throw an exception", "data": str(e)}, False
        )
        await process_agent(agent, states.FAILED, failure)


async def activate_agents(agents: List[VerfierMain], verifier_ip: str, verifier_port: int) -> None:
    aas = get_AgentAttestStates()
    for agent in agents:
        agent.verifier_ip = verifier_ip  # pyright: ignore
        agent.verifier_port = verifier_port  # pyright: ignore
        agent_run = _from_db_obj(agent)
        if agent_run["mtls_cert"] and agent_run["mtls_cert"] != "disabled":
            agent_run["ssl_context"] = web_util.generate_agent_tls_context(
                "verifier", agent_run["mtls_cert"], logger=logger
            )

        if agent.operational_state == states.START:  # pyright: ignore
            asyncio.ensure_future(process_agent(agent_run, states.GET_QUOTE))
        if agent.boottime:  # pyright: ignore
            ima_pcrs_dict = {}
            assert isinstance(agent.ima_pcrs, list)
            for pcr_num in agent.ima_pcrs:
                ima_pcrs_dict[pcr_num] = getattr(agent, f"pcr{pcr_num}")
            aas.add(
                str(agent.agent_id),
                int(agent.boottime),  # pyright: ignore
                ima_pcrs_dict,
                int(agent.next_ima_ml_entry),  # type: ignore
                dict(agent.learned_ima_keyrings),  # type: ignore
            )


def get_agents_by_verifier_id(verifier_id: str) -> List[VerfierMain]:
    try:
        with session_context() as session:
            return session.query(VerfierMain).filter_by(verifier_id=verifier_id).all()
    except SQLAlchemyError as e:
        logger.error("SQLAlchemy Error: %s", e)
    return []
