"""Pure Conditional Routing Functions for LangGraph Workflow State Transitions.

Provides deterministic routing based on state status, verification results,
validation outcomes, and circuit-breaker retry threshold constraints.
"""

from __future__ import annotations
from typing import Literal
from langgraph_netagent.workflow.state import NetworkAgentState


def route_after_validation(
    state: NetworkAgentState,
) -> Literal["human_approval", "topology_generation", "circuit_breaker"]:
    """Conditional edge routing after offline validation node.

    Routes:
        - "human_approval" if validation passed.
        - "circuit_breaker" if validation failed and retry limit is exceeded.
        - "topology_generation" if validation failed and retries remain (error feedback loop).
    """
    val_res = state.get("validation_result")
    is_valid = (
        state.get("status") == "validation_passed"
        or (val_res is not None and val_res.get("is_valid", False) is True)
    )

    if is_valid:
        return "human_approval"

    # Validation failed - check circuit breaker threshold
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if retry_count >= max_retries:
        return "circuit_breaker"

    return "topology_generation"


def route_after_approval(
    state: NetworkAgentState,
) -> Literal["deployment", "circuit_breaker", "end"]:
    """Conditional edge routing after human approval node.

    Routes:
        - "deployment" if approved (human_approved is True).
        - "circuit_breaker" if retry exhaustion triggered during approval phase.
        - "end" if human approval was explicitly rejected or aborted.
    """
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if retry_count >= max_retries and state.get("human_approved") is not True:
        return "circuit_breaker"

    if state.get("human_approved") is True:
        return "deployment"

    # Operator rejected or pending pause
    return "end"


def route_after_deployment(
    state: NetworkAgentState,
) -> Literal["verification_probing", "diagnosis_and_healing", "circuit_breaker"]:
    """Conditional edge routing after deployment node.

    Routes:
        - "verification_probing" if deployment succeeded.
        - "circuit_breaker" if deployment failed and retry limit reached.
        - "diagnosis_and_healing" if deployment failed and retries remain.
    """
    deploy_status = state.get("deploy_status")
    deploy_ok = (
        state.get("status") == "deployed"
        or (deploy_status is not None and deploy_status.get("success", False) is True)
    )

    if deploy_ok:
        return "verification_probing"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if retry_count >= max_retries:
        return "circuit_breaker"

    return "diagnosis_and_healing"


def route_after_verification(
    state: NetworkAgentState,
) -> Literal["end", "diagnosis_and_healing", "circuit_breaker"]:
    """Conditional edge routing after telemetry verification probing node.

    Routes:
        - "end" if all verification telemetry probes passed (Happy Path).
        - "circuit_breaker" if verification failed and retry limit reached.
        - "diagnosis_and_healing" if verification failed and retries remain (Self-Healing Loop).
    """
    verif = state.get("verification_results")
    verified = (
        state.get("status") == "verified"
        or (verif is not None and verif.get("all_passed", False) is True)
    )

    if verified:
        return "end"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    if retry_count >= max_retries:
        return "circuit_breaker"

    return "diagnosis_and_healing"
