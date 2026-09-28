"""Operational Conditional Routing Functions for NetOps State Machine.

Implements deterministic routing for the UML activity diagram:
Baseline Ingestion → Telemetry/5-Tuple Extraction → 2-Stage Diagnosis →
AAL Sandbox Validation → Human Approval → Live Hot-Patch → Re-verification.
"""

from __future__ import annotations

from typing import Literal
from langgraph_netagent.workflow.operational_state import OperationalState


def route_after_telemetry(
    state: OperationalState,
) -> Literal["end_healthy", "diagnostic_stage1"]:
    """Route after telemetry_extraction node.

    Routes:
        - 'end_healthy' if all telemetry probes pass and no discrepancies or 5-tuple failures exist.
        - 'diagnostic_stage1' if any 5-tuple failures or discrepancies are detected.
    """
    failures = state.get("failure_5tuples") or []
    discrepancies = state.get("discrepancies") or []

    if failures or discrepancies:
        return "diagnostic_stage1"

    telemetry = state.get("telemetry_results") or state.get("probe_results")
    if telemetry and telemetry.get("all_passed", False):
        return "end_healthy"

    # If telemetry dict claims all passed and no failures/discrepancies
    if telemetry and not failures and not discrepancies and telemetry.get("failures") == []:
        return "end_healthy"

    return "diagnostic_stage1"


def route_after_stage2(
    state: OperationalState,
) -> Literal["sandbox_validation", "circuit_breaker"]:
    """Route after diagnostic_stage2 plan generation node.

    Routes:
        - 'circuit_breaker' if step tagging / retry limit is exceeded.
        - 'sandbox_validation' if remediation plan is generated and ready for sandbox.
    """
    if state.get("circuit_breaker_tripped") is True:
        return "circuit_breaker"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries:
        return "circuit_breaker"

    return "sandbox_validation"


def route_after_sandbox(
    state: OperationalState,
) -> Literal["human_approval", "diagnostic_stage1", "circuit_breaker"]:
    """Route after sandbox_validation node.

    Candidate patches MUST execute in the shadow sandbox replica BEFORE reaching
    the human approval stage.

    Routes:
        - 'human_approval' if candidate patch executes cleanly in sandbox replica.
        - 'circuit_breaker' if sandbox failed and retries exhausted.
        - 'diagnostic_stage1' if sandbox failed but retries remain (regenerate plan).
    """
    sandbox_passed = state.get("sandbox_passed")
    if sandbox_passed is True:
        return "human_approval"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries:
        return "circuit_breaker"

    return "diagnostic_stage1"


def route_after_approval(
    state: OperationalState,
) -> Literal["live_hot_patch", "circuit_breaker", "end_rejected"]:
    """Route after human_approval node.

    Routes:
        - 'live_hot_patch' if operator approved candidate plan.
        - 'circuit_breaker' if retries exhausted and plan not approved.
        - 'end_rejected' if operator rejected candidate plan or awaiting approval pause.
    """
    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries and state.get("human_approved") is not True:
        return "circuit_breaker"

    if state.get("human_approved") is True:
        return "live_hot_patch"
    return "end_rejected"


def route_after_re_verification(
    state: OperationalState,
) -> Literal["end_fixed", "diagnostic_stage1", "circuit_breaker"]:
    """Route after re_verification node.

    Routes:
        - 'end_fixed' if post-change verification confirms all probes pass.
        - 'circuit_breaker' if failure remains and retry threshold is exhausted.
        - 'diagnostic_stage1' if failure remains but retries remain.
    """
    re_ver = state.get("re_verify_results")
    if re_ver and re_ver.get("all_passed", False):
        return "end_fixed"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries:
        return "circuit_breaker"

    return "diagnostic_stage1"


def route_after_healthy(
    state: OperationalState,
) -> Literal["telemetry_extraction", "end"]:
    """Route after end_healthy node.

    If watch_mode is active and remaining cycles allow, loops back to telemetry_extraction.
    Otherwise, routes cleanly to END.
    """
    if state.get("watch_mode") is True:
        max_cycles = state.get("max_watch_cycles")
        current = state.get("watch_cycle", 0)
        if max_cycles is None or max_cycles <= 0 or current < max_cycles:
            return "telemetry_extraction"
    return "end"

