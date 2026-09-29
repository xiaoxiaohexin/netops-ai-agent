"""Day-2 Conditional Routing Functions for LangGraph Workflow.

Deterministic routing based on probe results, diagnosis outcomes,
dry-run checks, approval status, and circuit-breaker retry thresholds.
"""

from __future__ import annotations
from typing import Literal
import warnings
from langgraph_netagent.workflow.day2_state import Day2OpsState


def route_after_probe(
    state: Day2OpsState,
) -> Literal["end_healthy", "hop_pruning"]:
    """Route after probe_matrix node.

    Routes:
        - 'end_healthy' if all probes passed (network is healthy).
        - 'hop_pruning' if any failures detected.
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )
    probe = state.get("probe_results")
    if probe and probe.get("all_passed", False):
        return "end_healthy"
    return "hop_pruning"


def route_after_dry_run(
    state: Day2OpsState,
) -> Literal["human_approval", "llm_diagnosis", "circuit_breaker"]:
    """Route after dry_run_check node.

    Routes:
        - 'human_approval' if dry-run passed.
        - 'circuit_breaker' if dry-run failed and retries exhausted.
        - 'llm_diagnosis' if dry-run failed but retries remain (regenerate patch).
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )
    if state.get("dry_run_passed") is True:
        return "human_approval"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries:
        return "circuit_breaker"
    return "llm_diagnosis"


def route_after_approval(
    state: Day2OpsState,
) -> Literal["hot_patch", "end_rejected"]:
    """Route after human_approval node.

    Routes:
        - 'hot_patch' if operator approved.
        - 'end_rejected' if operator rejected.
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )
    if state.get("human_approved") is True:
        return "hot_patch"
    return "end_rejected"


def route_after_re_verify(
    state: Day2OpsState,
) -> Literal["end_fixed", "llm_diagnosis", "circuit_breaker"]:
    """Route after re_verify node.

    Routes:
        - 'end_fixed' if re-verification probes all pass (fix confirmed).
        - 'circuit_breaker' if still failing and retries exhausted.
        - 'llm_diagnosis' if still failing but retries remain (re-diagnose).
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )
    re_verify = state.get("re_verify_results")
    if re_verify and re_verify.get("all_passed", False):
        return "end_fixed"

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)
    if retry_count >= max_retries:
        return "circuit_breaker"
    return "llm_diagnosis"
