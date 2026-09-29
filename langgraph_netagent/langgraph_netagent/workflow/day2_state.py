"""Day-2 Network Operations Agent State Schema.

Defines Day2OpsState for live network monitoring, fault diagnosis,
and in-place hot-patching workflows.
"""

from __future__ import annotations
from datetime import datetime, timezone
import operator
from typing import Any, Dict, List, Optional
import warnings
from typing_extensions import Annotated, TypedDict


class LogEntry(TypedDict):
    """Structured audit and trace log entry."""
    timestamp: str
    stage: str
    level: str  # "info", "warning", "error", "critical"
    message: str
    metadata: Optional[Dict[str, Any]]


def create_log_entry(
    stage: str,
    message: str,
    level: str = "info",
    metadata: Optional[Dict[str, Any]] = None,
) -> LogEntry:
    """Helper to construct a standardized LogEntry."""
    return LogEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        stage=stage,
        level=level,
        message=message,
        metadata=metadata,
    )


class Day2OpsState(TypedDict):
    """Unified state dictionary for Day-2 live network operations LangGraph.

    Flow: read_baseline -> probe_matrix -> hop_pruning -> llm_diagnosis
          -> generate_patch -> dry_run_check -> human_approval
          -> hot_patch -> re_verify -> (loop or END)
    """
    # Baseline snapshot from live network
    baseline: Optional[Dict[str, Any]]          # clab inspect + running configs
    topology_path: Optional[List[str]]          # ordered device path e.g. ['pc1','frr1','srl1','pc2']
    node_kinds: Optional[Dict[str, str]]        # e.g. {'frr1': 'frr', 'srl1': 'srl', 'pc1': 'linux'}

    # Probe results
    probe_results: Optional[Dict[str, Any]]     # NetworkHealthReport dict
    suspect_devices: Optional[List[str]]        # hop pruning output
    affected_segments: Optional[List[Dict[str, Any]]]  # which hops failed

    # Diagnosis
    diagnostic_report: Optional[Dict[str, Any]] # DiagnosticReport dict

    # Remediation
    remediation_plan: Optional[Dict[str, Any]]  # RemediationPlan dict
    dry_run_passed: Optional[bool]              # syntax/safety check result
    dry_run_errors: Optional[List[str]]         # dry-run failure reasons

    # HITL approval
    human_approved: Optional[bool]

    # Patch execution
    patch_result: Optional[Dict[str, Any]]      # hot-patch execution result

    # Re-verification
    re_verify_results: Optional[Dict[str, Any]] # post-patch probe results

    # Control flow
    retry_count: int
    max_retries: int
    error_message: Optional[str]
    status: str
    execution_logs: Annotated[List[LogEntry], operator.add]


def create_day2_initial_state(
    max_retries: int = 3,
    auto_approve: bool = False,
) -> Day2OpsState:
    """Create a fully initialized Day2OpsState.

    Args:
        max_retries: Maximum permitted healing retries before circuit breaker trips.
        auto_approve: If True, human approval is granted automatically.

    Returns:
        Fresh Day2OpsState ready for graph execution.
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )
    initial_log = create_log_entry(
        stage="init",
        message="Day-2 operations workflow initialized",
        level="info",
        metadata={"max_retries": max_retries, "auto_approve": auto_approve},
    )

    return Day2OpsState(
        baseline=None,
        topology_path=None,
        node_kinds=None,
        probe_results=None,
        suspect_devices=None,
        affected_segments=None,
        diagnostic_report=None,
        remediation_plan=None,
        dry_run_passed=None,
        dry_run_errors=None,
        human_approved=True if auto_approve else None,
        patch_result=None,
        re_verify_results=None,
        retry_count=0,
        max_retries=max_retries,
        error_message=None,
        status="initialized",
        execution_logs=[initial_log],
    )
