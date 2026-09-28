"""Network Agent Workflow State Schema.

Defines NetworkAgentState, execution log contracts, and initialization helpers.
"""

from __future__ import annotations
from datetime import datetime, timezone
import operator
from typing import Any, Dict, List, Optional
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


class NetworkAgentState(TypedDict):
    """Unified state dictionary passed across LangGraph nodes."""
    user_intent: str
    parsed_intent: Optional[Dict[str, Any]]
    raw_topology: Optional[Dict[str, Any]]
    validated_topology: Optional[Dict[str, Any]]
    validation_result: Optional[Dict[str, Any]]
    human_approved: Optional[bool]
    deploy_status: Optional[Dict[str, Any]]
    verification_results: Optional[Dict[str, Any]]
    diagnostic_report: Optional[Dict[str, Any]]
    remediation_plan: Optional[Dict[str, Any]]
    retry_count: int
    max_retries: int
    error_message: Optional[str]
    status: str
    execution_logs: Annotated[List[LogEntry], operator.add]


def create_initial_state(
    user_intent: str,
    max_retries: int = 3,
    auto_approve: bool = True,
) -> NetworkAgentState:
    """Create a fully initialized NetworkAgentState.

    Args:
        user_intent: Natural language request or specification.
        max_retries: Maximum permitted retries before circuit breaker trips.
        auto_approve: If True, human approval is granted automatically.

    Returns:
        Fresh NetworkAgentState ready for graph execution.
    """
    initial_log = create_log_entry(
        stage="init",
        message="Workflow initialized with user intent",
        level="info",
        metadata={"max_retries": max_retries, "auto_approve": auto_approve},
    )

    return NetworkAgentState(
        user_intent=user_intent,
        parsed_intent=None,
        raw_topology=None,
        validated_topology=None,
        validation_result=None,
        human_approved=True if auto_approve else None,
        deploy_status=None,
        verification_results=None,
        diagnostic_report=None,
        remediation_plan=None,
        retry_count=0,
        max_retries=max_retries,
        error_message=None,
        status="initialized",
        execution_logs=[initial_log],
    )
