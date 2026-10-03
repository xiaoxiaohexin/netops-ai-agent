"""Operational State Schema for NetOps Incident Troubleshooting and Self-Healing.

Defines OperationalState TypedDict for the pure NetOps LangGraph state machine:
Baseline Ingestion → Telemetry/5-Tuple Extraction → 2-Stage Diagnosis →
AAL Sandbox Validation → Human Approval → Live Hot-Patch → Re-verification.
"""

from __future__ import annotations

from datetime import datetime, timezone
import operator
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from typing_extensions import Annotated, TypedDict

from langgraph_netagent.workflow.day2_state import LogEntry, create_log_entry


class OperationalState(TypedDict):
    """Unified state dictionary for the operational NetOps LangGraph workflow."""

    # 1. Baseline Ingestion & Asset Inventory
    baseline: Optional[Dict[str, Any]]
    inventory_pool: Optional[Dict[str, Any]]
    topology_path: Optional[List[str]]
    node_kinds: Optional[Dict[str, str]]

    # 2. Telemetry, 5-Tuple Extraction & Discrepancy Isolation
    initial_alerts: Optional[List[str]]
    telemetry_results: Optional[Dict[str, Any]]
    probe_results: Optional[Dict[str, Any]]  # Alias for probe matrix compatibility
    failure_5tuples: Optional[List[Dict[str, Any]]]
    discrepancies: Optional[List[Dict[str, Any]]]
    suspect_devices: Optional[List[str]]
    affected_segments: Optional[List[Dict[str, Any]]]
    anomaly_classification: Optional[Dict[str, Any]]
    last_qdisc_stats: Optional[Dict[str, Any]]

    # 3. Two-Stage Diagnostic Engine
    # Stage 1: Context Enrichment & Pre-retrieval
    enriched_context: Optional[Dict[str, Any]]
    rag_keywords: Optional[List[str]]

    # Stage 2: Targeted Plan Generation & Step-Tagging
    retrieved_sop: Optional[List[Dict[str, Any]]]
    diagnostic_report: Optional[Dict[str, Any]]
    remediation_plan: Optional[Dict[str, Any]]
    step_tags_history: Optional[List[str]]
    current_step_tag: Optional[str]

    # 4. AAL Shadow Sandbox Validation
    sandbox_result: Optional[Dict[str, Any]]
    sandbox_passed: Optional[bool]
    dry_run_passed: Optional[bool]  # Compatibility alias

    # 5. Human-in-the-Loop (HITL) Gate
    human_approved: Optional[bool]

    # 6. Live Hot-Patching via AAL
    patch_result: Optional[Dict[str, Any]]

    # 7. Post-Change Re-verification Probing
    re_verify_results: Optional[Dict[str, Any]]
    rollback_executed: Optional[bool]
    rollback_results: List[Dict[str, Any]]

    # 8. Execution Control & Audit
    retry_count: int
    max_retries: int
    circuit_breaker_tripped: bool
    status: str
    error_message: Optional[str]
    execution_logs: Annotated[List[LogEntry], operator.add]

    # 9. Continuous Monitoring Loop Control (R1)
    watch_mode: Optional[bool]
    watch_interval: Optional[float]
    watch_cycle: Optional[int]
    max_watch_cycles: Optional[int]
    last_healthy_timestamp: Optional[str]
    consecutive_healthy_cycles: Optional[int]

    # 10. Milestone 4 Bounded AI Autonomy & Two-Stage Diagnostic Loop
    canonical_intents: Optional[List[Any]]
    compilation_results: Optional[List[Any]]
    preflight_report: Optional[Any]
    dual_retrieval_results: Optional[List[Any]]
    autonomy_tier: str
    step_tag: str

    # 11. Milestone 5 Harmonized Workflow & Phase Boundaries
    operational_phase: Optional[str]
    phase_history: Optional[List[str]]
    vendor_knowledge_indexed: Optional[bool]
    dual_retrieval_index_built: Optional[bool]

    # 12. Dynamic Runtime Discovery & Dynamic SOPs (Requirement R1, R2, R3)
    discovered_topology: Optional[Any]
    scraped_sops: Optional[List[Any]]
    runtime_incident_context: Optional[Dict[str, Any]]


def create_operational_initial_state(
    max_retries: int = 3,
    auto_approve: bool = False,
    initial_alerts: Optional[List[str]] = None,
    watch_mode: bool = False,
    watch_interval: float = 5.0,
    max_watch_cycles: Optional[int] = None,
    autonomy_tier: str = "bounded",
    step_tag: str = "",
) -> OperationalState:
    """Create a fully initialized OperationalState.

    Args:
        max_retries: Retry limit before tripping circuit breaker.
        auto_approve: Whether human approval is auto-granted after sandbox pass.
        initial_alerts: Optional initial syslog / alert strings to parse.
        watch_mode: Whether to enable persistent continuous monitoring loop.
        watch_interval: Interval in seconds between healthy monitoring cycles.
        max_watch_cycles: Optional cycle cap before terminating (None for infinite).
        autonomy_tier: Autonomy level ("bounded", "full_autonomy").
        step_tag: Monotonic iteration step tracking tag.

    Returns:
        Fresh OperationalState ready for LangGraph execution.
    """
    initial_log = create_log_entry(
        stage="init",
        message="Operational NetOps incident troubleshooting workflow initialized",
        level="info",
        metadata={
            "max_retries": max_retries,
            "auto_approve": auto_approve,
            "initial_alerts_count": len(initial_alerts) if initial_alerts else 0,
            "watch_mode": watch_mode,
            "watch_interval": watch_interval,
            "max_watch_cycles": max_watch_cycles,
            "autonomy_tier": autonomy_tier,
            "step_tag": step_tag,
        },
    )

    return {
        "baseline": None,
        "inventory_pool": None,
        "topology_path": None,
        "node_kinds": None,
        "initial_alerts": initial_alerts or [],
        "telemetry_results": None,
        "probe_results": None,
        "failure_5tuples": [],
        "discrepancies": [],
        "suspect_devices": [],
        "affected_segments": [],
        "anomaly_classification": None,
        "last_qdisc_stats": None,
        "enriched_context": None,
        "rag_keywords": [],
        "retrieved_sop": [],
        "diagnostic_report": None,
        "remediation_plan": None,
        "step_tags_history": [],
        "current_step_tag": None,
        "sandbox_result": None,
        "sandbox_passed": None,
        "dry_run_passed": None,
        "human_approved": None if not auto_approve else True,
        "patch_result": None,
        "re_verify_results": None,
        "rollback_executed": False,
        "rollback_results": [],
        "retry_count": 0,
        "max_retries": max_retries,
        "circuit_breaker_tripped": False,
        "status": "initialized",
        "error_message": None,
        "execution_logs": [initial_log],
        "watch_mode": watch_mode,
        "watch_interval": watch_interval,
        "watch_cycle": 0,
        "max_watch_cycles": max_watch_cycles,
        "last_healthy_timestamp": None,
        "consecutive_healthy_cycles": 0,
        "canonical_intents": [],
        "compilation_results": [],
        "preflight_report": None,
        "dual_retrieval_results": [],
        "autonomy_tier": autonomy_tier,
        "step_tag": step_tag,
        "operational_phase": "day1",
        "phase_history": ["day1"],
        "vendor_knowledge_indexed": False,
        "dual_retrieval_index_built": False,
        "discovered_topology": None,
        "scraped_sops": [],
        "runtime_incident_context": {},
    }


class OperationalStateModel(BaseModel):
    """Pydantic model equivalent of OperationalState for schema validation and serialization."""

    model_config = ConfigDict(populate_by_name=True, extra="allow")

    baseline: Optional[Dict[str, Any]] = None
    inventory_pool: Optional[Dict[str, Any]] = None
    topology_path: Optional[List[str]] = None
    node_kinds: Optional[Dict[str, str]] = None
    initial_alerts: List[str] = Field(default_factory=list)
    telemetry_results: Optional[Dict[str, Any]] = None
    probe_results: Optional[Dict[str, Any]] = None
    failure_5tuples: List[Dict[str, Any]] = Field(default_factory=list)
    discrepancies: List[Dict[str, Any]] = Field(default_factory=list)
    suspect_devices: List[str] = Field(default_factory=list)
    affected_segments: List[Dict[str, Any]] = Field(default_factory=list)
    anomaly_classification: Optional[Dict[str, Any]] = None
    last_qdisc_stats: Optional[Dict[str, Any]] = None
    enriched_context: Optional[Dict[str, Any]] = None
    rag_keywords: List[str] = Field(default_factory=list)
    retrieved_sop: List[Dict[str, Any]] = Field(default_factory=list)
    diagnostic_report: Optional[Dict[str, Any]] = None
    remediation_plan: Optional[Dict[str, Any]] = None
    step_tags_history: List[str] = Field(default_factory=list)
    current_step_tag: Optional[str] = None
    sandbox_result: Optional[Dict[str, Any]] = None
    sandbox_passed: Optional[bool] = None
    dry_run_passed: Optional[bool] = None
    human_approved: Optional[bool] = None
    patch_result: Optional[Dict[str, Any]] = None
    re_verify_results: Optional[Dict[str, Any]] = None
    rollback_executed: Optional[bool] = False
    rollback_results: List[Dict[str, Any]] = Field(default_factory=list)
    retry_count: int = 0
    max_retries: int = 3
    circuit_breaker_tripped: bool = False
    status: str = "initialized"
    error_message: Optional[str] = None
    execution_logs: List[Any] = Field(default_factory=list)
    watch_mode: Optional[bool] = False
    watch_interval: Optional[float] = 5.0
    watch_cycle: Optional[int] = 0
    max_watch_cycles: Optional[int] = None
    last_healthy_timestamp: Optional[str] = None
    consecutive_healthy_cycles: Optional[int] = 0
    canonical_intents: List[Any] = Field(default_factory=list)
    compilation_results: List[Any] = Field(default_factory=list)
    preflight_report: Optional[Any] = None
    dual_retrieval_results: List[Any] = Field(default_factory=list)
    autonomy_tier: str = "bounded"
    step_tag: str = ""
    operational_phase: Optional[str] = "day1"
    phase_history: List[str] = Field(default_factory=lambda: ["day1"])
    vendor_knowledge_indexed: Optional[bool] = False
    dual_retrieval_index_built: Optional[bool] = False

    # Dynamic Discovery and SOPs (Requirement R1, R2, R3)
    discovered_topology: Optional[Any] = None
    scraped_sops: List[Any] = Field(default_factory=list)
    runtime_incident_context: Dict[str, Any] = Field(default_factory=dict)


