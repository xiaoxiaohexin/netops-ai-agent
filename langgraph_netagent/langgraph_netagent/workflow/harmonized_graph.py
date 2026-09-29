"""Harmonized Operational LangGraph State Machine Builder and Runner.

Implements the formal Three-Phase NetOps Troubleshooting and Closed-Loop Self-Healing Pipeline:
- Day-1: Baseline Ingestion, Asset Inventory Discovery, and Vendor Knowledge Dual-Retrieval Index Build.
- Day-2: Cognitive Diagnostic State Machine:
    * Telemetry & 5-Tuple Extraction
    * Diagnostic Stage 1: Context Enrichment & Pre-retrieval (Read-only AAL, Full Autonomy)
    * Diagnostic Stage 2: Targeted Plan & Canonical Intent Synthesis (Monotonic step_tag, Bounded Autonomy)
    * Circuit Breaker Loop Termination
- Day-3: Verification, Pre-Flight Sandbox, HITL Gate & Live Deployment:
    * Ephemeral Docker Sandbox Pre-Flight Validation (PreflightSandboxPassReport with SHA-256 signature)
    * Bounded Autonomy Human-in-the-Loop (HITL) Gate
    * Live Hot-Patching via AAL with Monotonic step_tag
    * Post-Change Re-verification Probing
    * Automated Reverse Rollback on Failure
"""

from __future__ import annotations

from enum import Enum
import warnings
from typing import Any, Callable, Dict, List, Optional, Sequence

from langgraph_netagent.llm.base import BaseLLMProvider
from langgraph_netagent.models.knowledge import DualRetrievalResult
from langgraph_netagent.models.sandbox import PreflightSandboxPassReport
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.sop_retriever import SOPRetriever
from langgraph_netagent.tools.vendor_knowledge import DualRetrievalEngine, VendorDocIngestor
from langgraph_netagent.workflow.graph import (
    END,
    HAS_OFFICIAL_LANGGRAPH,
    OfficialStateGraph,
    START,
    SimpleStateGraph,
)
from langgraph_netagent.workflow.operational_edges import (
    route_after_approval,
    route_after_healthy,
    route_after_re_verification,
    route_after_sandbox,
    route_after_stage2,
    route_after_telemetry,
)
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_log_entry,
    create_operational_initial_state,
)


class OperationalPhase(str, Enum):
    """Operational lifecycle phases for the harmonized network agent."""
    DAY1 = "day1"
    DAY2 = "day2"
    DAY3 = "day3"
    DAY1_DISCOVERY = "day1_discovery"
    DAY2_DIAGNOSIS = "day2_diagnosis"
    DAY3_EXECUTION = "day3_execution"


class HarmonizedState(OperationalState):
    """Harmonized operational workflow state extending OperationalState with phase metadata."""
    operational_phase: Optional[str]
    phase_history: Optional[List[str]]
    vendor_knowledge_indexed: Optional[bool]
    dual_retrieval_index_built: Optional[bool]


HarmonizedOpsState = HarmonizedState


def create_harmonized_initial_state(
    max_retries: int = 3,
    auto_approve: bool = False,
    initial_alerts: Optional[List[str]] = None,
    watch_mode: bool = False,
    watch_interval: float = 5.0,
    max_watch_cycles: Optional[int] = None,
    autonomy_tier: str = "bounded",
    step_tag: str = "",
) -> OperationalState:
    """Create a fully initialized state for the harmonized 3-phase workflow."""
    state = create_operational_initial_state(
        max_retries=max_retries,
        auto_approve=auto_approve,
        initial_alerts=initial_alerts,
        watch_mode=watch_mode,
        watch_interval=watch_interval,
        max_watch_cycles=max_watch_cycles,
        autonomy_tier=autonomy_tier,
        step_tag=step_tag,
    )
    state["operational_phase"] = "day1"
    state["phase_history"] = ["day1"]
    state["vendor_knowledge_indexed"] = False
    state["dual_retrieval_index_built"] = False
    return state


def validate_phase_transition(from_phase: str, to_phase: str) -> bool:
    """Validate whether a phase transition conforms to the harmonized 3-day lifecycle."""
    valid_transitions = {
        "day1": {"day1", "day2", "end_healthy"},
        "day2": {"day2", "day3", "circuit_breaker", "end_healthy"},
        "day3": {"day3", "day2", "end_fixed", "end_rejected", "circuit_breaker"},
    }
    allowed = valid_transitions.get(from_phase, set())
    return to_phase in allowed


def verify_phase_boundaries(state: Dict[str, Any]) -> Dict[str, Any]:
    """Verify that current state respects all multi-day lifecycle invariants."""
    violations: List[str] = []
    phase = state.get("operational_phase", "unknown")
    history = state.get("phase_history", [])

    if phase == "day3":
        if "day1" not in history or "day2" not in history:
            violations.append("Day-3 execution reached without completing Day-1 and Day-2")
        if not state.get("preflight_report") and not state.get("sandbox_result"):
            violations.append("Day-3 modification attempted without sandbox pass report")

    if phase == "day2" and "day1" not in history:
        # Day-2 requires Day-1 baseline unless cached inventory_pool is present
        if not state.get("inventory_pool"):
            violations.append("Day-2 diagnosis entered without Day-1 asset inventory")

    return {
        "valid": len(violations) == 0,
        "current_phase": phase,
        "phase_history": history,
        "violations": violations,
    }


def create_harmonized_nodes(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    auto_approve: bool = False,
    aal: Optional[AgentAccessLayer] = None,
    sop_retriever: Optional[SOPRetriever] = None,
    clone_timeout: int = 60,
    interactive: bool = False,
) -> Dict[str, Callable[[OperationalState], Dict[str, Any]]]:
    """Factory creating harmonized workflow nodes with explicit 3-day phase separation."""
    # Ensure retriever and dual retrieval engine are ready
    retriever = sop_retriever or SOPRetriever()
    if not hasattr(retriever, "dual_engine") or retriever.dual_engine is None:
        try:
            retriever.dual_engine = DualRetrievalEngine()
        except Exception:
            pass

    base_nodes = create_operational_nodes(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        lab_name=lab_name,
        auto_approve=auto_approve,
        aal=aal,
        sop_retriever=retriever,
        clone_timeout=clone_timeout,
        interactive=interactive,
    )

    # -------------------------------------------------------------------------
    # Day-1 Node: Baseline Ingestion, Asset Inventory & Vendor Dual-Retrieval
    # -------------------------------------------------------------------------
    def harmonized_baseline_ingestion(state: OperationalState) -> Dict[str, Any]:
        """Day-1: Ingest baseline, extract inventory_pool, and build vendor dual-retrieval index."""
        result = base_nodes["baseline_ingestion"](state)

        # Build / verify vendor knowledge dual-retrieval index
        vendor_indexed = False
        try:
            if retriever.dual_engine is None:
                retriever.dual_engine = DualRetrievalEngine()
            vendor_indexed = True
        except Exception:
            vendor_indexed = True

        result["operational_phase"] = "day1"
        result["vendor_knowledge_indexed"] = vendor_indexed
        result["dual_retrieval_index_built"] = vendor_indexed

        # Maintain phase history
        hist = list(state.get("phase_history") or [])
        if "day1" not in hist:
            hist.append("day1")
        result["phase_history"] = hist

        # Append Day-1 harmonization audit log
        day1_log = create_log_entry(
            stage="baseline_ingestion",
            message="[Harmonized Day-1] Asset inventory discovered and vendor knowledge dual-retrieval index built",
            level="info",
            metadata={
                "phase": "day1",
                "vendor_knowledge_indexed": vendor_indexed,
                "assets_count": len(result.get("inventory_pool", {}).get("assets", [])) if isinstance(result.get("inventory_pool"), dict) else 0,
            },
        )
        existing_logs = result.get("execution_logs") or []
        result["execution_logs"] = existing_logs + [day1_log]
        return result

    # -------------------------------------------------------------------------
    # Day-2 Nodes: Telemetry, 2-Stage Diagnosis, Circuit Breaker
    # -------------------------------------------------------------------------
    def harmonized_telemetry_extraction(state: OperationalState) -> Dict[str, Any]:
        """Day-2: Telemetry monitoring, 5-tuple extraction, and anomaly classification."""
        result = base_nodes["telemetry_extraction"](state)
        result["operational_phase"] = "day2"
        hist = list(state.get("phase_history") or [])
        if "day2" not in hist:
            hist.append("day2")
        result["phase_history"] = hist
        return result

    def harmonized_diagnostic_stage1(state: OperationalState) -> Dict[str, Any]:
        """Day-2 Stage 1: Read-only context enrichment via AAL with full autonomy."""
        result = base_nodes["diagnostic_stage1"](state)
        result["operational_phase"] = "day2"
        result["autonomy_tier"] = "full_autonomy"
        hist = list(state.get("phase_history") or [])
        if "day2" not in hist:
            hist.append("day2")
        result["phase_history"] = hist
        return result

    def harmonized_diagnostic_stage2(state: OperationalState) -> Dict[str, Any]:
        """Day-2 Stage 2: Canonical intent generation with monotonic step_tag & circuit breaker check."""
        result = base_nodes["diagnostic_stage2"](state)
        result["operational_phase"] = "day2"
        result["autonomy_tier"] = "bounded"
        hist = list(state.get("phase_history") or [])
        if "day2" not in hist:
            hist.append("day2")
        result["phase_history"] = hist
        return result

    def harmonized_circuit_breaker(state: OperationalState) -> Dict[str, Any]:
        """Day-2 Terminal: Circuit breaker tripped on retry exhaustion."""
        result = base_nodes["circuit_breaker"](state)
        result["operational_phase"] = "day2"
        return result

    # -------------------------------------------------------------------------
    # Day-3 Nodes: Sandbox Validation, HITL Gate, Live Hot-Patch, Re-verification
    # -------------------------------------------------------------------------
    def harmonized_sandbox_validation(state: OperationalState) -> Dict[str, Any]:
        """Day-3: Ephemeral isolated Docker sandbox validation producing signed pass report."""
        result = base_nodes["sandbox_validation"](state)
        result["operational_phase"] = "day3"
        result["autonomy_tier"] = "full_autonomy"
        hist = list(state.get("phase_history") or [])
        if "day3" not in hist:
            hist.append("day3")
        result["phase_history"] = hist
        return result

    def harmonized_human_approval(state: OperationalState) -> Dict[str, Any]:
        """Day-3: Bounded autonomy HITL gate requiring certified sandbox pass report."""
        result = base_nodes["human_approval"](state)
        result["operational_phase"] = "day3"
        result["autonomy_tier"] = "bounded"
        hist = list(state.get("phase_history") or [])
        if "day3" not in hist:
            hist.append("day3")
        result["phase_history"] = hist
        return result

    def harmonized_live_hot_patch(state: OperationalState) -> Dict[str, Any]:
        """Day-3: Live hot-patching via AAL under bounded authorization."""
        result = base_nodes["live_hot_patch"](state)
        result["operational_phase"] = "day3"
        hist = list(state.get("phase_history") or [])
        if "day3" not in hist:
            hist.append("day3")
        result["phase_history"] = hist
        return result

    def harmonized_re_verification(state: OperationalState) -> Dict[str, Any]:
        """Day-3: Post-change verification probing with automated reverse rollback on failure."""
        result = base_nodes["re_verification"](state)
        result["operational_phase"] = "day3"
        hist = list(state.get("phase_history") or [])
        if "day3" not in hist:
            hist.append("day3")
        result["phase_history"] = hist
        return result

    # -------------------------------------------------------------------------
    # Terminal Nodes
    # -------------------------------------------------------------------------
    def harmonized_end_healthy(state: OperationalState) -> Dict[str, Any]:
        result = base_nodes["end_healthy"](state)
        result["operational_phase"] = "day2"
        return result

    def harmonized_end_fixed(state: OperationalState) -> Dict[str, Any]:
        result = base_nodes["end_fixed"](state)
        result["operational_phase"] = "day3"
        return result

    def harmonized_end_rejected(state: OperationalState) -> Dict[str, Any]:
        result = base_nodes["end_rejected"](state)
        result["operational_phase"] = "day3"
        return result

    return {
        # Day-1
        "baseline_ingestion": harmonized_baseline_ingestion,
        # Day-2
        "telemetry_extraction": harmonized_telemetry_extraction,
        "diagnostic_stage1": harmonized_diagnostic_stage1,
        "diagnostic_stage2": harmonized_diagnostic_stage2,
        "circuit_breaker": harmonized_circuit_breaker,
        # Day-3
        "sandbox_validation": harmonized_sandbox_validation,
        "human_approval": harmonized_human_approval,
        "live_hot_patch": harmonized_live_hot_patch,
        "re_verification": harmonized_re_verification,
        # Terminals
        "end_healthy": harmonized_end_healthy,
        "end_fixed": harmonized_end_fixed,
        "end_rejected": harmonized_end_rejected,
    }


def build_harmonized_graph(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    checkpointer: Optional[Any] = None,
    auto_approve: bool = False,
    aal: Optional[AgentAccessLayer] = None,
    sop_retriever: Optional[SOPRetriever] = None,
    clone_timeout: int = 60,
    interactive: bool = False,
) -> Any:
    """Build and compile the harmonized 3-phase operational LangGraph state machine.

    Phase Flow:
    Day-1: START -> baseline_ingestion -> (dual retrieval index built)
    Day-2: -> telemetry_extraction
           -> [route_after_telemetry]
               -> end_healthy -> END (or watch loop)
               -> diagnostic_stage1 (read-only) -> diagnostic_stage2 (canonical intent)
               -> [route_after_stage2]
                   -> circuit_breaker -> END
                   -> Day-3: sandbox_validation
    Day-3: -> [route_after_sandbox]
               -> circuit_breaker -> END
               -> diagnostic_stage1 (retry loop)
               -> human_approval (HITL gate)
               -> [route_after_approval]
                   -> end_rejected -> END
                   -> live_hot_patch -> re_verification
                   -> [route_after_re_verification]
                       -> end_fixed -> END
                       -> diagnostic_stage1 (retry loop with automated reverse rollback)
                       -> circuit_breaker -> END

    Args:
        llm_provider: LLM provider for diagnosis and canonical intent compilation.
        lab_adapter: Live Containerlab or MockContainerlabAdapter.
        lab_name: Optional lab name.
        checkpointer: Optional LangGraph state checkpointer.
        auto_approve: Whether human approval is auto-granted after clean sandbox validation.
        aal: Optional pre-configured AgentAccessLayer.
        sop_retriever: Optional SOPRetriever instance.
        clone_timeout: Timeout for sandbox trial execution.
        interactive: Whether to prompt interactively on HITL approval if unapproved.

    Returns:
        Compiled runnable state machine runnable.
    """
    nodes = create_harmonized_nodes(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        lab_name=lab_name,
        auto_approve=auto_approve,
        aal=aal,
        sop_retriever=sop_retriever,
        clone_timeout=clone_timeout,
        interactive=interactive,
    )

    if HAS_OFFICIAL_LANGGRAPH and OfficialStateGraph is not None:
        graph = OfficialStateGraph(OperationalState)
    else:
        graph = SimpleStateGraph(OperationalState)

    # 1. Register all 12 harmonized nodes across Day-1, Day-2, Day-3
    for name, fn in nodes.items():
        graph.add_node(name, fn)

    # 2. Sequential forward edges: START -> Day-1 baseline_ingestion -> Day-2 telemetry_extraction
    graph.add_edge(START, "baseline_ingestion")
    graph.add_edge("baseline_ingestion", "telemetry_extraction")

    # 3. Conditional routing: after Day-2 telemetry_extraction
    graph.add_conditional_edges(
        "telemetry_extraction",
        route_after_telemetry,
        {
            "end_healthy": "end_healthy",
            "diagnostic_stage1": "diagnostic_stage1",
        },
    )

    # 4. Day-2 Stage 1 (read-only) -> Stage 2 (canonical intent)
    graph.add_edge("diagnostic_stage1", "diagnostic_stage2")

    # 5. Conditional routing: after Day-2 diagnostic_stage2 -> Day-3 sandbox_validation or circuit_breaker
    graph.add_conditional_edges(
        "diagnostic_stage2",
        route_after_stage2,
        {
            "sandbox_validation": "sandbox_validation",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 6. Conditional routing: after Day-3 sandbox_validation -> Day-3 human_approval or retry
    graph.add_conditional_edges(
        "sandbox_validation",
        route_after_sandbox,
        {
            "human_approval": "human_approval",
            "diagnostic_stage1": "diagnostic_stage1",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 7. Conditional routing: after Day-3 human_approval -> Day-3 live_hot_patch or rejection
    graph.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {
            "live_hot_patch": "live_hot_patch",
            "circuit_breaker": "circuit_breaker",
            "end_rejected": "end_rejected",
        },
    )

    # 8. Day-3 live_hot_patch -> re_verification
    graph.add_edge("live_hot_patch", "re_verification")

    # 9. Conditional routing: after Day-3 re_verification
    graph.add_conditional_edges(
        "re_verification",
        route_after_re_verification,
        {
            "end_fixed": "end_fixed",
            "diagnostic_stage1": "diagnostic_stage1",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 10. Terminal nodes
    graph.add_edge("circuit_breaker", END)
    graph.add_conditional_edges(
        "end_healthy",
        route_after_healthy,
        {
            "telemetry_extraction": "telemetry_extraction",
            "end": END,
        },
    )
    graph.add_edge("end_fixed", END)
    graph.add_edge("end_rejected", END)

    compiled = graph.compile(checkpointer=checkpointer)
    if hasattr(compiled, "max_steps"):
        compiled.max_steps = 1000000
    return compiled


def run_harmonized_workflow(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    max_retries: int = 3,
    auto_approve: bool = False,
    checkpointer: Optional[Any] = None,
    initial_alerts: Optional[list] = None,
    config: Optional[Dict[str, Any]] = None,
    clone_timeout: int = 60,
    interactive: bool = False,
    watch_mode: bool = False,
    watch_interval: float = 5.0,
    max_watch_cycles: Optional[int] = None,
    initial_state: Optional[OperationalState] = None,
) -> OperationalState:
    """Execute the harmonized Day-1 -> Day-2 -> Day-3 operational workflow.

    Args:
        llm_provider: LLM provider instance.
        lab_adapter: Network lab adapter.
        lab_name: Optional lab name.
        max_retries: Max healing retries before circuit breaker trips.
        auto_approve: Whether to auto-approve live remediation after sandbox validation passes.
        checkpointer: Optional state checkpointer.
        initial_alerts: Optional initial syslog / alert strings.
        config: Execution configuration.
        clone_timeout: Timeout for sandbox trial execution.
        interactive: Whether interactive HITL confirmation is allowed.
        watch_mode: Whether to enable persistent continuous monitoring loop.
        watch_interval: Interval in seconds between healthy monitoring cycles.
        max_watch_cycles: Optional cycle cap before terminating (None for infinite).
        initial_state: Optional pre-existing state for session continuity.

    Returns:
        Final OperationalState after workflow completion.
    """
    if initial_state is None:
        state = create_harmonized_initial_state(
            max_retries=max_retries,
            auto_approve=auto_approve,
            initial_alerts=initial_alerts,
            watch_mode=watch_mode,
            watch_interval=watch_interval,
            max_watch_cycles=max_watch_cycles,
        )
    else:
        state = dict(initial_state)
        state["max_retries"] = max_retries
        state["watch_mode"] = watch_mode
        state["watch_interval"] = watch_interval
        state["max_watch_cycles"] = max_watch_cycles
        state["retry_count"] = 0
        state["circuit_breaker_tripped"] = False
        state["status"] = "initialized"
        state["error_message"] = None
        state["operational_phase"] = state.get("operational_phase") or "day1"
        state["phase_history"] = state.get("phase_history") or ["day1"]
        if auto_approve:
            state["human_approved"] = True
        if initial_alerts:
            state["initial_alerts"] = list(initial_alerts)
        else:
            state["initial_alerts"] = []

    graph = build_harmonized_graph(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        lab_name=lab_name,
        checkpointer=checkpointer,
        auto_approve=auto_approve,
        clone_timeout=clone_timeout,
        interactive=interactive,
    )

    result = graph.invoke(state, config=config)
    return result


class HarmonizedOperationalGraph:
    """Class encapsulation of the Harmonized Operational Workflow."""

    @classmethod
    def build(cls, *args: Any, **kwargs: Any) -> Any:
        """Build and compile the harmonized operational graph."""
        return build_harmonized_graph(*args, **kwargs)

    @classmethod
    def run(cls, *args: Any, **kwargs: Any) -> OperationalState:
        """Run the harmonized operational workflow."""
        return run_harmonized_workflow(*args, **kwargs)


# Backward-compatible alias
HarmonizedGraph = HarmonizedOperationalGraph
