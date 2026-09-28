"""Operational LangGraph State Machine Builder and Runner.

Assembles the pure NetOps Incident Troubleshooting and Self-Healing Graph:
START -> Baseline Ingestion -> Telemetry/5-Tuple Extraction
      -> [route_after_telemetry]
          -> end_healthy -> END
          -> Diagnostic Stage 1 -> Diagnostic Stage 2
          -> [route_after_stage2]
              -> circuit_breaker -> END
              -> AAL Sandbox Validation -> [route_after_sandbox]
                  -> circuit_breaker -> END
                  -> Diagnostic Stage 1 (loop)
                  -> Human Approval -> [route_after_approval]
                      -> end_rejected -> END
                      -> Live Hot-Patch -> Re-verification -> [route_after_re_verification]
                          -> end_fixed -> END
                          -> Diagnostic Stage 1 (loop)
                          -> circuit_breaker -> END
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from langgraph_netagent.llm.base import BaseLLMProvider
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.sop_retriever import SOPRetriever
from langgraph_netagent.workflow.graph import (
    END,
    HAS_OFFICIAL_LANGGRAPH,
    OFFICIAL_END,
    OFFICIAL_START,
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
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)


def build_operational_graph(
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
    """Build and compile the operational NetOps LangGraph state machine.

    Args:
        llm_provider: LLM provider for 2-stage diagnosis and remediation generation.
        lab_adapter: Live or mock Containerlab adapter.
        lab_name: Optional lab name.
        checkpointer: Optional checkpointer for state checkpointing.
        auto_approve: Whether human approval is auto-granted after sandbox validation.
        aal: Optional pre-configured AgentAccessLayer.
        sop_retriever: Optional SOPRetriever instance.
        clone_timeout: Timeout for sandbox node cloning.
        interactive: Whether to prompt interactively on HITL approval if unapproved.

    Returns:
        Compiled executable state machine runnable.
    """
    nodes = create_operational_nodes(
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

    # 1. Register all 12 discrete nodes
    for name, fn in nodes.items():
        graph.add_node(name, fn)

    # 2. Sequential forward edges: START -> baseline_ingestion -> telemetry_extraction
    graph.add_edge(START, "baseline_ingestion")
    graph.add_edge("baseline_ingestion", "telemetry_extraction")

    # 3. Conditional routing: after telemetry_extraction
    graph.add_conditional_edges(
        "telemetry_extraction",
        route_after_telemetry,
        {
            "end_healthy": "end_healthy",
            "diagnostic_stage1": "diagnostic_stage1",
        },
    )

    # 4. Stage 1 -> Stage 2
    graph.add_edge("diagnostic_stage1", "diagnostic_stage2")

    # 5. Conditional routing: after diagnostic_stage2
    graph.add_conditional_edges(
        "diagnostic_stage2",
        route_after_stage2,
        {
            "sandbox_validation": "sandbox_validation",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 6. Conditional routing: after sandbox_validation
    graph.add_conditional_edges(
        "sandbox_validation",
        route_after_sandbox,
        {
            "human_approval": "human_approval",
            "diagnostic_stage1": "diagnostic_stage1",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 7. Conditional routing: after human_approval
    graph.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {
            "live_hot_patch": "live_hot_patch",
            "circuit_breaker": "circuit_breaker",
            "end_rejected": "end_rejected",
        },
    )

    # 8. Live hot-patch -> Re-verification
    graph.add_edge("live_hot_patch", "re_verification")

    # 9. Conditional routing: after re_verification
    graph.add_conditional_edges(
        "re_verification",
        route_after_re_verification,
        {
            "end_fixed": "end_fixed",
            "diagnostic_stage1": "diagnostic_stage1",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 10. Terminal nodes -> END
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


def run_operational_workflow(
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
    """Execute the pure operational troubleshooting and self-healing state machine.

    Args:
        llm_provider: LLM provider instance.
        lab_adapter: Network lab adapter.
        lab_name: Optional lab name.
        max_retries: Max healing retries before circuit breaker.
        auto_approve: Whether to auto-approve remediation after sandbox validation passes.
        checkpointer: Optional state checkpointer.
        initial_alerts: Optional initial syslog / alert strings.
        config: Execution configuration.
        clone_timeout: Timeout for sandbox node cloning.
        interactive: Whether interactive HITL confirmation is allowed.
        watch_mode: Whether to enable persistent continuous monitoring loop.
        watch_interval: Interval in seconds between healthy monitoring cycles.
        max_watch_cycles: Optional cycle cap before terminating (None for infinite).
        initial_state: Optional pre-existing OperationalState for session continuity.

    Returns:
        Final OperationalState after workflow completion.
    """
    if initial_state is None:
        state = create_operational_initial_state(
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
        if auto_approve:
            state["human_approved"] = True
        if initial_alerts:
            state["initial_alerts"] = list(initial_alerts)
        else:
            state["initial_alerts"] = []

    graph = build_operational_graph(
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

