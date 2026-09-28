"""Day-2 LangGraph State Machine Builder and Runner.

Builds the Day-2 operations graph:
  read_baseline -> probe_matrix -> (healthy? END : hop_pruning)
  -> llm_diagnosis -> generate_patch -> dry_run_check
  -> (passed? human_approval : loop/circuit_breaker)
  -> hot_patch -> re_verify -> (fixed? END : loop/circuit_breaker)
"""

from __future__ import annotations
from typing import Any, Callable, Dict, Optional

from langgraph_netagent.llm.base import BaseLLMProvider
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.workflow.day2_edges import (
    route_after_approval,
    route_after_dry_run,
    route_after_probe,
    route_after_re_verify,
)
from langgraph_netagent.workflow.day2_nodes import create_day2_nodes
from langgraph_netagent.workflow.day2_state import (
    Day2OpsState,
    create_day2_initial_state,
)

# Import graph infrastructure (dual-mode: official langgraph or fallback)
try:
    from langgraph.checkpoint.memory import MemorySaver as OfficialMemorySaver
    from langgraph.graph import END as OFFICIAL_END
    from langgraph.graph import START as OFFICIAL_START
    from langgraph.graph import StateGraph as OfficialStateGraph

    HAS_OFFICIAL_LANGGRAPH = True
except ImportError:
    HAS_OFFICIAL_LANGGRAPH = False
    OFFICIAL_START = "__start__"
    OFFICIAL_END = "__end__"
    OfficialStateGraph = None
    OfficialMemorySaver = None

# Use fallback SimpleStateGraph if official not available
from langgraph_netagent.workflow.graph import SimpleStateGraph

START = OFFICIAL_START if HAS_OFFICIAL_LANGGRAPH else "__start__"
END = OFFICIAL_END if HAS_OFFICIAL_LANGGRAPH else "__end__"


def build_day2_graph(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    checkpointer: Optional[Any] = None,
    auto_approve: bool = False,
) -> Any:
    """Build and compile the Day-2 operations LangGraph state machine.

    The graph implements 10 active nodes + 3 terminal nodes:

    ```
    START -> read_baseline -> probe_matrix
          -> [route_after_probe]
              -> end_healthy (all pass) -> END
              -> hop_pruning -> llm_diagnosis -> generate_patch
              -> dry_run_check -> [route_after_dry_run]
                  -> human_approval -> [route_after_approval]
                      -> hot_patch -> re_verify -> [route_after_re_verify]
                          -> end_fixed -> END
                          -> llm_diagnosis (loop)
                          -> circuit_breaker -> END
                      -> end_rejected -> END
                  -> llm_diagnosis (loop on dry-run fail)
                  -> circuit_breaker -> END
    ```

    Args:
        llm_provider: LLM provider for diagnosis and remediation generation.
        lab_adapter: Live Containerlab adapter.
        lab_name: Optional lab name for baseline collection.
        checkpointer: Optional state checkpointer.
        auto_approve: If True, human approval is auto-granted.

    Returns:
        Compiled runnable state graph.
    """
    nodes = create_day2_nodes(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        lab_name=lab_name,
        auto_approve=auto_approve,
    )

    # Select graph implementation
    if HAS_OFFICIAL_LANGGRAPH and OfficialStateGraph is not None:
        graph = OfficialStateGraph(Day2OpsState)
    else:
        graph = SimpleStateGraph(Day2OpsState)

    # ----------------------------------------------------------------
    # 1. Register all 13 nodes
    # ----------------------------------------------------------------
    for name, fn in nodes.items():
        graph.add_node(name, fn)

    # ----------------------------------------------------------------
    # 2. Entry point and sequential edges
    # ----------------------------------------------------------------
    graph.add_edge(START, "read_baseline")
    graph.add_edge("read_baseline", "probe_matrix")

    # ----------------------------------------------------------------
    # 3. Conditional edge: after probe_matrix
    #    - all_passed -> end_healthy
    #    - failures   -> hop_pruning
    # ----------------------------------------------------------------
    graph.add_conditional_edges(
        "probe_matrix",
        route_after_probe,
        {
            "end_healthy": "end_healthy",
            "hop_pruning": "hop_pruning",
        },
    )

    # ----------------------------------------------------------------
    # 4. Sequential: hop_pruning -> llm_diagnosis -> generate_patch -> dry_run_check
    # ----------------------------------------------------------------
    graph.add_edge("hop_pruning", "llm_diagnosis")
    graph.add_edge("llm_diagnosis", "generate_patch")
    graph.add_edge("generate_patch", "dry_run_check")

    # ----------------------------------------------------------------
    # 5. Conditional edge: after dry_run_check
    #    - passed            -> human_approval
    #    - failed + retries  -> llm_diagnosis (re-generate)
    #    - failed + exhausted -> circuit_breaker
    # ----------------------------------------------------------------
    graph.add_conditional_edges(
        "dry_run_check",
        route_after_dry_run,
        {
            "human_approval": "human_approval",
            "llm_diagnosis": "llm_diagnosis",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # ----------------------------------------------------------------
    # 6. Conditional edge: after human_approval
    #    - approved -> hot_patch
    #    - rejected -> end_rejected
    # ----------------------------------------------------------------
    graph.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {
            "hot_patch": "hot_patch",
            "end_rejected": "end_rejected",
        },
    )

    # ----------------------------------------------------------------
    # 7. Sequential: hot_patch -> re_verify
    # ----------------------------------------------------------------
    graph.add_edge("hot_patch", "re_verify")

    # ----------------------------------------------------------------
    # 8. Conditional edge: after re_verify
    #    - all pass      -> end_fixed
    #    - fail + retries -> llm_diagnosis (re-diagnose)
    #    - fail + exhausted -> circuit_breaker
    # ----------------------------------------------------------------
    graph.add_conditional_edges(
        "re_verify",
        route_after_re_verify,
        {
            "end_fixed": "end_fixed",
            "llm_diagnosis": "llm_diagnosis",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # ----------------------------------------------------------------
    # 9. Terminal edges -> END
    # ----------------------------------------------------------------
    graph.add_edge("end_healthy", END)
    graph.add_edge("end_fixed", END)
    graph.add_edge("end_rejected", END)
    graph.add_edge("circuit_breaker", END)

    # ----------------------------------------------------------------
    # 10. Compile
    # ----------------------------------------------------------------
    compiled = graph.compile(checkpointer=checkpointer)
    return compiled


def run_day2_workflow(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    max_retries: int = 3,
    auto_approve: bool = False,
    checkpointer: Optional[Any] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Day2OpsState:
    """Execute the full Day-2 operations workflow.

    Args:
        llm_provider: LLM provider instance.
        lab_adapter: Live Containerlab adapter.
        lab_name: Optional lab name.
        max_retries: Maximum healing retries before circuit breaker.
        auto_approve: Whether to auto-approve remediation.
        checkpointer: Optional state checkpointer.
        config: Optional execution configuration.

    Returns:
        Final Day2OpsState after completion.
    """
    initial_state = create_day2_initial_state(
        max_retries=max_retries,
        auto_approve=auto_approve,
    )

    graph = build_day2_graph(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        lab_name=lab_name,
        checkpointer=checkpointer,
        auto_approve=auto_approve,
    )

    result = graph.invoke(initial_state, config=config)
    return result
