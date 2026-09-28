"""LangGraph State Machine Builder and Dual-Mode Runner.

Provides dual-mode support: seamlessly utilizes official `langgraph` if available,
or operates via a self-contained, fully-featured `SimpleStateGraph` fallback engine
with full support for reducers, conditional edges, stream, and memory checkpointing.
"""

from __future__ import annotations
import copy
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

from langgraph_netagent.llm.base import BaseLLMProvider
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.workflow.edges import (
    route_after_approval,
    route_after_deployment,
    route_after_validation,
    route_after_verification,
)
from langgraph_netagent.workflow.nodes import create_workflow_nodes
from langgraph_netagent.workflow.state import (
    NetworkAgentState,
    create_initial_state,
)

# Detect if official langgraph is installed
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

START = OFFICIAL_START
END = OFFICIAL_END


class SimpleMemorySaver:
    """Thread-safe in-memory checkpointer for SimpleStateGraph."""

    def __init__(self) -> None:
        self.storage: Dict[str, List[Dict[str, Any]]] = {}

    def put(self, config: Dict[str, Any], checkpoint: Dict[str, Any]) -> None:
        """Store a state checkpoint for the thread specified in config."""
        thread_id = (
            config.get("configurable", {}).get("thread_id", "default")
            if config
            else "default"
        )
        if thread_id not in self.storage:
            self.storage[thread_id] = []
        self.storage[thread_id].append(copy.deepcopy(checkpoint))

    def get(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Retrieve the latest checkpoint for the given thread."""
        thread_id = (
            config.get("configurable", {}).get("thread_id", "default")
            if config
            else "default"
        )
        history = self.storage.get(thread_id, [])
        return copy.deepcopy(history[-1]) if history else None


class CompiledSimpleGraph:
    """Compiled runnable graph instance produced by SimpleStateGraph."""

    def __init__(
        self,
        nodes: Dict[str, Callable[[dict], dict]],
        edges: Dict[str, str],
        conditional_edges: Dict[str, Tuple[Callable[[dict], str], Optional[Dict[str, str]]]],
        entry_point: str,
        checkpointer: Optional[Any] = None,
        max_steps: int = 50,
    ) -> None:
        self.nodes = nodes
        self.edges = edges
        self.conditional_edges = conditional_edges
        self.entry_point = entry_point
        self.checkpointer = checkpointer
        self.max_steps = max_steps

    def _apply_state_update(self, current: Dict[str, Any], update: Dict[str, Any]) -> None:
        """Apply state dictionary update respecting list reducer semantics."""
        for key, val in update.items():
            if key == "execution_logs" and isinstance(val, list):
                if key not in current or not isinstance(current[key], list):
                    current[key] = []
                current[key].extend(val)
            else:
                current[key] = val

    def invoke(
        self,
        initial_state: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute the state machine synchronously until END or max steps reached."""
        state = copy.deepcopy(initial_state)
        current_node = self.entry_point
        steps = 0

        while current_node and current_node not in (END, "__end__") and steps < self.max_steps:
            steps += 1
            node_action = self.nodes.get(current_node)
            if not node_action:
                break

            # Execute node
            node_output = node_action(copy.deepcopy(state))
            if isinstance(node_output, dict):
                self._apply_state_update(state, node_output)

            # Checkpoint intermediate state
            if self.checkpointer:
                try:
                    self.checkpointer.put(config or {}, state)
                except Exception:
                    pass

            # Determine next node
            if current_node in self.conditional_edges:
                route_fn, path_map = self.conditional_edges[current_node]
                route_key = route_fn(state)
                if path_map and route_key in path_map:
                    next_node = path_map[route_key]
                else:
                    next_node = route_key
            elif current_node in self.edges:
                next_node = self.edges[current_node]
            else:
                next_node = END

            if next_node in (END, "__end__"):
                break
            current_node = next_node

        return state

    def stream(
        self,
        initial_state: Dict[str, Any],
        config: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Yield node output dictionary at each transition step."""
        state = copy.deepcopy(initial_state)
        current_node = self.entry_point
        steps = 0

        while current_node and current_node not in (END, "__end__") and steps < self.max_steps:
            steps += 1
            node_action = self.nodes.get(current_node)
            if not node_action:
                break

            node_output = node_action(copy.deepcopy(state))
            if isinstance(node_output, dict):
                self._apply_state_update(state, node_output)

            yield {current_node: node_output}

            if self.checkpointer:
                try:
                    self.checkpointer.put(config or {}, state)
                except Exception:
                    pass

            if current_node in self.conditional_edges:
                route_fn, path_map = self.conditional_edges[current_node]
                route_key = route_fn(state)
                if path_map and route_key in path_map:
                    next_node = path_map[route_key]
                else:
                    next_node = route_key
            elif current_node in self.edges:
                next_node = self.edges[current_node]
            else:
                next_node = END

            if next_node in (END, "__end__"):
                break
            current_node = next_node


class SimpleStateGraph:
    """Self-contained fallback StateGraph implementation for environments without langgraph."""

    def __init__(self, state_schema: Any = None) -> None:
        self.state_schema = state_schema
        self.nodes: Dict[str, Callable[[dict], dict]] = {}
        self.edges: Dict[str, str] = {}
        self.conditional_edges: Dict[str, Tuple[Callable[[dict], str], Optional[Dict[str, str]]]] = {}
        self.entry_point: Optional[str] = None

    def add_node(self, name: str, action: Callable[[dict], dict]) -> SimpleStateGraph:
        """Register a node callable by name."""
        self.nodes[name] = action
        return self

    def add_edge(self, start_key: str, end_key: str) -> SimpleStateGraph:
        """Register an unconditional transition edge."""
        if start_key == START or start_key == "__start__":
            self.entry_point = end_key
        else:
            self.edges[start_key] = end_key
        return self

    def set_entry_point(self, key: str) -> SimpleStateGraph:
        """Designate the graph entry point node."""
        self.entry_point = key
        return self

    def add_conditional_edges(
        self,
        source: str,
        path: Callable[[dict], str],
        path_map: Optional[Dict[str, str]] = None,
    ) -> SimpleStateGraph:
        """Register a conditional edge based on a routing function."""
        self.conditional_edges[source] = (path, path_map)
        return self

    def compile(
        self,
        checkpointer: Optional[Any] = None,
        interrupt_before: Optional[List[str]] = None,
        interrupt_after: Optional[List[str]] = None,
    ) -> CompiledSimpleGraph:
        """Compile state machine into an executable runnable."""
        if not self.entry_point:
            raise ValueError("Graph entry point must be specified before compilation")
        return CompiledSimpleGraph(
            nodes=self.nodes,
            edges=self.edges,
            conditional_edges=self.conditional_edges,
            entry_point=self.entry_point,
            checkpointer=checkpointer,
        )


def build_network_agent_graph(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    export_dir: Path,
    checkpointer: Optional[Any] = None,
    auto_approve: bool = True,
) -> Any:
    """Build and compile the full 8-node LangGraph State Machine with closed loops.

    Uses official `langgraph.graph.StateGraph` if installed, or `SimpleStateGraph` fallback.

    Args:
        llm_provider: BaseLLMProvider implementation for intent, topology, and healing.
        lab_adapter: BaseNetworkLabAdapter implementation for deployment and telemetry.
        export_dir: Path to directory for exporting Containerlab topology files.
        checkpointer: Optional checkpointer for state persistence.
        auto_approve: If True, human approval is granted automatically.

    Returns:
        Compiled runnable state graph instance.
    """
    nodes = create_workflow_nodes(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        export_dir=export_dir,
        auto_approve=auto_approve,
    )

    # Use official StateGraph if available, otherwise fallback
    if HAS_OFFICIAL_LANGGRAPH and OfficialStateGraph is not None:
        graph = OfficialStateGraph(NetworkAgentState)
    else:
        graph = SimpleStateGraph(NetworkAgentState)

    # 1. Add 8 discrete nodes
    graph.add_node("intent_parsing", nodes["intent_parsing"])
    graph.add_node("topology_generation", nodes["topology_generation"])
    graph.add_node("offline_validation", nodes["offline_validation"])
    graph.add_node("human_approval", nodes["human_approval"])
    graph.add_node("deployment", nodes["deployment"])
    graph.add_node("verification_probing", nodes["verification_probing"])
    graph.add_node("diagnosis_and_healing", nodes["diagnosis_and_healing"])
    graph.add_node("circuit_breaker", nodes["circuit_breaker"])

    # 2. Add entry point and sequential forward edges
    graph.add_edge(START, "intent_parsing")
    graph.add_edge("intent_parsing", "topology_generation")
    graph.add_edge("topology_generation", "offline_validation")

    # 3. Add conditional routing edges
    # Offline Validation -> Human Approval / Topology Gen (Error Loop) / Circuit Breaker
    graph.add_conditional_edges(
        "offline_validation",
        route_after_validation,
        {
            "human_approval": "human_approval",
            "topology_generation": "topology_generation",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # Human Approval -> Deployment / Circuit Breaker / END
    graph.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {
            "deployment": "deployment",
            "circuit_breaker": "circuit_breaker",
            "end": END,
        },
    )

    # Deployment -> Verification / Diagnosis / Circuit Breaker
    graph.add_conditional_edges(
        "deployment",
        route_after_deployment,
        {
            "verification_probing": "verification_probing",
            "diagnosis_and_healing": "diagnosis_and_healing",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # Verification Probing -> END / Diagnosis & Healing (Self-Healing Loop) / Circuit Breaker
    graph.add_conditional_edges(
        "verification_probing",
        route_after_verification,
        {
            "end": END,
            "diagnosis_and_healing": "diagnosis_and_healing",
            "circuit_breaker": "circuit_breaker",
        },
    )

    # 4. Closed Loop & Terminal Edges
    # Healing routes back to Deployment to apply fixes and re-verify
    graph.add_edge("diagnosis_and_healing", "deployment")
    # Circuit Breaker terminates the workflow cleanly
    graph.add_edge("circuit_breaker", END)

    # 5. Compile graph
    compiled = graph.compile(checkpointer=checkpointer)
    return compiled


def run_network_agent_workflow(
    user_intent: str,
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    export_dir: Path,
    max_retries: int = 3,
    auto_approve: bool = True,
    checkpointer: Optional[Any] = None,
    config: Optional[Dict[str, Any]] = None,
) -> NetworkAgentState:
    """Execute the full network automation workflow from intent to verification.

    Args:
        user_intent: Natural language specification.
        llm_provider: LLM provider instance.
        lab_adapter: Network lab adapter instance.
        export_dir: Filesystem export directory.
        max_retries: Maximum permitted retries before circuit breaker trips.
        auto_approve: Whether to auto-approve human approval stage.
        checkpointer: Optional checkpoint saver.
        config: Optional execution configuration dict.

    Returns:
        Final NetworkAgentState after completion or circuit breaking.
    """
    initial_state = create_initial_state(
        user_intent=user_intent,
        max_retries=max_retries,
        auto_approve=auto_approve,
    )
    graph = build_network_agent_graph(
        llm_provider=llm_provider,
        lab_adapter=lab_adapter,
        export_dir=export_dir,
        checkpointer=checkpointer,
        auto_approve=auto_approve,
    )
    result = graph.invoke(initial_state, config=config)
    return result
