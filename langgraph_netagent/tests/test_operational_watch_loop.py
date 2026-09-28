"""Unit and Integration Tests for Continuous Monitoring Watch Loop (R1 / Milestone 4).

Validates:
1. `route_after_healthy` routing logic when watch_mode is disabled vs enabled vs cycle cap reached.
2. `end_healthy_node` state updates (cycle increment, timestamp, fault resets, inventory preservation).
3. `baseline_ingestion_node` fast-path caching.
4. `run_operational_workflow` with watch_mode=True, max_watch_cycles=3, watch_interval=0.001 runs 3 cycles and terminates cleanly.
5. Self-healing in watch loop: inject fault, heal to fixed/healthy, verify watch continues.
6. `create_operational_initial_state` watch control parameter initialization.
"""

from datetime import datetime
import time
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan, RollbackStep
from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)
from langgraph_netagent.workflow.operational_edges import (
    route_after_healthy,
)
from langgraph_netagent.workflow.operational_graph import (
    build_operational_graph,
    run_operational_workflow,
)
from langgraph_netagent.workflow.operational_nodes import (
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)


# ---------------------------------------------------------------------------
# Test Fixtures & Mocks
# ---------------------------------------------------------------------------

class MockWatchLLMProvider:
    """Mock LLM for watch loop tests."""

    def __init__(self, target_node: str = "frr1"):
        self.target_node = target_node
        self.call_count = 0

    def generate_structured(self, messages: list, response_schema: type):
        self.call_count += 1
        if response_schema == DiagnosticReport:
            return DiagnosticReport(
                telemetry_trigger="Packet drop 10.1.1.2 -> 10.2.2.2",
                root_cause=f"Missing static route on {self.target_node}",
                affected_nodes=[self.target_node],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.95,
                evidence=["Ping failure 10.1.1.2 -> 10.2.2.2"],
            )
        elif response_schema == RemediationPlan:
            return RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity=self.target_node,
                exec_commands=[f"vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
                rollback_steps=[
                    RollbackStep(
                        step_order=1,
                        description="Rollback route",
                        action="EXEC_COMMAND",
                        target_node=self.target_node,
                        payload=f"vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'",
                    )
                ],
                expected_outcome="Reachability restored",
                estimated_risk=SeverityLevel.LOW,
            )
        raise ValueError(f"Unexpected schema: {response_schema}")


class MockWatchAdapter(BaseNetworkLabAdapter):
    """Adapter simulating a healthy or faulty network for watch loop tests."""

    def __init__(self, healthy: bool = True):
        self.healthy = healthy
        self.patched = False
        self.exec_history = []
        self.inspect_calls = 0

    def deploy(self, topo_file, reconfigure=True) -> DeploymentResult:
        return DeploymentResult(
            success=True,
            lab_name="watch-lab",
            topo_file=str(topo_file),
            nodes_deployed=["pc1", "frr1", "srl1", "pc2"],
        )

    def destroy(self, topo_file=None, lab_name=None, cleanup=True) -> DestructionResult:
        return DestructionResult(success=True, lab_name="watch-lab")

    def inspect(self, topo_file=None, lab_name=None) -> LabInspectionResult:
        self.inspect_calls += 1
        nodes = [
            LabNodeState(name="pc1", container_id="clab-pc1", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.2"),
            LabNodeState(name="frr1", container_id="clab-frr1", image="frrouting/frr", kind="linux", state="running", ipv4_address="172.100.100.3"),
            LabNodeState(name="srl1", container_id="clab-srl1", image="ghcr.io/nokia/srlinux", kind="nokia_srlinux", state="running", ipv4_address="172.100.100.4"),
            LabNodeState(name="pc2", container_id="clab-pc2", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.5"),
        ]
        return LabInspectionResult(success=True, lab_name="watch-lab", nodes=nodes)

    def exec_command(self, node_name: str, command: str, timeout: int = 15) -> CommandResult:
        self.exec_history.append({"node": node_name, "command": command})

        if "ip addr show" in command:
            ip_map = {
                "pc1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.2/24 scope global eth1",
                "frr1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.1/24 scope global eth1\n3: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.1/24 scope global eth2",
                "srl1": "2: e1-1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.2/24 scope global e1-1\n3: e1-2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.1/24 scope global e1-2",
                "pc2": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.2/24 scope global eth1",
            }
            return CommandResult(command=command, exit_code=0, stdout=ip_map.get(node_name, ""), node=node_name)

        base_node = node_name.replace("sandbox_", "") if node_name.startswith("sandbox_") else node_name

        if "vtysh" in command and "configure" in command:
            if not node_name.startswith("sandbox_"):
                self.patched = True
            return CommandResult(command=command, exit_code=0, stdout="Configuration applied\n", node=node_name)

        if "route" in command.lower():
            if base_node == "frr1":
                if self.healthy or self.patched or node_name.startswith("sandbox_"):
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2\nS>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2", node=node_name)
                else:
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2", node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="default via 10.1.1.1 dev eth1", node=node_name)

        if "ping" in command:
            dst_ip = command.split()[-1]
            reachable = self.healthy or self.patched
            if reachable or dst_ip in ("10.1.1.1", "10.1.1.2", "10.1.12.1", "10.1.12.2"):
                return CommandResult(
                    command=command, exit_code=0,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 3 received, 0% packet loss\nrtt avg = 0.080 ms",
                    node=node_name,
                )
            else:
                return CommandResult(
                    command=command, exit_code=1,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 0 received, 100% packet loss",
                    node=node_name,
                )

        return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

    def is_live_ready(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Tests: 1. Initial State Watch Parameters
# ---------------------------------------------------------------------------

def test_create_operational_initial_state_watch_fields():
    """Verify create_operational_initial_state initializes continuous monitoring fields."""
    state = create_operational_initial_state(
        max_retries=3,
        auto_approve=True,
        watch_mode=True,
        watch_interval=2.5,
        max_watch_cycles=5,
    )
    assert state["watch_mode"] is True
    assert state["watch_interval"] == 2.5
    assert state["watch_cycle"] == 0
    assert state["max_watch_cycles"] == 5
    assert state["last_healthy_timestamp"] is None
    assert state["consecutive_healthy_cycles"] == 0


def test_create_operational_initial_state_default_watch_fields():
    """Verify default values for watch parameters preserve one-shot execution."""
    state = create_operational_initial_state()
    assert state["watch_mode"] is False
    assert state["watch_interval"] == 5.0
    assert state["watch_cycle"] == 0
    assert state["max_watch_cycles"] is None
    assert state["last_healthy_timestamp"] is None
    assert state["consecutive_healthy_cycles"] == 0


# ---------------------------------------------------------------------------
# Tests: 2. route_after_healthy Routing Logic
# ---------------------------------------------------------------------------

def test_route_after_healthy_watch_mode_disabled():
    """When watch_mode is False or None, route_after_healthy routes to 'end'."""
    state1 = create_operational_initial_state(watch_mode=False)
    assert route_after_healthy(state1) == "end"

    state2 = create_operational_initial_state()
    assert route_after_healthy(state2) == "end"


def test_route_after_healthy_watch_mode_unbounded():
    """When watch_mode is True and max_watch_cycles is None or <= 0, routes to telemetry."""
    state_none = create_operational_initial_state(watch_mode=True, max_watch_cycles=None)
    state_none["watch_cycle"] = 10
    assert route_after_healthy(state_none) == "telemetry_extraction"

    state_zero = create_operational_initial_state(watch_mode=True, max_watch_cycles=0)
    state_zero["watch_cycle"] = 5
    assert route_after_healthy(state_zero) == "telemetry_extraction"

    state_neg = create_operational_initial_state(watch_mode=True, max_watch_cycles=-1)
    state_neg["watch_cycle"] = 2
    assert route_after_healthy(state_neg) == "telemetry_extraction"


def test_route_after_healthy_cycle_cap_reached():
    """When watch_mode is True and watch_cycle reaches or exceeds max_watch_cycles, routes to 'end'."""
    state = create_operational_initial_state(watch_mode=True, max_watch_cycles=3)

    state["watch_cycle"] = 0
    assert route_after_healthy(state) == "telemetry_extraction"

    state["watch_cycle"] = 1
    assert route_after_healthy(state) == "telemetry_extraction"

    state["watch_cycle"] = 2
    assert route_after_healthy(state) == "telemetry_extraction"

    state["watch_cycle"] = 3
    assert route_after_healthy(state) == "end"

    state["watch_cycle"] = 4
    assert route_after_healthy(state) == "end"


# ---------------------------------------------------------------------------
# Tests: 3. end_healthy_node State Updates
# ---------------------------------------------------------------------------

def test_end_healthy_node_state_updates():
    """Test end_healthy_node increments counters, updates timestamp, and resets faults."""
    adapter = MockWatchAdapter(healthy=True)
    nodes = create_operational_nodes(
        llm_provider=MockWatchLLMProvider(),
        lab_adapter=adapter,
    )
    end_healthy_fn = nodes["end_healthy"]

    # Create state with transient fault artifacts
    state = create_operational_initial_state(watch_mode=True, watch_interval=0.001, max_watch_cycles=5)
    state["watch_cycle"] = 2
    state["consecutive_healthy_cycles"] = 2
    state["failure_5tuples"] = [{"source_ip": "10.1.1.2", "destination_ip": "10.2.2.2"}]
    state["discrepancies"] = [{"discrepancy_type": "link_drop", "node": "frr1"}]
    state["suspect_devices"] = ["frr1"]
    state["error_message"] = "Previous transient issue"
    state["retry_count"] = 2
    state["current_step_tag"] = "STEP-TAG-2"
    state["baseline"] = {"nodes": {"pc1": {}}}
    state["inventory_pool"] = {"assets": ["pc1", "frr1"]}

    update = end_healthy_fn(state)

    assert update["watch_cycle"] == 3
    assert update["consecutive_healthy_cycles"] == 3
    assert update["last_healthy_timestamp"] is not None
    # Parse timestamp to ensure valid ISO format
    ts = datetime.fromisoformat(update["last_healthy_timestamp"])
    assert ts is not None

    # Transient fault attributes must be reset
    assert update["failure_5tuples"] == []
    assert update["discrepancies"] == []
    assert update["suspect_devices"] == []
    assert update["error_message"] is None
    assert update["retry_count"] == 0
    assert update["current_step_tag"] is None
    assert update["status"] == "healthy"
    assert len(update["execution_logs"]) == 1
    assert update["execution_logs"][0]["stage"] == "end_healthy"


def test_end_healthy_node_does_not_sleep_on_terminal_cycle():
    """Verify end_healthy_node skips sleeping when cycle cap is reached (terminal cycle)."""
    adapter = MockWatchAdapter(healthy=True)
    nodes = create_operational_nodes(
        llm_provider=MockWatchLLMProvider(),
        lab_adapter=adapter,
    )
    end_healthy_fn = nodes["end_healthy"]

    # State where current cycle will reach max_watch_cycles (2 -> 3 with max=3)
    state = create_operational_initial_state(watch_mode=True, watch_interval=5.0, max_watch_cycles=3)
    state["watch_cycle"] = 2  # next will be 3, which equals max_watch_cycles

    start = time.perf_counter()
    update = end_healthy_fn(state)
    elapsed = time.perf_counter() - start

    assert update["watch_cycle"] == 3
    # Elapsed time must be minimal (< 0.2s), proving it skipped the 5.0s sleep
    assert elapsed < 0.2


# ---------------------------------------------------------------------------
# Tests: 4. baseline_ingestion_node Fast-Path Caching
# ---------------------------------------------------------------------------

def test_baseline_ingestion_node_fast_path_caching():
    """Verify baseline_ingestion_node reuses cached inventory without querying adapter."""
    adapter = MockWatchAdapter(healthy=True)
    nodes = create_operational_nodes(
        llm_provider=MockWatchLLMProvider(),
        lab_adapter=adapter,
    )
    baseline_fn = nodes["baseline_ingestion"]

    # 1. First run without cached inventory: calls inspect
    state_empty = create_operational_initial_state()
    result1 = baseline_fn(state_empty)
    assert result1["status"] == "baseline_ingested"
    assert adapter.inspect_calls == 1

    # 2. Second run with populated baseline & inventory_pool: hits fast path cache
    state_cached = create_operational_initial_state()
    state_cached["baseline"] = result1["baseline"]
    state_cached["inventory_pool"] = result1["inventory_pool"]
    state_cached["topology_path"] = result1["topology_path"]
    state_cached["node_kinds"] = result1["node_kinds"]

    result2 = baseline_fn(state_cached)
    assert result2["status"] == "baseline_ingested"
    # Inspect calls should NOT have increased!
    assert adapter.inspect_calls == 1
    assert result2["baseline"] == result1["baseline"]
    assert result2["inventory_pool"] == result1["inventory_pool"]
    assert any("Fast-path session cache hit" in log["message"] for log in result2["execution_logs"])


# ---------------------------------------------------------------------------
# Tests: 5. run_operational_workflow with Multi-Cycle Watch Loop
# ---------------------------------------------------------------------------

def test_run_operational_workflow_watch_cycles():
    """Verify run_operational_workflow executes requested watch cycles and cleanly halts."""
    adapter = MockWatchAdapter(healthy=True)
    llm = MockWatchLLMProvider()

    final_state = run_operational_workflow(
        llm_provider=llm,
        lab_adapter=adapter,
        watch_mode=True,
        max_watch_cycles=3,
        watch_interval=0.001,
    )

    assert final_state["status"] == "healthy"
    assert final_state["watch_cycle"] == 3
    assert final_state["consecutive_healthy_cycles"] == 3
    assert final_state["last_healthy_timestamp"] is not None

    # Check that execution logs contain entries from multiple watch cycles
    healthy_logs = [log for log in final_state["execution_logs"] if log.get("stage") == "end_healthy"]
    assert len(healthy_logs) == 3


# ---------------------------------------------------------------------------
# Tests: 6. Self-Healing in Watch Loop
# ---------------------------------------------------------------------------

def test_watch_loop_self_healing_and_continuity():
    """Verify that after healing an incident, session state preserves continuity into watch cycles."""
    # 1. Start with an unhealthy network
    adapter = MockWatchAdapter(healthy=False)
    llm = MockWatchLLMProvider(target_node="frr1")

    # Workflow runs to diagnose, sandbox, patch, and re-verify
    fixed_state = run_operational_workflow(
        llm_provider=llm,
        lab_adapter=adapter,
        auto_approve=True,
        watch_mode=False,
    )

    assert fixed_state["status"] == "fixed"
    assert adapter.patched is True
    assert fixed_state.get("remediation_plan") is not None

    # 2. Subsequent monitoring run takes fixed_state as initial_state
    # Fast path baseline caching is used, network is verified healthy, and watch increments
    watch_state = run_operational_workflow(
        llm_provider=llm,
        lab_adapter=adapter,
        initial_state=fixed_state,
        watch_mode=True,
        max_watch_cycles=2,
        watch_interval=0.001,
    )

    assert watch_state["status"] == "healthy"
    assert watch_state["watch_cycle"] == 2
    assert watch_state["consecutive_healthy_cycles"] == 2
    assert watch_state["failure_5tuples"] == []
    assert watch_state["discrepancies"] == []
    assert watch_state["retry_count"] == 0
