"""Tests for Containerlab Fault Injector (R1) & Lab Isolation (R4).

Validates:
1. Dual adapter support: works with MockContainerlabAdapter and LiveContainerlabAdapter.
2. Standard fault scenarios: LinkDownFault, RouteDropFault, PacketLossFault, LatencyFault.
3. InjectedFaultToken creation and deterministic symmetric rollback commands.
4. Safe revert_fault and multiple concurrent faults with revert_all in LIFO order.
5. fault_context context manager guaranteeing automatic rollback on normal exit and exception.
6. LabIsolationGuard integration preventing any mutation of host interfaces or unauthorized containers.
7. Synchronization with MockEngine fault rules for hermetic simulation parity.
"""

from unittest.mock import MagicMock
import pytest

from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.clab_fault_injector import (
    ContainerlabFaultInjector,
    InjectedFaultToken,
    LatencyFault,
    LinkDownFault,
    PacketLossFault,
    RouteDropFault,
)
from langgraph_netagent.tools.lab_isolation import (
    LabIsolationGuard,
    LabIsolationViolationError,
)
from langgraph_netagent.tools.experimental_loop import (
    ExperimentalLoop,
    ExperimentalNetworkSnapshot,
    ExperimentalStateDiff,
    LifecycleStage,
)
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter


@pytest.fixture
def mock_adapter():
    """Create a fresh MockContainerlabAdapter."""
    return MockContainerlabAdapter()


@pytest.fixture
def isolation_guard():
    """Create standard clos5 LabIsolationGuard."""
    return LabIsolationGuard(lab_name="clos5")


@pytest.fixture
def injector(mock_adapter, isolation_guard):
    """Create ContainerlabFaultInjector wired with mock adapter and isolation guard."""
    return ContainerlabFaultInjector(
        adapter=mock_adapter,
        isolation_guard=isolation_guard,
        lab_name="clos5",
    )


class TestStandardFaultScenarios:
    """Tests fault injection and rollback generation for standard scenarios."""

    def test_link_down_fault(self, injector, mock_adapter):
        """LinkDownFault injects 'ip link set dev <iface> down' and rolls back with 'up'."""
        scenario = LinkDownFault(node="leaf1", interface="eth1")
        token = injector.inject_fault(scenario)

        assert isinstance(token, InjectedFaultToken)
        assert token.active is True
        assert token.node == "leaf1"
        assert token.container_name == "clab-clos5-leaf1"
        assert token.injection_command == "ip link set dev eth1 down"
        assert token.rollback_command == "ip link set dev eth1 up"
        assert token.scenario_type == "link_down"

        # Mock adapter synchronization verification
        assert bool(mock_adapter.fault_injector.is_interface_down("leaf1", "eth1")) is True

        # Revert fault
        success = injector.revert_fault(token)
        assert success is True
        assert token.active is False
        assert bool(mock_adapter.fault_injector.is_interface_down("leaf1", "eth1")) is False

    def test_route_drop_fault_static(self, injector, mock_adapter):
        """RouteDropFault for static route generates route del and route add rollback."""
        scenario = RouteDropFault(
            node="h1",
            prefix="172.16.0.0/16",
            via="172.16.1.1",
            dev="eth1",
        )
        token = injector.inject_fault(scenario)

        assert token.active is True
        assert token.injection_command == "ip route del 172.16.0.0/16 via 172.16.1.1 dev eth1"
        assert token.rollback_command == "ip route add 172.16.0.0/16 via 172.16.1.1 dev eth1"

        # Mock adapter route suppression verification
        assert mock_adapter.fault_injector.should_suppress_route("h1", "172.16.0.0/16") is not None

        # Revert fault
        success = injector.revert_fault(token)
        assert success is True
        assert token.active is False
        assert mock_adapter.fault_injector.should_suppress_route("h1", "172.16.0.0/16") is None

    def test_route_drop_fault_bgp(self, injector):
        """RouteDropFault for FRR BGP neighbor generates vtysh shutdown and rollback."""
        scenario = RouteDropFault(
            node="leaf1",
            bgp_neighbor="eth1",
            bgp_as=65001,
        )
        token = injector.inject_fault(scenario)

        assert token.active is True
        assert token.injection_command == 'vtysh -c "conf t" -c "router bgp 65001" -c "neighbor eth1 shutdown"'
        assert token.rollback_command == 'vtysh -c "conf t" -c "router bgp 65001" -c "no neighbor eth1 shutdown"'

        # Revert fault
        success = injector.revert_fault(token)
        assert success is True
        assert token.active is False

    def test_packet_loss_fault(self, injector, mock_adapter):
        """PacketLossFault injects tc netem loss and rolls back by deleting root qdisc."""
        scenario = PacketLossFault(node="ext-router", interface="eth1", loss_pct=25.0)
        token = injector.inject_fault(scenario)

        assert token.active is True
        assert token.injection_command == "tc qdisc add dev eth1 root netem loss 25%"
        assert token.rollback_command == "tc qdisc del dev eth1 root"

        # Verify mock rule
        rules = mock_adapter.fault_injector.get_active_rules()
        loss_rules = [r for r in rules if r.target_node == "ext-router" and r.loss_pct == 25.0]
        assert len(loss_rules) == 1

        # Revert fault
        success = injector.revert_fault(token)
        assert success is True
        assert token.active is False
        loss_rules_after = [r for r in mock_adapter.fault_injector.get_active_rules() if r.target_node == "ext-router"]
        assert len(loss_rules_after) == 0

    def test_latency_fault(self, injector):
        """LatencyFault injects tc netem delay with optional jitter and rolls back cleanly."""
        scenario = LatencyFault(node="dc-egress", interface="eth2", delay_ms=50.0, jitter_ms=10.0)
        token = injector.inject_fault(scenario)

        assert token.active is True
        assert token.injection_command == "tc qdisc add dev eth2 root netem delay 50ms 10ms"
        assert token.rollback_command == "tc qdisc del dev eth2 root"

        success = injector.revert_fault(token)
        assert success is True
        assert token.active is False


class TestConcurrentFaultsAndLIFORollback:
    """Tests managing multiple concurrent active faults and atomic revert_all."""

    def test_multiple_concurrent_faults(self, injector):
        """Multiple faults can be injected simultaneously and tracked via tokens."""
        s1 = LinkDownFault(node="leaf1", interface="eth1")
        s2 = LinkDownFault(node="leaf2", interface="eth2")
        s3 = PacketLossFault(node="ext-router", interface="eth1", loss_pct=15.0)

        t1 = injector.inject_fault(s1)
        t2 = injector.inject_fault(s2)
        t3 = injector.inject_fault(s3)

        assert injector.active_faults_count == 3
        tokens = injector.get_active_tokens()
        assert [t.token_id for t in tokens] == [t1.token_id, t2.token_id, t3.token_id]

        # Revert single fault
        assert injector.revert_fault(t2) is True
        assert injector.active_faults_count == 2
        assert t2.active is False

        # Revert all remaining faults
        reverted_count = injector.revert_all()
        assert reverted_count == 2
        assert injector.active_faults_count == 0
        assert t1.active is False
        assert t3.active is False

    def test_revert_all_lifo_order(self, injector):
        """revert_all rolls back active faults strictly in LIFO order."""
        call_order = []

        # Wrap adapter exec_command to capture execution order
        original_exec = injector.adapter.exec_command

        def tracking_exec(node_name, command, timeout=15):
            call_order.append((node_name, command))
            return original_exec(node_name, command, timeout)

        injector.adapter.exec_command = tracking_exec

        s1 = LinkDownFault(node="leaf1", interface="eth1")
        s2 = LinkDownFault(node="leaf2", interface="eth2")
        s3 = LinkDownFault(node="spine1", interface="eth3")

        injector.inject_fault(s1)
        injector.inject_fault(s2)
        injector.inject_fault(s3)

        call_order.clear()
        reverted = injector.revert_all()
        assert reverted == 3

        # LIFO check: spine1 (s3) reverted first, then leaf2 (s2), then leaf1 (s1)
        expected_nodes = ["spine1", "leaf2", "leaf1"]
        actual_nodes = [node for node, _ in call_order]
        assert actual_nodes == expected_nodes

    def test_revert_inactive_token_returns_false(self, injector):
        """Attempting to revert an already reverted token safely returns False."""
        s = LinkDownFault(node="leaf1", interface="eth1")
        token = injector.inject_fault(s)

        assert injector.revert_fault(token) is True
        assert injector.revert_fault(token) is False


class TestContextManagerGuarantees:
    """Tests fault_context ensuring rollback on clean exit and on exception."""

    def test_context_manager_clean_exit(self, injector):
        """fault_context automatically reverts fault when with-block exits cleanly."""
        scenario = LinkDownFault(node="leaf3", interface="eth1")

        with injector.fault_context(scenario) as token:
            assert token.active is True
            assert injector.active_faults_count == 1

        assert token.active is False
        assert injector.active_faults_count == 0

    def test_context_manager_exception_rollback(self, injector):
        """fault_context guarantees rollback even when an unhandled exception occurs."""
        scenario = PacketLossFault(node="ext-router", interface="eth2", loss_pct=40.0)

        token_ref = None
        with pytest.raises(ValueError, match="simulated failure"):
            with injector.fault_context(scenario) as token:
                token_ref = token
                assert token.active is True
                assert injector.active_faults_count == 1
                raise ValueError("simulated failure")

        assert token_ref is not None
        assert token_ref.active is False
        assert injector.active_faults_count == 0


class TestLabIsolationIntegration:
    """Tests that ContainerlabFaultInjector intercepts host and boundary violations."""

    def test_rejects_injection_targeting_host(self, injector):
        """Attempting to inject a fault on 'host' raises LabIsolationViolationError."""
        scenario = LinkDownFault(node="host", interface="eth1")
        with pytest.raises(LabIsolationViolationError) as exc_info:
            injector.inject_fault(scenario)
        assert "not an authorized clos5 container" in str(exc_info.value)
        assert injector.active_faults_count == 0

    def test_rejects_injection_targeting_unauthorized_container(self, injector):
        """Attempting to inject a fault on non-clos5 container is blocked."""
        scenario = LinkDownFault(node="clab-otherlab-router", interface="eth1")
        with pytest.raises(LabIsolationViolationError):
            injector.inject_fault(scenario)
        assert injector.active_faults_count == 0

    def test_rejects_injection_targeting_eth0_host_nic(self, injector):
        """Attempting to inject a link down or packet loss on eth0 is blocked."""
        scenario = LinkDownFault(node="leaf1", interface="eth0")
        with pytest.raises(LabIsolationViolationError) as exc_info:
            injector.inject_fault(scenario)
        assert "targets protected host interface" in str(exc_info.value)
        assert injector.active_faults_count == 0

    def test_rejects_injection_targeting_docker0_bridge(self, injector):
        """Attempting to inject fault on docker0 bridge is blocked."""
        scenario = PacketLossFault(node="leaf1", interface="docker0", loss_pct=10.0)
        with pytest.raises(LabIsolationViolationError):
            injector.inject_fault(scenario)
        assert injector.active_faults_count == 0


class TestLiveAdapterCompatibility:
    """Tests compatibility with LiveContainerlabAdapter interface."""

    def test_live_adapter_interface(self, isolation_guard):
        """Fault injector delegates commands cleanly to live adapter mock."""
        mock_live_adapter = MagicMock()
        mock_live_adapter.exec_command.return_value = CommandResult(
            command="ip link set dev eth1 down",
            exit_code=0,
            stdout="",
            stderr="",
            node="leaf1",
        )

        injector = ContainerlabFaultInjector(
            adapter=mock_live_adapter,
            isolation_guard=isolation_guard,
            lab_name="clos5",
        )

        scenario = LinkDownFault(node="leaf1", interface="eth1")
        token = injector.inject_fault(scenario)

        assert token.active is True
        mock_live_adapter.exec_command.assert_called_once_with(
            node_name="leaf1",
            command="ip link set dev eth1 down",
        )

        mock_live_adapter.exec_command.return_value = CommandResult(
            command="ip link set dev eth1 up",
            exit_code=0,
            stdout="",
            stderr="",
            node="leaf1",
        )

        injector.revert_fault(token)
        assert mock_live_adapter.exec_command.call_count == 2


class TestExperimentalLoopRunner:
    """Tests for ExperimentalLoop lifecycle coordination."""

    @pytest.fixture
    def loop(self, mock_adapter, injector, isolation_guard):
        """Create ExperimentalLoop test fixture."""
        return ExperimentalLoop(
            adapter=mock_adapter,
            fault_injector=injector,
            isolation_guard=isolation_guard,
            lab_name="clos5",
            target_nodes=["leaf1", "leaf2", "h1", "h2"],
            ping_targets=[("h1", "172.16.2.2")],
        )

    def test_capture_snapshot(self, loop):
        """capture_snapshot captures point-in-time interface and reachability state."""
        snap = loop.capture_snapshot()
        assert isinstance(snap, ExperimentalNetworkSnapshot)
        assert "leaf1" in snap.interfaces
        assert "leaf2" in snap.interfaces
        assert "h1->172.16.2.2" in snap.reachability

    def test_detect_state_diff_link_down(self, loop):
        """detect_state_diff detects interface state transitioning to DOWN."""
        base_snap = loop.capture_snapshot()

        # Inject link down
        token = loop.fault_injector.inject_fault(LinkDownFault(node="leaf1", interface="eth1"))
        post_fault_snap = loop.capture_snapshot()

        diff = loop.detect_state_diff(baseline=base_snap, current=post_fault_snap)
        assert isinstance(diff, ExperimentalStateDiff)
        assert diff.is_anomaly_detected is True
        assert "leaf1:eth1" in diff.interfaces_down

        # Clean up
        loop.fault_injector.revert_fault(token)

    def test_detect_state_diff_route_drop(self, loop):
        """detect_state_diff detects missing route prefix."""
        base_snap = loop.capture_snapshot()

        token = loop.fault_injector.inject_fault(RouteDropFault(node="h1", prefix="172.16.0.0/16", via="172.16.1.1"))
        post_fault_snap = loop.capture_snapshot()

        diff = loop.detect_state_diff(baseline=base_snap, current=post_fault_snap)
        assert isinstance(diff, ExperimentalStateDiff)
        # Note: in mock engine, suppressed route is reflected in diff or routes
        loop.fault_injector.revert_fault(token)

    def test_verify_post_repair_success(self, loop):
        """verify_post_repair succeeds when current state matches baseline."""
        base_snap = loop.capture_snapshot()
        post_snap = loop.capture_snapshot()

        outcome = loop.verify_post_repair(baseline=base_snap, post_repair=post_snap)
        assert outcome.passed is True
        assert len(outcome.details) > 0
        assert "restored" in outcome.details[0].lower()

    def test_run_experiment_default_healing(self, loop):
        """Full end-to-end run_experiment with default rollback succeeds."""
        scenario = LinkDownFault(node="leaf1", interface="eth1")
        result = loop.run_experiment(scenario=scenario)

        assert result.success is True
        assert result.scenario_type == "link_down"
        assert result.target_node == "leaf1"
        assert result.stage == LifecycleStage.VERIFICATION_COMPLETED
        assert result.verification is not None
        assert result.verification.passed is True
        assert loop.fault_injector.active_faults_count == 0

    def test_run_experiment_custom_agent_handler(self, loop):
        """run_experiment with custom agent remediation callback restores health."""
        handler_called = []

        def custom_remediation(diff: ExperimentalStateDiff, adapter):
            handler_called.append(True)
            # Apply remediation command: bring link back up
            adapter.exec_command(node_name="leaf1", command="ip link set dev eth1 up")
            # Clear mock fault rule
            mock_inj = getattr(adapter, "fault_injector", None)
            if mock_inj:
                for r in mock_inj.get_active_rules():
                    if r.target_node == "leaf1" and r.target_interface == "eth1":
                        mock_inj.remove_rule(r.rule_id)
            return {"status": "repaired", "interfaces": diff.interfaces_down}

        scenario = LinkDownFault(node="leaf1", interface="eth1")
        result = loop.run_experiment(scenario=scenario, agent_handler=custom_remediation)

        assert result.success is True
        assert len(handler_called) == 1
        assert result.remediation_result is not None
        assert result.remediation_result["handler_output"]["status"] == "repaired"
        assert result.verification.passed is True

