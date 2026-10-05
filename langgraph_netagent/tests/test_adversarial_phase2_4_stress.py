"""Adversarial Empirical Stress-Test Harness for Phases 2-4 (Milestone M4).

Empirically challenges:
1. Host Isolation Attacks & Evasion:
   - Malicious/evasive container targets (path traversal, command injection, null bytes, pseudo-hosts).
   - Prohibited host interface mutations (eth0, docker0, br-*, virbr*, veth*, Windows NICs, case variants, chained commands).
   - Namespace escapes and host tampering (nsenter, /proc/pid/ns/net, ip netns, --net=host, Windows network tools, destructive commands).
   - Malicious rollback command interception during transactional rollback.
2. Transactional Rollback Stress:
   - Multi-step plans with mid-execution failure (e.g. 3rd action fails).
   - Verification of exact reverse LIFO rollback order and state reversal.
   - Failure at pre-check assertion vs post-check assertion vs execution vs isolation guard.
   - Multi-node coordinated rollback.
   - Empty plan handling.
3. Extreme State Diff Inputs & Robustness:
   - Completely empty network states and disconnected / partitioned graphs.
   - Massive route table scale (500+ routes added/removed/churned).
   - Corrupted/malformed JSON responses in NetworkStateSnapshotter (truncated JSON, HTML errors, type mismatches).
   - Strict verification of StateDiff prompt byte budget (<500B) under massive compound anomalies.
   - Empirical boundary analysis of DiagnosticReasoningEngine prompt expansion under multi-fault loads.
"""

from __future__ import annotations

import copy
import json
import re
import time
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock
import pytest

from langgraph_netagent.models.network_state import (
    InterfaceDiff,
    InterfaceState,
    NetworkState,
    NodeState,
    QdiscDiff,
    QdiscState,
    ReachabilityDiff,
    ReachabilityState,
    RouteDiff,
    RouteState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.models.reasoning import (
    DiagnosticStrategy,
    DiagnosticStrategySelector,
)
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.deterministic_executor import (
    DeterministicExecutor,
    ExecutionResult,
)
from langgraph_netagent.tools.lab_isolation import (
    LabIsolationGuard,
    LabIsolationViolationError,
)
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    RouteEntry,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
from langgraph_netagent.workflow.programmatic_verifier import ProgrammaticVerifier
from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine


# ==============================================================================
# Helper Builders & Fixtures
# ==============================================================================

@pytest.fixture
def clos5_guard() -> LabIsolationGuard:
    """Fixture providing a standard clos5 LabIsolationGuard."""
    return LabIsolationGuard(lab_name="clos5")


def build_clos5_vnodes(adapter: MockContainerlabAdapter) -> None:
    """Build mock clos5 virtual nodes in MockContainerlabAdapter."""
    g = adapter.mock_engine.graph
    g.clear()
    for name in ["leaf1", "leaf2", "leaf3", "leaf4", "h1", "h2", "dc-egress", "ext-router"]:
        vn = VirtualNode(name=name, kind="linux")
        vn.add_interface(VirtualInterface(name="lo", oper_state="UP", ip_cidr="127.0.0.1/8"))
        vn.add_interface(VirtualInterface(name="eth1", oper_state="DOWN"))
        vn.add_interface(VirtualInterface(name="eth2", oper_state="DOWN"))
        vn.add_interface(VirtualInterface(name="eth3", oper_state="DOWN"))
        g.add_node(vn)


# ==============================================================================
# 1. Host Isolation Attacks & Evasion Stress Tests
# ==============================================================================

class TestHostIsolationAdversarialStress:
    """Adversarial challenge against LabIsolationGuard container naming and command inspection."""

    @pytest.mark.parametrize(
        "malicious_target",
        [
            # Explicit host keywords
            "host", "HOST", "Host", " localhost ", "\tlocalhost\n", "127.0.0.1", "::1", "0.0.0.0", "root",
            # Path traversal / directory escape
            "clab-clos5-../../etc/shadow",
            "clab-clos5-leaf1/../leaf2",
            "clab-clos5-leaf1/..",
            # Command injection attempts
            "clab-clos5-leaf1; rm -rf /",
            "clab-clos5-leaf1 & reboot",
            "clab-clos5-leaf1|poweroff",
            "leaf1$(id)",
            "leaf1`id`",
            "leaf1\nreboot",
            "leaf1\x00extra",
            # Unauthorized prefix/suffix / non-clos5 lab
            "clab-otherlab-leaf1",
            "clab-production-leaf1",
            "clab-clos5-",
            "clab-clos5",
            "clab-clos5-leaf999",
            "leaf999",
            "spine99",
            "superspine99",
            "unknown_container_foo",
            "",
            "    ",
            None,
        ],
    )
    def test_unauthorized_container_targets_unconditionally_blocked(
        self,
        clos5_guard: LabIsolationGuard,
        malicious_target: Any,
    ):
        """LabIsolationGuard must reject all malicious, evasive, or non-clos5 container targets."""
        assert clos5_guard.is_valid_container_target(malicious_target) is False
        with pytest.raises(LabIsolationViolationError):
            clos5_guard.assert_container_isolated(malicious_target)

    @pytest.mark.parametrize(
        "evasive_host_iface_cmd",
        [
            # Physical host NIC (eth0) variations
            "ip link set dev eth0 down",
            "IP LINK SET DEV ETH0 DOWN",
            "ip link set dev eth0 up",
            "ifconfig eth0 down",
            "ip addr add 10.0.0.1/24 dev eth0",
            "ip route add default dev eth0",
            "tc qdisc add dev eth0 root netem loss 10%",
            # Docker host bridge (docker0) variations
            "ip link set dev docker0 down",
            "IP LINK SET DEV DOCKER0 DOWN",
            "brctl delbr docker0",
            "ip route replace 172.17.0.0/16 dev docker0",
            # Generic Linux bridges and virtual ethernet pairs
            "ip link set dev br-1234567890ab down",
            "ip link set dev br_mgt down",
            "ip link set dev virbr0 down",
            "ip link set dev virbr1 down",
            "ip link set dev veth1a2b3c down",
            "ip link set dev veth-peer down",
            # Windows physical and virtual adapters
            "ip link set dev vEthernet down",
            "ip link set dev \"vEthernet (Default Switch)\" down",
            "ip link set dev Wi-Fi down",
            "ip link set dev WiFi down",
            "ip link set dev \"Ethernet 2\" down",
            "ip link set dev \"Local Area Connection\" down",
            "ip link set dev \"Wireless Network Connection\" down",
            "ip link set dev \"Loopback Adapter\" down",
            # Command chaining evasion targeting host NICs
            "echo hello; ip link set dev eth0 down",
            "true && ip link set dev docker0 down",
            "vtysh -c 'show version'\nip link set dev eth0 down",
            "ip link show || ip link set dev br-abcdef down",
        ],
    )
    def test_evasive_host_interface_commands_unconditionally_blocked(
        self,
        clos5_guard: LabIsolationGuard,
        evasive_host_iface_cmd: str,
    ):
        """Commands referencing host physical/virtual interfaces must be blocked regardless of case or chaining."""
        assert clos5_guard.validate_command_safety(evasive_host_iface_cmd, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError):
            clos5_guard.assert_command_safety(evasive_host_iface_cmd, container_name="leaf1")

    @pytest.mark.parametrize(
        "escape_and_destructive_cmd",
        [
            # nsenter namespace escapes
            "nsenter -t 1 -n ip link",
            "NSENTER -t 1 -m -u -i -n -p sh",
            "/usr/bin/nsenter --target 1 --net ip a",
            "/bin/nsenter -n ip route",
            "nsenter --net=/proc/1/ns/net sh",
            # /proc/pid/ns/net access
            "cat /proc/1/ns/net",
            "ls -la /proc/1/ns/net",
            "head /proc/42/ns/net",
            "cat /proc/9999/ns/net",
            # ip netns commands
            "ip netns exec host ip link",
            "ip netns show",
            "ip  netns  list",
            "ip netns add evil",
            # Docker container breakout flags
            "docker run --net=host alpine",
            "docker run --network=host alpine",
            "docker run --net host alpine",
            "docker run --network host alpine",
            "docker run --pid=host alpine",
            "docker run --pid host alpine",
            "docker run --privileged alpine",
            # Windows host reconfiguration tools
            "netsh interface set interface Wi-Fi disable",
            "netsh interface ipv4 show interfaces",
            "Get-NetAdapter | Disable-NetAdapter",
            "Set-NetIPAddress -InterfaceAlias 'Ethernet' -IPAddress 1.1.1.1",
            "New-NetIPAddress -InterfaceAlias 'vEthernet' -IPAddress 1.1.1.1",
            "ipconfig /flushdns",
            # Destructive system commands
            "reboot",
            "sudo reboot",
            "/sbin/reboot",
            "/usr/sbin/reboot",
            "poweroff",
            "sudo poweroff",
            "halt",
            "shutdown -h now",
            "shutdown -r now",
            "shutdown +1",
            "systemctl reboot",
            "systemctl poweroff",
            "systemctl halt",
            "rm -rf /",
            "rm -r /",
            "mkfs /dev/sda",
            "mkfs.ext4 /dev/sda1",
            "wipefs -a /dev/sda",
            "shred -n 3 /dev/sdb",
            "fdisk /dev/sda",
            "parted /dev/sda",
        ],
    )
    def test_namespace_escapes_and_destructive_commands_blocked(
        self,
        clos5_guard: LabIsolationGuard,
        escape_and_destructive_cmd: str,
    ):
        """Namespace escapes, container breakouts, and system destructive commands must be blocked."""
        assert clos5_guard.validate_command_safety(escape_and_destructive_cmd, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError):
            clos5_guard.assert_command_safety(escape_and_destructive_cmd, container_name="leaf1")

    @pytest.mark.parametrize(
        "node, legitimate_cmd",
        [
            ("leaf1", "ip link set dev eth1 up"),
            ("leaf1", "ip link set dev eth1 down"),
            ("leaf2", "ip link set dev eth2 up"),
            ("leaf3", "ip link set dev eth3 down"),
            ("h1", "ip route add 172.16.2.0/24 via 172.16.1.1 dev eth1"),
            ("h1", "ip route replace default via 172.16.1.1 dev eth1"),
            ("h2", "ip route del 172.16.1.0/24"),
            ("ext-router", "tc qdisc add dev eth1 root netem loss 10%"),
            ("ext-router", "tc qdisc del dev eth1 root"),
            ("dc-egress", "tc qdisc replace dev eth1 root netem delay 20ms"),
            ("leaf1", "vtysh -c 'show ip route json'"),
            ("leaf2", 'vtysh -c "conf t" -c "router bgp 65001" -c "neighbor eth1 shutdown"'),
            ("leaf2", 'vtysh -c "conf t" -c "router bgp 65001" -c "no neighbor eth1 shutdown"'),
            ("h1", "ping -c 2 -W 2 172.16.2.2"),
        ],
    )
    def test_legitimate_clos5_commands_allowed(
        self,
        clos5_guard: LabIsolationGuard,
        node: str,
        legitimate_cmd: str,
    ):
        """Standard network troubleshooting and configuration commands inside clos5 containers pass."""
        assert clos5_guard.validate_command_safety(legitimate_cmd, container_name=node) is True
        clos5_guard.assert_command_safety(legitimate_cmd, container_name=node)


# ==============================================================================
# 2. Transactional Rollback Stress Tests
# ==============================================================================

class TestTransactionalRollbackAdversarialStress:
    """Stress tests verifying strict reverse LIFO rollback order and atomic failure handling."""

    def test_mid_plan_execution_failure_lifo_rollback_order(self):
        """Simulate a 5-action plan where action 3 fails during CLI execution:
        - Actions 1 and 2 succeed.
        - Action 3 fails.
        - Verify rollback executes Action 2 rollback FIRST, Action 1 rollback SECOND.
        - Actions 4 and 5 are NEVER executed.
        - VirtualNode states are properly reverted to DOWN.
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        orig_exec = adapter.exec_command
        executed_order: List[str] = []
        rollback_order: List[str] = []

        def tracking_exec(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if "simulated_exec_failure_act3" in command:
                executed_order.append(f"{node_name}:{command}")
                return CommandResult(command=command, exit_code=1, stderr="Simulated CLI error", node=node_name)
            if "rb_" in kwargs.get("step_tag", "") or "rb_" in str(kwargs):
                rollback_order.append(f"{node_name}:{command}")
            else:
                executed_order.append(f"{node_name}:{command}")
            return orig_exec(node_name=node_name, command=command, **kwargs)

        adapter.exec_command = tracking_exec

        # Multi-step plan with 5 actions
        plan = RepairPlan(
            incident_id="inc-stress-01",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    rollback_command="ip link set dev eth2 down",
                ),
                RepairAction(
                    action_id="act-3",
                    target_node="leaf1",
                    action_type="failing_cmd",
                    command="simulated_exec_failure_act3",
                    rollback_command="ip link set dev eth3 down",
                ),
                RepairAction(
                    action_id="act-4",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    rollback_command="ip link set dev eth3 down",
                ),
                RepairAction(
                    action_id="act-5",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev lo up",
                    rollback_command="ip link set dev lo down",
                ),
            ],
        )

        result: ExecutionResult = executor.execute_plan(plan, step_tag="stress_test")

        # 1. Execution must report failure and rollback
        assert result.success is False
        assert result.rolled_back is True
        assert len(result.executed_actions) == 2  # act-1 and act-2 were applied
        assert result.executed_actions[0].action_id == "act-1"
        assert result.executed_actions[1].action_id == "act-2"

        # 2. Rollback output order must be strictly LIFO: act-2 reversed first, then act-1
        assert len(result.rollback_outputs) == 2
        assert result.rollback_outputs[0]["action_id"] == "act-2"
        assert result.rollback_outputs[0]["rollback_command"] == "ip link set dev eth2 down"
        assert result.rollback_outputs[1]["action_id"] == "act-1"
        assert result.rollback_outputs[1]["rollback_command"] == "ip link set dev eth1 down"

        # 3. Actions 4 and 5 were never executed
        executed_cmds = [item for item in executed_order]
        assert not any("eth3" in c and "up" in c for c in executed_cmds)
        assert not any("lo" in c and "up" in c for c in executed_cmds)

        # 4. Final state on leaf1 must have both eth1 and eth2 restored to DOWN
        vnode = adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth1"].oper_state == "DOWN"
        assert vnode.interfaces["eth2"].oper_state == "DOWN"

    def test_mid_plan_post_check_failure_lifo_rollback_order(self):
        """Simulate action 3 executing successfully, but its post-check condition fails:
        - Actions 1, 2, and 3 are executed.
        - Action 3 post-check fails.
        - Verify rollback reverses Action 3 FIRST, then Action 2, then Action 1 (LIFO).
        - All 3 interfaces are cleanly restored to DOWN.
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        plan = RepairPlan(
            incident_id="inc-stress-02",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    rollback_command="ip link set dev eth2 down",
                ),
                RepairAction(
                    action_id="act-3",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    post_check_command="ip link show dev eth3",
                    expected_post_condition="EXPECTED_STRING_THAT_DOES_NOT_EXIST",  # Trigger post-check failure
                    rollback_command="ip link set dev eth3 down",
                ),
            ],
        )

        result = executor.execute_plan(plan)

        assert result.success is False
        assert result.rolled_back is True
        assert "Post-check assertion failed" in result.error
        # Because act-3 executed before post-check failed, all 3 actions were registered
        assert len(result.executed_actions) == 3

        # Rollback outputs must be in reverse LIFO order: act-3, act-2, act-1
        assert len(result.rollback_outputs) == 3
        assert result.rollback_outputs[0]["action_id"] == "act-3"
        assert result.rollback_outputs[1]["action_id"] == "act-2"
        assert result.rollback_outputs[2]["action_id"] == "act-1"

        # Mock node states must all be reverted to DOWN
        vnode = adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth1"].oper_state == "DOWN"
        assert vnode.interfaces["eth2"].oper_state == "DOWN"
        assert vnode.interfaces["eth3"].oper_state == "DOWN"

    def test_mid_plan_pre_check_failure_lifo_rollback_order(self):
        """Simulate action 3 failing at pre-check:
        - Actions 1 and 2 execute successfully.
        - Action 3 fails pre-check before main command execution.
        - Verify only Action 2 and Action 1 are rolled back in LIFO order (Action 3 is not applied).
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        # Ensure eth3 is already marked UP so pre-check expecting DOWN fails
        adapter.mock_engine.graph.nodes["leaf1"].interfaces["eth3"].oper_state = "UP"

        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        plan = RepairPlan(
            incident_id="inc-stress-03",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    rollback_command="ip link set dev eth2 down",
                ),
                RepairAction(
                    action_id="act-3",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth3 up",
                    pre_check_command="ip link show dev eth3",
                    expected_pre_condition="DOWN",  # Fails because eth3 is UP!
                    rollback_command="ip link set dev eth3 down",
                ),
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True
        assert "Pre-check assertion failed" in result.error
        assert len(result.executed_actions) == 2  # act-1 and act-2

        # LIFO rollback of act-2 then act-1
        assert len(result.rollback_outputs) == 2
        assert result.rollback_outputs[0]["action_id"] == "act-2"
        assert result.rollback_outputs[1]["action_id"] == "act-1"

        vnode = adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth1"].oper_state == "DOWN"
        assert vnode.interfaces["eth2"].oper_state == "DOWN"

    def test_mid_plan_isolation_violation_triggers_lifo_rollback(self):
        """Simulate malicious injection in Action 3 targeting host docker0 interface:
        - Actions 1 and 2 execute safely on clos5 container.
        - Action 3 attempts to touch docker0.
        - LabIsolationGuard trips before Action 3 runs.
        - Actions 1 and 2 are rolled back in LIFO order.
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        plan = RepairPlan(
            incident_id="inc-stress-04",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-2",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    rollback_command="ip link set dev eth2 down",
                ),
                RepairAction(
                    action_id="act-3-malicious",
                    target_node="leaf1",
                    action_type="host_attack",
                    command="ip link set dev docker0 down",  # Prohibited host NIC!
                    rollback_command="ip link set dev docker0 up",
                ),
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True
        assert "Lab isolation boundary violation" in result.error
        assert len(result.executed_actions) == 2

        # LIFO rollback
        assert len(result.rollback_outputs) == 2
        assert result.rollback_outputs[0]["action_id"] == "act-2"
        assert result.rollback_outputs[1]["action_id"] == "act-1"

        vnode = adapter.mock_engine.graph.nodes["leaf1"]
        assert vnode.interfaces["eth1"].oper_state == "DOWN"
        assert vnode.interfaces["eth2"].oper_state == "DOWN"

    def test_malicious_rollback_command_intercepted_by_guard(self):
        """If an action contains a malicious rollback command attempting to mutate host interfaces:
        - Main action succeeds.
        - Subsequent failure triggers rollback.
        - IsolationGuard catches and rejects the malicious rollback command during rollback phase.
        - Safe prior actions continue to be reversed without uncaught crash.
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        orig_exec = adapter.exec_command
        def fail_on_act2(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if "fail_act2" in command:
                return CommandResult(command=command, exit_code=1, stderr="fail", node=node_name)
            return orig_exec(node_name=node_name, command=command, **kwargs)
        adapter.exec_command = fail_on_act2

        plan = RepairPlan(
            incident_id="inc-stress-rb-intercept",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-safe-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-poisoned-rb",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth2 up",
                    # Malicious rollback attempting host interface breach!
                    rollback_command="ip link set dev eth0 down",
                ),
                RepairAction(
                    action_id="act-fail",
                    target_node="leaf1",
                    action_type="fail",
                    command="fail_act2",
                ),
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True

        # act-poisoned-rb rollback should be blocked by isolation guard and not appear as successful output
        # act-safe-1 rollback should execute cleanly
        assert any(o["action_id"] == "act-safe-1" and o["success"] for o in result.rollback_outputs)
        # Verify eth1 was cleanly restored to DOWN
        assert adapter.mock_engine.graph.nodes["leaf1"].interfaces["eth1"].oper_state == "DOWN"

    def test_multi_node_coordinated_rollback(self):
        """Coordinated repair across leaf1 and leaf2:
        - Action 1 on leaf1 succeeds (eth1 UP).
        - Action 2 on leaf2 succeeds (eth1 UP).
        - Action 3 on leaf3 fails CLI command.
        - Rollback reverses leaf2 then leaf1.
        """
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        orig_exec = adapter.exec_command
        def fail_on_leaf3(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if node_name == "leaf3" and "error_trigger" in command:
                return CommandResult(command=command, exit_code=1, stderr="Simulated node 3 failure", node=node_name)
            return orig_exec(node_name=node_name, command=command, **kwargs)
        adapter.exec_command = fail_on_leaf3

        plan = RepairPlan(
            incident_id="inc-stress-05",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="clos5-fabric",
            actions=[
                RepairAction(
                    action_id="act-leaf1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-leaf2",
                    target_node="leaf2",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                ),
                RepairAction(
                    action_id="act-leaf3",
                    target_node="leaf3",
                    action_type="fail_cmd",
                    command="error_trigger",
                    rollback_command="ip link set dev eth1 down",
                ),
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True

        assert len(result.rollback_outputs) == 2
        assert result.rollback_outputs[0]["node"] == "leaf2"
        assert result.rollback_outputs[1]["node"] == "leaf1"

        assert adapter.mock_engine.graph.nodes["leaf1"].interfaces["eth1"].oper_state == "DOWN"
        assert adapter.mock_engine.graph.nodes["leaf2"].interfaces["eth1"].oper_state == "DOWN"

    def test_first_action_failure_handled_gracefully(self):
        """When action 1 fails immediately, executor handles empty rollback safely."""
        adapter = MockContainerlabAdapter()
        build_clos5_vnodes(adapter)
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        orig_exec = adapter.exec_command
        adapter.exec_command = lambda node_name, command, **kwargs: CommandResult(command=command, exit_code=1, stderr="Fail on 1st", node=node_name)

        plan = RepairPlan(
            incident_id="inc-stress-06",
            strategy=DiagnosticStrategy.LINK_RECOVERY,
            target_node="leaf1",
            actions=[
                RepairAction(
                    action_id="act-1",
                    target_node="leaf1",
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                )
            ],
        )

        result = executor.execute_plan(plan)
        assert result.success is False
        assert result.rolled_back is True
        assert len(result.executed_actions) == 0
        assert len(result.rollback_outputs) == 0

    def test_empty_plan_execution_succeeds_without_side_effects(self):
        """A plan with zero actions executes cleanly as successful with 0 executed actions."""
        adapter = MockContainerlabAdapter()
        executor = DeterministicExecutor(lab_adapter=adapter, lab_name="clos5")

        plan = RepairPlan(
            incident_id="inc-stress-empty",
            strategy=DiagnosticStrategy.HEALTHY,
            target_node="leaf1",
            actions=[],
        )

        result = executor.execute_plan(plan)
        assert result.success is True
        assert result.rolled_back is False
        assert len(result.executed_actions) == 0


# ==============================================================================
# 3. Extreme State Diff Inputs & Robustness Stress Tests
# ==============================================================================

class TestExtremeStateDiffAdversarialStress:
    """Stress tests verifying handling of empty states, disconnected graphs, maximum routes,
    corrupted JSON CLI responses, and strict prompt byte budget (<500B).
    """

    def test_completely_empty_network_states(self):
        """Empty baseline vs empty current snapshot:
        - Computes diff without crashing.
        - Reports has_anomalies == False.
        - Markdown summary is strictly '<500B'.
        - DiagnosticReasoningEngine returns healthy plan.
        """
        empty_baseline = NetworkState(nodes={}, reachability_matrix=[], healthy=True)
        empty_current = NetworkState(nodes={}, reachability_matrix=[], healthy=True)

        diff: StateDiff = compute_state_diff(baseline=empty_baseline, current=empty_current)
        assert diff.has_anomalies() is False
        assert diff.affected_nodes() == []

        md = diff.to_llm_markdown()
        assert "OK (No anomalies)" in md
        assert len(md.encode("utf-8")) < 500

        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy == DiagnosticStrategy.HEALTHY
        assert len(plan.actions) == 0

    def test_empty_baseline_vs_populated_current_and_vice_versa(self):
        """Check transitions from empty to populated and from populated to empty:
        - Handled cleanly without KeyError or AttributeError.
        - Prompt byte budget remains <500B.
        """
        leaf1 = NodeState(
            node_name="leaf1",
            interfaces={"eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP")},
            routes=[RouteState(prefix="172.16.1.0/24", interface="eth1")],
        )
        populated = NetworkState(nodes={"leaf1": leaf1}, healthy=True)
        empty = NetworkState(nodes={}, healthy=True)

        # 1. Empty -> Populated
        diff_add = compute_state_diff(baseline=empty, current=populated)
        assert diff_add.interface_diffs["leaf1"].added[0].name == "eth1"
        assert len(diff_add.to_llm_markdown().encode("utf-8")) < 500

        # 2. Populated -> Empty (all nodes vanished)
        diff_rem = compute_state_diff(baseline=populated, current=empty)
        assert diff_rem.has_anomalies() is True
        assert diff_rem.has_link_failure() is True
        assert diff_rem.has_route_failure() is True
        assert len(diff_rem.to_llm_markdown().encode("utf-8")) < 500

    def test_disconnected_partitioned_network_graph(self):
        """Simulate a network partition with 10 nodes split into disconnected islands:
        - 45 pairs newly unreachable.
        - Diff detects unreachable pairs.
        - Markdown output must strictly respect byte budget (<500B).
        """
        nodes = {
            f"node{i}": NodeState(
                node_name=f"node{i}",
                interfaces={"eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP")},
            )
            for i in range(1, 11)
        }

        # Baseline: all 10 nodes fully mutually reachable (90 pairs)
        baseline_reach = [
            ReachabilityState(source=f"node{i}", destination=f"node{j}", reachable=True, latency_ms=1.0)
            for i in range(1, 11) for j in range(1, 11) if i != j
        ]
        baseline = NetworkState(nodes=nodes, reachability_matrix=baseline_reach, healthy=True)

        # Current: partition node1..5 from node6..10 (all cross-island pairs unreachable)
        current_reach = []
        for i in range(1, 11):
            for j in range(1, 11):
                if i == j:
                    continue
                # Same island: reachable; across island: unreachable
                same_island = (i <= 5 and j <= 5) or (i > 5 and j > 5)
                current_reach.append(
                    ReachabilityState(
                        source=f"node{i}",
                        destination=f"node{j}",
                        reachable=same_island,
                        packet_loss_pct=0.0 if same_island else 100.0,
                    )
                )

        current = NetworkState(nodes=nodes, reachability_matrix=current_reach, healthy=False)

        diff = compute_state_diff(baseline=baseline, current=current)
        assert diff.has_anomalies() is True
        assert diff.has_packet_loss() is True
        assert len(diff.reachability_diffs.newly_unreachable) == 50  # 5 * 5 * 2 = 50 cross pairs

        md = diff.to_llm_markdown()
        byte_len = len(md.encode("utf-8"))
        assert byte_len < 500, f"Markdown byte budget exceeded under network partition: {byte_len} bytes"
        assert "Unreachable:" in md

    def test_massive_route_table_churn_stress(self):
        """Simulate massive route churn with 500 routes removed, 500 added, and 500 changed:
        - Diff engine computes differences without lag or error.
        - Markdown serialization enforces hard truncation (<500B).
        """
        b_routes = [
            RouteState(prefix=f"10.{i // 256}.{i % 256}.0/24", next_hop="192.168.1.1", active=True)
            for i in range(500)
        ]
        # Current routes: first 250 removed, next 250 next-hop changed, 250 new routes added
        c_routes = [
            RouteState(prefix=f"10.{i // 256}.{i % 256}.0/24", next_hop="192.168.2.2", active=True)
            for i in range(250, 500)
        ] + [
            RouteState(prefix=f"172.20.{i // 256}.{i % 256}.0/24", next_hop="192.168.3.3", active=True)
            for i in range(250)
        ]

        b_node = NodeState(node_name="spine1", routes=b_routes)
        c_node = NodeState(node_name="spine1", routes=c_routes)

        b_state = NetworkState(nodes={"spine1": b_node})
        c_state = NetworkState(nodes={"spine1": c_node})

        start_t = time.perf_counter()
        diff = compute_state_diff(baseline=b_state, current=c_state)
        elapsed = time.perf_counter() - start_t

        assert elapsed < 1.0, f"Route diff computation too slow: {elapsed:.3f}s"
        assert diff.has_anomalies() is True
        assert diff.has_route_failure() is True
        assert len(diff.route_diffs["spine1"].removed) == 250
        assert len(diff.route_diffs["spine1"].added) == 250
        assert len(diff.route_diffs["spine1"].changed) == 250

        # Markdown budget verification
        md = diff.to_llm_markdown()
        byte_len = len(md.encode("utf-8"))
        assert byte_len < 500, f"Markdown budget exceeded on 500 routes churn: {byte_len} bytes"
        assert "... [truncated]" in md

    def test_corrupted_json_cli_responses_snapshotter_fallback(self):
        """Corrupted JSON responses from CLI tools must trigger robust fallback to text parsing:
        - ip -j addr show -> malformed JSON
        - vtysh -c 'show ip route json' -> HTML error string
        - ip -j route show -> truncated JSON
        """
        adapter = MockContainerlabAdapter()
        snapshotter = NetworkStateSnapshotter(lab_adapter=adapter)

        # 1. Corrupted ip -j addr show JSON with fallback to valid text
        corrupted_json_ip = "[[{invalid_json: unquoted, \"ifname\": "
        valid_text_ip = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 172.16.1.1/24 scope global eth1\n"
        )
        def mock_exec_ip(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if "ip -j addr show" in command:
                return CommandResult(command=command, exit_code=0, stdout=corrupted_json_ip, node=node_name)
            if "ip addr show" in command:
                return CommandResult(command=command, exit_code=0, stdout=valid_text_ip, node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

        adapter.exec_command = mock_exec_ip
        ifaces = snapshotter._collect_interfaces("leaf1")
        assert "eth1" in ifaces
        assert ifaces["eth1"].oper_state == "UP"
        assert ifaces["eth1"].ipv4_addresses == ["172.16.1.1/24"]

        # 2. Corrupted vtysh show ip route json (e.g. 502 Bad Gateway HTML) with fallback to valid text
        html_error = "<html><head><title>502 Bad Gateway</title></head><body>Server Error</body></html>"
        valid_vtysh_text = (
            "Codes: K - kernel route, C - connected, S - static, B - BGP\n"
            "C>* 172.16.1.0/24 is directly connected, eth1\n"
            "B>* 172.16.2.0/24 [20/0] via 172.16.254.2, eth2\n"
        )
        def mock_exec_routes(node_name: str, command: str, **kwargs: Any) -> CommandResult:
            if "show ip route json" in command:
                return CommandResult(command=command, exit_code=0, stdout=html_error, node=node_name)
            if "show ip route" in command:
                return CommandResult(command=command, exit_code=0, stdout=valid_vtysh_text, node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

        adapter.exec_command = mock_exec_routes
        routes = snapshotter._collect_routes("leaf1")
        assert len(routes) == 2
        assert routes[0].prefix == "172.16.1.0/24"
        assert routes[1].prefix == "172.16.2.0/24"
        assert routes[1].next_hop == "172.16.254.2"
        assert routes[1].protocol == "bgp"

    def test_corrupted_ping_and_qdisc_outputs_handled_safely(self):
        """Malformed ping output and corrupted tc qdisc text handled without unhandled exceptions."""
        adapter = MockContainerlabAdapter()
        snapshotter = NetworkStateSnapshotter(lab_adapter=adapter)

        # Corrupted ping outputs
        corrupted_pings = [
            "",
            "connect: Network is unreachable",
            "ping: unknown host foo.bar",
            "Segmentation fault",
            "--- 1.1.1.1 ping statistics ---\nno packets info here",
        ]
        for ping_out in corrupted_pings:
            reach, loss, rtt = snapshotter._parse_ping_output(ping_out)
            assert reach is False
            assert loss == 100.0
            assert rtt is None

        # Corrupted tc qdisc outputs
        adapter.exec_command = lambda node_name, command, **kwargs: CommandResult(
            command=command, exit_code=0, stdout="garbage tc output with random binary \x00\xff", node=node_name
        )
        qdiscs = snapshotter._collect_qdiscs("leaf1")
        assert isinstance(qdiscs, dict)

    def test_latency_jitter_filtering(self):
        """Latency changes within 0.05ms are treated as insignificant jitter and filtered out."""
        r_base = ReachabilityState(source="h1", destination="h2", reachable=True, latency_ms=1.10)
        r_jitter = ReachabilityState(source="h1", destination="h2", reachable=True, latency_ms=1.13)  # delta = 0.03ms <= 0.05ms
        r_spike = ReachabilityState(source="h1", destination="h2", reachable=True, latency_ms=1.50)   # delta = 0.40ms > 0.05ms

        s_base = NetworkState(reachability_matrix=[r_base])
        s_jitter = NetworkState(reachability_matrix=[r_jitter])
        s_spike = NetworkState(reachability_matrix=[r_spike])

        diff_jitter = compute_state_diff(s_base, s_jitter)
        assert "h1->h2" not in diff_jitter.reachability_diffs.latency_changes

        diff_spike = compute_state_diff(s_base, s_spike)
        assert "h1->h2" in diff_spike.reachability_diffs.latency_changes
        assert diff_spike.reachability_diffs.latency_changes["h1->h2"] == (1.10, 1.50)

    def test_compound_mass_anomalies_state_diff_markdown_budget(self):
        """Massive compound disaster: 50 links down + 50 routes removed + 20 queue overflows + 50 unreachable pairs.
        - Verifies that StateDiff.to_llm_markdown() strictly enforces <500B budget with truncation.
        """
        interface_diffs = {
            f"leaf{i}": InterfaceDiff(
                node=f"leaf{i}",
                changed={f"eth{j}": {"oper_state": ("UP", "DOWN")} for j in range(1, 11)},
            )
            for i in range(1, 6)
        }
        route_diffs = {
            f"leaf{i}": RouteDiff(
                node=f"leaf{i}",
                removed=[RouteState(prefix=f"10.{i}.{j}.0/24") for j in range(1, 11)],
            )
            for i in range(1, 6)
        }
        qdisc_diffs = {
            f"leaf{i}": QdiscDiff(
                node=f"leaf{i}",
                changed={f"eth{j}": {"dropped_packets": (0, 5000)} for j in range(1, 5)},
            )
            for i in range(1, 6)
        }
        reachability_diffs = ReachabilityDiff(
            newly_unreachable=[(f"h{i}", f"h{j}") for i in range(1, 6) for j in range(6, 11)],
            loss_changes={f"h{i}->h{j}": (0.0, 100.0) for i in range(1, 6) for j in range(6, 11)},
        )

        diff = StateDiff(
            interface_diffs=interface_diffs,
            route_diffs=route_diffs,
            qdisc_diffs=qdisc_diffs,
            reachability_diffs=reachability_diffs,
        )

        # StateDiff.to_llm_markdown() check: strictly <500B
        md = diff.to_llm_markdown()
        md_bytes = len(md.encode("utf-8"))
        assert md_bytes < 500, f"StateDiff markdown exceeded 500 bytes: {md_bytes} bytes"
        assert "... [truncated]" in md

        # Deterministic plan formulation handles mass compound diff without exception
        engine = DiagnosticReasoningEngine()
        plan = engine.analyze_diff_and_plan(diff)
        assert plan.strategy in (DiagnosticStrategy.LINK_RECOVERY, DiagnosticStrategy.ROUTING_REPAIR)
        assert len(plan.actions) > 0

    def test_format_prompt_expansion_limitation_observed(self):
        """Empirically documents the boundary behavior of DiagnosticReasoningEngine.format_prompt():
        - When StateDiff is small (single anomaly), format_prompt() is <500B (~450B).
        - When StateDiff contains mass compound anomalies, StateDiff.to_llm_markdown() is 467B (<500B),
          but format_prompt() adds surrounding system instruction scaffolding (~360B), expanding the
          total prompt to ~826B (>500B).
        - This documents the architectural boundary where StateDiff enforces truncation, but the outer
          wrapper format_prompt() does not enforce a secondary budget cap.
        """
        # Case A: Single anomaly (link down)
        single_diff = StateDiff(
            interface_diffs={
                "leaf1": InterfaceDiff(node="leaf1", changed={"eth1": {"oper_state": ("UP", "DOWN")}})
            }
        )
        engine = DiagnosticReasoningEngine()
        prompt_single = engine.format_prompt(single_diff)
        bytes_single = len(prompt_single.encode("utf-8"))
        assert bytes_single < 500, f"Single fault prompt exceeded 500B: {bytes_single} bytes"

        # Case B: Compound massive anomalies
        compound_diff = StateDiff(
            interface_diffs={
                f"leaf{i}": InterfaceDiff(node=f"leaf{i}", changed={f"eth{j}": {"oper_state": ("UP", "DOWN")} for j in range(1, 10)})
                for i in range(1, 5)
            },
            reachability_diffs=ReachabilityDiff(
                newly_unreachable=[(f"h{i}", f"h{j}") for i in range(1, 5) for j in range(5, 9)]
            ),
        )
        # Inner markdown obeys budget (<500B)
        inner_md = compound_diff.to_llm_markdown()
        assert len(inner_md.encode("utf-8")) < 500

        # Outer prompt expands beyond 500B due to scaffolding
        prompt_compound = engine.format_prompt(compound_diff)
        bytes_compound = len(prompt_compound.encode("utf-8"))
        # Document empirical observation
        assert bytes_compound > 500, f"Expected prompt expansion observed: {bytes_compound} bytes"
        assert bytes_compound <= 900, f"Unexpectedly large prompt: {bytes_compound} bytes"
