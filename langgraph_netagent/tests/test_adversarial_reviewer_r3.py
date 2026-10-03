"""Comprehensive Round 3 Adversarial Audit & Edge-Case Verification Tests.

Validates:
1. Multi-vendor BGP and routing protocol syslog parsing in FiveTuple.from_syslog.
2. AAL security protections against script interpreter piping, system auth tampering, and read-only ifup/ifdown.
3. AAL structured CLI output normalization for IPv6 addresses and IPv6 routes.
4. Human-in-the-loop (HITL) approval gate robustness:
   - String/numeric truthy and falsy normalization ("yes", "approve", "reject", etc.).
   - Malformed input resilience.
   - Checkpoint-based pause with status="pending_approval" and clean resumption to "fixed".
   - Circuit breaker routing upon retry exhaustion at approval gate.
5. Configurable shadow sandbox clone_timeout and hermetic mock execution.
6. Full acceptance criteria audit across UML state machine sequence and circuit breaker.
"""

from pathlib import Path
from typing import Any, Dict, List
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    FiveTuple,
    InventoryPool,
    ShadowSandboxResult,
)
from langgraph_netagent.models.remediation import (
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.tools.aal import AgentAccessLayer, AALSecurityError
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.workflow.graph import create_memory_saver
from langgraph_netagent.workflow.operational_edges import (
    route_after_approval,
    route_after_re_verification,
    route_after_sandbox,
    route_after_stage2,
    route_after_telemetry,
)
from langgraph_netagent.workflow.operational_graph import (
    build_operational_graph,
    run_operational_workflow,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)
from tests.test_operational_workflow import MockOperationalLLMProvider, MockUMLAdapter


# ===========================================================================
# 1. Multi-Vendor Syslog & Routing Protocol Flap Parsing Tests
# ===========================================================================

class TestMultiVendorSyslogParsing:
    """Test FiveTuple.from_syslog on real-world multi-vendor log formats."""

    @pytest.mark.parametrize(
        "log_line, expected_proto, expected_type, expected_dst, expected_port",
        [
            ("BGP-5-ADJCHANGE: neighbor 10.1.1.2:179 Down", "TCP", "BGP_SESSION_DOWN", "10.1.1.2", 179),
            ("bgp neighbor 10.1.1.2 Down", "TCP", "BGP_SESSION_DOWN", "10.1.1.2", 179),
            ("%BGP-5-ADJCHANGE: neighbor 10.2.2.2 Down User reset", "TCP", "BGP_SESSION_DOWN", "10.2.2.2", 179),
            ("%BGP-5-PEER_STATE: session with peer 10.1.1.2:179 changed state to DOWN", "TCP", "BGP_SESSION_DOWN", "10.1.1.2", 179),
            ("%%01BGP/4/BGP_STATE_DETECT: The status of the BGP peer 10.1.1.2 changed from ESTABLISHED to IDLE.", "TCP", "BGP_SESSION_DOWN", "10.1.1.2", 179),
            ("RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 2001:db8::1 (Internal AS 65000) changed state from Established to Idle", "TCP", "BGP_SESSION_DOWN", "2001:db8::1", 179),
            ("RPD_BGP_NEIGHBOR_STATE_CHANGED: BGP peer 2001:db8::1:179 changed state from Established to Idle", "TCP", "BGP_SESSION_DOWN", "2001:db8::1", 179),
            ("%BGP-3-NOTIFICATION: sent to neighbor 10.1.1.2:179 4/0 (hold timer expired)", "TCP", "BGP_SESSION_DOWN", "10.1.1.2", 179),
            ("OSPF-5-ADJCHANGE: Process 1, Nbr 10.1.1.2 on eth1 from FULL to DOWN", "OSPF", "OSPF_NEIGHBOR_DOWN", "10.1.1.2", 0),
            ("ISIS-4-ADJCHANGE: Adjacency to 10.1.1.2 Down", "ISIS", "ISIS_ADJACENCY_DOWN", "10.1.1.2", 0),
            ("BGP multi-hop session flap between 10.1.1.1 and 10.2.2.2 down", "TCP", "BGP_SESSION_DOWN", "10.2.2.2", 179),
            ("bgp session 10.1.1.1 -> 10.2.2.2 down", "TCP", "BGP_SESSION_DOWN", "10.2.2.2", 179),
        ],
    )
    def test_vendor_syslog_matrix(
        self,
        log_line: str,
        expected_proto: str,
        expected_type: str,
        expected_dst: str,
        expected_port: int,
    ):
        result = FiveTuple.from_syslog(log_line)
        assert result is not None, f"Failed to parse log: {log_line}"
        assert result.protocol == expected_proto
        assert result.alert_type == expected_type
        assert result.destination_ip == expected_dst
        assert result.destination_port == expected_port


# ===========================================================================
# 2. AAL Security & Shell Interpreter Escapes
# ===========================================================================

class TestAALSecurityAndPolicy:
    """Test AAL security blocking of script interpreters and system file tampering."""

    @pytest.mark.parametrize(
        "dangerous_cmd",
        [
            "cat payload | python",
            "cat payload | python3",
            "echo 'import os; os.system(\"reboot\")' | /usr/bin/python",
            "cat exploit.pl | perl",
            "cat script.rb | ruby",
            "echo 'evil' > /etc/passwd",
            "echo 'evil' >> /etc/shadow",
            "cat payload > /etc/sudoers",
            "echo '' > /etc/group",
        ],
    )
    def test_aal_blocks_interpreters_and_auth_tampering(self, dangerous_cmd: str):
        aal = AgentAccessLayer(lab_adapter=MockContainerlabAdapter())
        is_safe, reason = aal.validate_command_safety(dangerous_cmd, read_only=False)
        assert is_safe is False
        assert "SECURITY POLICY VIOLATION" in reason

    @pytest.mark.parametrize(
        "mutating_cmd",
        [
            "ifdown eth1",
            "ifup eth1",
            "ifconfig eth1 10.1.1.5 up",
        ],
    )
    def test_aal_blocks_interface_mutations_in_read_only(self, mutating_cmd: str):
        aal = AgentAccessLayer(lab_adapter=MockContainerlabAdapter())
        is_safe, reason = aal.validate_command_safety(mutating_cmd, read_only=True)
        assert is_safe is False
        assert "READ-ONLY CONSTRAINT VIOLATION" in reason


# ===========================================================================
# 3. AAL Structured CLI Normalization (IPv6 Support)
# ===========================================================================

class TestAALStructuredOutputNormalization:
    """Verify structured JSON output normalization for IPv6 addresses and routing tables."""

    def test_normalize_ip_addr_show_dual_stack(self):
        stdout = (
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP\n"
            "    link/ether 00:16:3e:01:02:03 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.1.1.2/24 scope global eth1\n"
            "    inet6 2001:db8:1::2/64 scope global\n"
            "    inet6 fe80::216:3eff:fe01:203/64 scope link\n"
        )
        parsed = AgentAccessLayer.normalize_cli_output("ip addr show", stdout)
        assert parsed["type"] == "interface_inventory"
        assert parsed["count"] == 1
        iface = parsed["interfaces"][0]
        assert iface["name"] == "eth1"
        assert "10.1.1.2/24" in iface["ips"]
        assert "2001:db8:1::2/64" in iface["ips"]
        assert "fe80::216:3eff:fe01:203/64" in iface["ips"]

    def test_normalize_route_show_frr_ipv6(self):
        stdout = (
            "Codes: K - kernel route, C - connected, S - static\n"
            "S>* 2001:db8:2::/64 [1/0] via 2001:db8:12::2, eth2\n"
            "C>* 2001:db8:1::/64 is directly connected, eth1\n"
            "S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2\n"
        )
        parsed = AgentAccessLayer.normalize_cli_output("vtysh -c 'show ip route'", stdout)
        assert parsed["type"] == "route_inventory"
        assert parsed["count"] == 3
        dests = [r["destination"] for r in parsed["routes"]]
        assert "2001:db8:2::/64" in dests
        assert "2001:db8:1::/64" in dests
        assert "10.2.2.0/24" in dests

        v6_route = next(r for r in parsed["routes"] if r["destination"] == "2001:db8:2::/64")
        assert v6_route["next_hop"] == "2001:db8:12::2"
        assert v6_route["protocol"] == "static"

    def test_normalize_route_show_linux_ipv6(self):
        stdout = (
            "2001:db8:2::/64 via 2001:db8:12::2 dev eth2\n"
            "2001:db8:1::/64 dev eth1 proto kernel scope link\n"
            "default via 2001:db8:1::1 dev eth1\n"
        )
        parsed = AgentAccessLayer.normalize_cli_output("ip route show", stdout)
        assert parsed["count"] == 3
        dests = [r["destination"] for r in parsed["routes"]]
        assert "2001:db8:2::/64" in dests
        assert "2001:db8:1::/64" in dests
        assert "0.0.0.0/0" in dests


# ===========================================================================
# 4. Human Approval (HITL) Gate Stress Tests
# ===========================================================================

class TestHumanApprovalGateStress:
    """Stress test human approval normalization, rejections, checkpointer pause and resume."""

    @pytest.mark.parametrize(
        "truthy_approval",
        ["yes", "YES", "y", "true", "True", "TRUE", "approve", "APPROVED", 1, True],
    )
    def test_human_approval_truthy_variations(self, truthy_approval: Any):
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        graph = build_operational_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=False,
        )

        initial = create_operational_initial_state(auto_approve=False)
        initial["human_approved"] = truthy_approval

        final_state = graph.invoke(initial)
        assert final_state["status"] == "fixed"
        assert final_state["human_approved"] is True
        assert adapter.patched is True

    @pytest.mark.parametrize(
        "falsy_rejection",
        ["no", "NO", "n", "false", "False", "FALSE", "reject", "REJECTED", 0, False],
    )
    def test_human_approval_falsy_variations(self, falsy_rejection: Any):
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        graph = build_operational_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=False,
        )

        initial = create_operational_initial_state(auto_approve=False)
        initial["human_approved"] = falsy_rejection

        final_state = graph.invoke(initial)
        assert final_state["status"] == "rejected"
        assert final_state["human_approved"] is False
        assert adapter.patched is False

    @pytest.mark.parametrize(
        "malformed_val",
        [{"unexpected": "object"}, ["list"], 42, "maybe", "unknown"],
    )
    def test_human_approval_malformed_values_treated_safely(self, malformed_val: Any):
        """Malformed or unrecognized approval values should safely pause/reject rather than crash."""
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False)

        graph = build_operational_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=False,
        )

        initial = create_operational_initial_state(auto_approve=False)
        initial["human_approved"] = malformed_val

        final_state = graph.invoke(initial)
        # Should NOT mutate live network
        assert adapter.patched is False
        # When unapproved and unrecognized, ends at end_rejected with status pending or rejected
        assert final_state["status"] in ("pending_approval", "rejected")

    def test_checkpoint_pause_at_approval_and_resumption_to_fixed(self, checkpoint_state):
        """Verify state machine pauses at human_approval with status='pending_approval' and cleanly resumes."""
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)
        saver = create_memory_saver()

        graph = build_operational_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=False,
            checkpointer=saver,
        )
        config = {"configurable": {"thread_id": "thread-hitl-r3-audit"}}

        # Phase 1: Run with auto_approve=False and human_approved=None
        initial = create_operational_initial_state(auto_approve=False)
        paused_state = graph.invoke(initial, config=config)

        # Graph halted before touching live network
        assert paused_state["status"] == "pending_approval"
        assert paused_state["human_approved"] is None
        assert paused_state.get("sandbox_passed") is True
        assert adapter.patched is False

        # Verify state is persisted in checkpointer
        saved = checkpoint_state(saver.get(config))
        assert saved is not None
        assert saved["status"] == "pending_approval"
        assert saved.get("remediation_plan") is not None

        # Phase 2: Operator reviews plan in dashboard and grants approval
        resumed_state = dict(saved)
        resumed_state["human_approved"] = True

        completed_state = graph.invoke(resumed_state, config=config)

        # Graph resumes, applies live hot patch, re-verifies, and succeeds
        assert completed_state["status"] == "fixed"
        assert completed_state["human_approved"] is True
        assert adapter.patched is True
        assert completed_state["re_verify_results"]["all_passed"] is True

    def test_retry_exhaustion_at_human_approval_trips_circuit_breaker(self):
        """When retries are exhausted and approval is not granted, route_after_approval trips circuit breaker."""
        state = create_operational_initial_state(max_retries=2)
        state["retry_count"] = 2
        state["human_approved"] = None

        assert route_after_approval(state) == "circuit_breaker"


# ===========================================================================
# 5. Configurable Sandbox Timeout & Hermetic Mock Execution
# ===========================================================================

class TestConfigurableSandboxAndMockHermeticity:
    """Verify clone_timeout configurability and hermetic mock safety."""

    def test_sandbox_validation_clone_timeout_configurable(self):
        adapter = MockContainerlabAdapter()
        aal = AgentAccessLayer(lab_adapter=adapter)

        # Verify custom clone_timeout accepted cleanly in mock mode
        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="pc1",
            patch_commands=["ip route add 10.2.2.0/24 via 10.1.1.1"],
            adapter=adapter,
            aal=aal,
            clone_timeout=120,
        )
        assert res.cloned_node == "pc1"

    def test_run_operational_workflow_with_custom_clone_timeout(self):
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        final_state = run_operational_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            clone_timeout=90,
            auto_approve=True,
        )
        assert final_state["status"] == "fixed"
        assert adapter.patched is True
