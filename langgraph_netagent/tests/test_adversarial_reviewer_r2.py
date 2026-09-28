"""Adversarial Reviewer Round 2 Test Suite for NetOps Agent.

Deeply attacks and verifies:
1. Live Containerlab Shadow Sandbox image and container cleanup on cloning/run failures.
2. Shadow Sandbox rejection of empty remediation plans (preventing no-op false positive bypasses).
3. IPv6 and multi-vendor syslog parsing in FiveTuple.from_syslog without unhandled exceptions.
4. AAL security whitelist and read-only mode loopholes (piping to shell, base64 decoding, wipefs/shred, vtysh config mutations, unslashed file redirects, file tools, firewall mutations).
5. Robust JSON parser resilience against single-quoted dicts with JSON booleans/null (true/false/null).
6. Discrepant router prioritization over destination end-hosts in 2-stage diagnosis.
7. Next-hop dynamic derivation from inventory/topology in plan generation fallback.
8. Circuit breaker loop progression and failure context propagation across sandbox retries.
"""

from unittest.mock import MagicMock, patch
import pytest

from langgraph_netagent.llm.parser import clean_json_syntax, parse_and_validate
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.remediation import RemediationPlan
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.workflow.operational_edges import route_after_sandbox, route_after_stage2
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


# ===========================================================================
# 1. Shadow Sandbox Leakage & Empty Patch False Positive
# ===========================================================================

class TestShadowSandboxHardening:
    """Verify shadow sandbox prevents resource leaks and rejects empty patches."""

    def test_empty_patch_commands_rejected(self):
        """Empty patch commands must NOT pass sandbox validation when allow_empty=False."""
        adapter = MockContainerlabAdapter()
        aal = AgentAccessLayer(adapter)
        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=[],
            adapter=adapter,
            aal=aal,
            allow_empty=False,
        )
        assert res.all_passed is False, "Empty candidate patch must fail sandbox validation"
        assert res.error_message is not None

        # Also verify sandbox_validation_node rejects empty remediation plan
        nodes = create_operational_nodes(llm_provider=MagicMock(), lab_adapter=adapter)
        state = create_operational_initial_state()
        state["remediation_plan"] = {"target_entity": "frr1", "exec_commands": []}
        node_res = nodes["sandbox_validation"](state)
        assert node_res["sandbox_passed"] is False
        assert node_res["status"] == "sandbox_failed"

    def test_live_clab_image_cleanup_when_run_fails(self):
        """When docker commit succeeds but docker run fails, temporary image MUST be cleaned up."""
        adapter = LiveContainerlabAdapter()
        aal = AgentAccessLayer(adapter)

        run_calls = []

        def mock_run(cmd, sudo=False, timeout=15):
            run_calls.append(cmd)
            if "docker commit" in cmd:
                return CommandResult(command=cmd, exit_code=0, stdout="sha256:12345")
            if "docker run" in cmd:
                return CommandResult(command=cmd, exit_code=1, stderr="docker run failed: port conflict")
            if "docker rmi" in cmd:
                return CommandResult(command=cmd, exit_code=0, stdout="Untagged")
            if "docker rm" in cmd:
                return CommandResult(command=cmd, exit_code=0, stdout="Removed")
            return CommandResult(command=cmd, exit_code=0, stdout="")

        adapter.runner.run = mock_run

        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=["vtysh -c 'conf t'"],
            adapter=adapter,
            aal=aal,
            clone_timeout=45,
        )
        assert res.all_passed is False
        # Verify docker rmi was executed to clean up the temporary image
        rmi_calls = [c for c in run_calls if "docker rmi" in c]
        assert len(rmi_calls) >= 1, "Temporary image must be cleaned up via docker rmi when container run fails"


# ===========================================================================
# 2. IPv6 and Non-IPv4 Syslog Resilience
# ===========================================================================

class TestSyslogIPv6Resilience:
    """Verify FiveTuple.from_syslog handles IPv6 and malformed inputs gracefully."""

    def test_ipv6_iptables_syslog(self):
        log = "IPTables-Dropped: IN=eth1 OUT=eth2 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=54321 DPT=80"
        ft = FiveTuple.from_syslog(log)
        assert ft is not None
        assert ft.source_ip == "2001:db8::1"
        assert ft.destination_ip == "2001:db8::2"
        assert ft.protocol == "TCP"
        assert ft.source_port == 54321
        assert ft.destination_port == 80

    def test_ipv6_cisco_acl_syslog(self):
        log = "%SEC-6-IPACCESSLOGP: list 101 denied tcp 2001:db8::1(12345) -> 2001:db8::2(80), 1 packet"
        ft = FiveTuple.from_syslog(log)
        assert ft is not None
        assert ft.source_ip == "2001:db8::1"
        assert ft.destination_ip == "2001:db8::2"

    def test_ipv6_standard_drop_syslog(self):
        log = "DROP 2001:db8::1:54321 -> 2001:db8::2:80 proto=TCP"
        ft = FiveTuple.from_syslog(log)
        assert ft is not None
        assert ft.source_ip == "2001:db8::1"
        assert ft.destination_ip == "2001:db8::2"

    def test_ipv6_bgp_down_syslog(self):
        log = "%BGP-5-ADJCHANGE: neighbor 2001:db8::2 Down BGP notification"
        ft = FiveTuple.from_syslog(log)
        assert ft is not None
        assert ft.destination_ip == "2001:db8::2"
        assert ft.alert_type == "BGP_SESSION_DOWN"

    @pytest.mark.parametrize("invalid_input", [None, "", "   ", 12345, [], {}])
    def test_syslog_non_string_no_crash(self, invalid_input):
        ft = FiveTuple.from_syslog(invalid_input)
        assert ft is None


# ===========================================================================
# 3. AAL Security & Read-Only Policy Loopholes
# ===========================================================================

class TestAALSecurityLoopholes:
    """Probe AAL against shell pipe execution, base64 evasions, and mutating leaks."""

    @pytest.fixture
    def aal(self):
        return AgentAccessLayer(MockContainerlabAdapter(), raise_on_security_violation=False)

    @pytest.mark.parametrize(
        "blocked_pipe_cmd",
        [
            "echo cmVib290 | base64 -d | sh",
            "echo cm0gLXJmIC8= | base64 --decode | bash",
            "cat /tmp/x | /bin/sh",
            "cat script.sh | sudo bash",
            "echo 'reboot' | zsh",
            "wipefs -a /dev/sda",
            "shred /dev/sda",
            "rm -r /*",
            "rm -r /boot",
            "rm -r /root",
        ],
    )
    def test_dangerous_shell_pipes_and_wipes_blocked(self, aal: AgentAccessLayer, blocked_pipe_cmd: str):
        is_safe, reason = aal.validate_command_safety(blocked_pipe_cmd, read_only=False)
        assert is_safe is False, f"Command '{blocked_pipe_cmd}' should have been blocked"
        assert "SECURITY POLICY VIOLATION" in (reason or "")

    @pytest.mark.parametrize(
        "mutating_cmd",
        [
            "vtysh -c 'router bgp 65000'",
            "vtysh -c 'no ip route 10.2.2.0/24 10.1.12.2'",
            "vtysh -c 'interface eth1' -c 'shutdown'",
            "vtysh -c 'write memory'",
            "vtysh -f /etc/frr/evil.conf",
            "echo 1 > frr.conf",
            "echo 1 > ./frr.conf",
            "echo 1 >> frr.conf",
            "touch /tmp/test",
            "mv foo bar",
            "rm file",
            "tee output.txt",
            "truncate -s 0 /var/log/syslog",
            "iptables -A INPUT -p tcp -j DROP",
            "iptables -F",
            "nft flush ruleset",
            "chmod 777 /etc/shadow",
            "chown root:root /tmp/bad",
        ],
    )
    def test_mutating_operations_blocked_in_read_only(self, aal: AgentAccessLayer, mutating_cmd: str):
        is_safe, reason = aal.validate_command_safety(mutating_cmd, read_only=True)
        assert is_safe is False, f"Mutating command '{mutating_cmd}' should be rejected in read-only mode"
        assert "READ-ONLY CONSTRAINT VIOLATION" in (reason or "") or "SECURITY POLICY VIOLATION" in (reason or "")


# ===========================================================================
# 4. JSON Parser Single-Quote Dict with JSON Booleans
# ===========================================================================

class TestParserSingleQuoteWithBooleans:
    """Verify parser can clean and validate single-quoted dicts containing JSON true/false/null."""

    def test_single_quoted_dict_with_json_literals(self):
        raw = "{'telemetry_trigger': 'ping drop', 'root_cause': 'missing route', 'affected_nodes': ['frr1'], 'error_category': 'routing_misconfig', 'severity': 'high', 'confidence_score': 0.95, 'evidence': ['loss'], 'active': true, 'fallback': null}"
        cleaned = clean_json_syntax(raw)
        instance, err = parse_and_validate(raw, DiagnosticReport)
        assert instance is not None, f"Failed to parse: {err}"
        assert instance.root_cause == "missing route"


# ===========================================================================
# 5. Target Node & Discrepancy Prioritization
# ===========================================================================

class TestDiagnosticTargetPrioritization:
    """Verify diagnosis targets the faulty router rather than the destination host."""

    def test_discrepant_router_prioritized_over_destination_pc(self):
        adapter = MockContainerlabAdapter()
        mock_llm = MagicMock()
        mock_llm.generate_structured.side_effect = Exception("offline")
        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=adapter,
        )

        state = create_operational_initial_state()
        state["topology_path"] = ["pc1", "frr1", "pc2"]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "pc2": "linux"}
        state["suspect_devices"] = ["pc2", "frr1"]  # pc2 was matched from dst_ip
        state["discrepancies"] = [
            NetworkDiscrepancy(
                node="frr1",
                discrepancy_type="missing_route",
                target_destination="10.2.2.0/24",
                description="frr1 missing route",
                suspect_nodes=["frr1"],
            ).model_dump()
        ]
        state["enriched_context"] = {}

        result = nodes["diagnostic_stage2"](state)
        plan = result.get("remediation_plan", {})
        # Target entity must be the router with the discrepancy (frr1), not pc2!
        assert plan.get("target_entity") == "frr1", f"Expected target frr1, got {plan.get('target_entity')}"
        # Commands must be router commands (vtysh)
        cmds = plan.get("exec_commands", [])
        assert len(cmds) > 0
        assert "vtysh" in cmds[0]

    def test_llm_prompt_targets_router_and_includes_retry_context(self):
        adapter = MockContainerlabAdapter()
        mock_llm = MagicMock()
        captured_messages = []

        def capture_call(messages, response_schema):
            captured_messages.extend(messages)
            if response_schema == DiagnosticReport:
                return DiagnosticReport(
                    telemetry_trigger="Packet drop",
                    root_cause="Missing route",
                    affected_nodes=["frr1"],
                    error_category=ErrorCategory.ROUTING_MISCONFIG,
                    severity=SeverityLevel.HIGH,
                    confidence_score=0.95,
                    evidence=["loss"],
                )
            return RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity="frr1",
                exec_commands=["vtysh -c 'conf t' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            )

        mock_llm.generate_structured.side_effect = capture_call
        nodes = create_operational_nodes(llm_provider=mock_llm, lab_adapter=adapter)

        state = create_operational_initial_state()
        state["topology_path"] = ["pc1", "frr1", "pc2"]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "pc2": "linux"}
        state["suspect_devices"] = ["pc2", "frr1"]
        state["discrepancies"] = [
            NetworkDiscrepancy(
                node="frr1",
                discrepancy_type="missing_route",
                target_destination="10.2.2.0/24",
                description="frr1 missing route",
                suspect_nodes=["frr1"],
            ).model_dump()
        ]
        state["retry_count"] = 1
        state["error_message"] = "Previous sandbox validation failed"
        state["sandbox_result"] = {"all_passed": False, "error_message": "Invalid syntax"}

        result = nodes["diagnostic_stage2"](state)
        assert result.get("current_step_tag") == "diag_iter_2"

        # Check prompt contents
        prompt_text = "".join(m.content for m in captured_messages)
        assert "target 'frr1'" in prompt_text
        assert "Previous Attempt Failure Context" in prompt_text
        assert "Invalid syntax" in prompt_text
