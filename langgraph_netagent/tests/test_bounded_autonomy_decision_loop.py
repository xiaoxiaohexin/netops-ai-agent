"""Milestone 4: Bounded AI Autonomy & Two-Stage Diagnostic Decision Loop (Day-2) Verification Tests.

Validates:
1. Stage 1 read-only constraint enforcement:
   - Strict read-only observation via AAL (read_only=True blocks mutating commands).
   - Full autonomy tier for telemetry and anomaly classification.
2. Stage 2 dual-retrieval ingestion & CanonicalIntent compilation:
   - Ingests dual-retrieval vendor knowledge and SOP playbooks.
   - Synthesizes declarative CanonicalIntent primitives (e.g. DROP_TRAFFIC, RESTORE_ROUTE, RESET_INTERFACE).
   - Compiles via CanonicalIntentCompiler into CompilationResult with reverse topological rollbacks.
   - Monotonic step_tag tagging (diag_iter_{retry_count + 1}).
   - Bounded autonomy tier enforcement.
3. Deterministic circuit breaker:
   - Trips when retry_count >= max_retries, halting execution safely.
4. Pre-flight sandbox pass report & SHA-256 signature verification:
   - Emits PreflightSandboxPassReport under network isolation and resource quotas.
   - Verifies cryptographic pass_signature and clean pass validation.
   - Detects and rejects tampered signatures or non-zero exit codes.
5. Guardrailed Human Approval Gate (HITL):
   - Blocks live deployment if PreflightSandboxPassReport is missing, unverified, or invalid.
   - Permits live deployment only after clean sandbox pass verification (auto-approve or manual).
6. Automated inverse rollback execution on re-verification failure:
   - Post-change probe failure triggers execution of inverse rollback compensation commands via AAL.
   - State records rollback execution results and increments retry counter.
7. Full lifecycle end-to-end state transitions across autonomy tiers.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import pytest

from langgraph_netagent.models.diagnostic import (
    DiagnosticReport,
    ErrorCategory,
    SeverityLevel,
)
from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CompilationResult,
    IntentAction,
    RollbackStep,
    TargetPlatform,
)
from langgraph_netagent.models.operational import (
    AALToolCall,
    AnomalyClassification,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.remediation import (
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.models.sandbox import (
    PreflightSandboxPassReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.tools.aal import AgentAccessLayer, AALSecurityError
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.intent_compiler import CanonicalIntentCompiler
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.tools.sop_retriever import SOPRetriever
from langgraph_netagent.workflow.operational_edges import (
    route_after_approval,
    route_after_healthy,
    route_after_re_verification,
    route_after_sandbox,
    route_after_stage2,
    route_after_telemetry,
)
from langgraph_netagent.workflow.operational_graph import (
    build_operational_graph,
    run_operational_workflow,
)
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)
from tests.test_operational_workflow import MockOperationalLLMProvider, MockUMLAdapter


# ==============================================================================
# 1. Stage 1 Read-Only Enforcement & Autonomy Tier
# ==============================================================================

class TestStage1ReadOnlyEnforcement:
    """Validate Stage 1 observation autonomy and strict read-only guarantees."""

    def test_stage1_strictly_uses_read_only_aal_calls(self):
        adapter = MockUMLAdapter(healthy=False)
        aal = AgentAccessLayer(adapter)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, aal=aal)

        state = create_operational_initial_state()
        state["suspect_devices"] = ["frr1"]
        state["node_kinds"] = {"frr1": "frr"}
        state["discrepancies"] = [
            {"node": "frr1", "discrepancy_type": "missing_route", "target_destination": "10.2.2.0/24"}
        ]

        result = nodes["diagnostic_stage1"](state)

        # Autonomy tier is full_autonomy for diagnostic stage 1
        assert result["autonomy_tier"] == "full_autonomy"
        assert result["status"] == "stage1_enriched"
        assert "rag_keywords" in result
        assert len(result["rag_keywords"]) > 0

        # Verify all AAL tool calls recorded in history have read_only=True
        aal_history = aal.execution_history
        assert len(aal_history) > 0
        for entry in aal_history:
            assert entry["read_only"] is True, f"AAL call {entry['command']} was not read_only!"

    def test_aal_blocks_mutating_commands_when_read_only_is_true(self):
        adapter = MockUMLAdapter(healthy=False)
        aal = AgentAccessLayer(adapter)

        mutating_commands = [
            "ip link set dev eth1 up",
            "iptables -I FORWARD -s 192.168.100.2 -j DROP",
            "vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'",
            "sysctl -w net.ipv4.ip_forward=1",
        ]

        for cmd in mutating_commands:
            call = AALToolCall(
                tool_name="test_cmd",
                node_name="frr1",
                command=cmd,
                read_only=True,
            )
            resp = aal.execute(call)
            assert resp.is_blocked is True
            assert resp.success is False
            assert "READ-ONLY" in resp.error_message


# ==============================================================================
# 2. Stage 2 Canonical Intent Synthesis & Rollback Compilation
# ==============================================================================

class TestStage2CanonicalIntentCompilation:
    """Validate Stage 2 synthesis of CanonicalIntent, compilation, and step-tagging."""

    def test_stage2_synthesizes_canonical_intents_and_compiles_rollbacks(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        retriever = SOPRetriever()
        nodes = create_operational_nodes(
            llm_provider=llm,
            lab_adapter=adapter,
            sop_retriever=retriever,
        )

        state = create_operational_initial_state()
        state["suspect_devices"] = ["frr1"]
        state["node_kinds"] = {"frr1": "frr"}
        state["rag_keywords"] = ["frr", "static", "route", "missing_route"]
        state["discrepancies"] = [
            {"node": "frr1", "discrepancy_type": "missing_route", "target_destination": "10.2.2.0/24"}
        ]
        state["failure_5tuples"] = [
            {"source_ip": "10.1.1.2", "destination_ip": "10.2.2.2", "protocol": "icmp", "alert_type": "packet_drop"}
        ]
        state["retry_count"] = 0

        result = nodes["diagnostic_stage2"](state)

        # Autonomy tier is bounded for remediation planning
        assert result["autonomy_tier"] == "bounded"
        assert result["current_step_tag"] == "diag_iter_1"
        assert result["step_tag"] == "diag_iter_1"
        assert result["status"] == "stage2_plan_generated"

        # Dual retrieval results ingested
        assert "dual_retrieval_results" in result
        assert isinstance(result["dual_retrieval_results"], list)

        # Canonical intents synthesized and compiled
        canonical_intents = result.get("canonical_intents")
        assert canonical_intents is not None
        assert len(canonical_intents) >= 1
        assert any(ci["action"] in ("RESTORE_ROUTE", "RESET_INTERFACE") for ci in canonical_intents)

        compilation_results = result.get("compilation_results")
        assert compilation_results is not None
        assert len(compilation_results) >= 1
        for cr in compilation_results:
            assert cr["is_safe"] is True
            assert len(cr["forward_commands"]) > 0
            assert len(cr["rollback_commands"]) > 0
            assert len(cr["rollback_steps"]) > 0

        # Remediation plan contains executable commands and rollbacks with step_tag
        plan = result["remediation_plan"]
        assert plan["step_tag"] == "diag_iter_1"
        assert len(plan["exec_commands"]) > 0
        assert len(plan["rollback_steps"]) > 0

    def test_stage2_overload_synthesizes_drop_traffic_canonical_intents(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="dc-egress")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter)

        state = create_operational_initial_state()
        state["suspect_devices"] = ["dc-egress"]
        state["node_kinds"] = {"dc-egress": "linux"}
        state["rag_keywords"] = ["overload", "buffer", "iptables", "external_overload"]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "confidence": 0.95,
            "bottleneck_node": "dc-egress",
            "offending_source_ip": "192.168.100.2",
            "victim_destination_ip": "203.0.113.10",
        }
        state["failure_5tuples"] = [
            {
                "source_ip": "192.168.100.2",
                "destination_ip": "203.0.113.10",
                "protocol": "tcp",
                "destination_port": 80,
                "alert_type": "TRAFFIC_OVERLOAD",
            }
        ]
        state["discrepancies"] = [
            {"node": "dc-egress", "discrepancy_type": "buffer_overlimit"}
        ]
        state["retry_count"] = 1

        result = nodes["diagnostic_stage2"](state)

        assert result["autonomy_tier"] == "bounded"
        assert result["current_step_tag"] == "diag_iter_2"
        assert result["step_tag"] == "diag_iter_2"

        # CanonicalIntents must specify DROP_TRAFFIC on LINUX_IPTABLES
        intents = result["canonical_intents"]
        assert len(intents) >= 1
        assert any(i["action"] == "DROP_TRAFFIC" and i["source_ip"] == "192.168.100.2" for i in intents)

        # CompilationResults must generate forward DROP and reverse -D
        comp_res = result["compilation_results"]
        assert len(comp_res) >= 1
        all_fwd = [cmd for cr in comp_res for cmd in cr["forward_commands"]]
        all_rb = [cmd for cr in comp_res for cmd in cr["rollback_commands"]]
        assert any("iptables" in cmd and "DROP" in cmd and "192.168.100.2" in cmd for cmd in all_fwd)
        assert any("iptables" in cmd and "-D" in cmd and "192.168.100.2" in cmd for cmd in all_rb)


# ==============================================================================
# 3. Deterministic Circuit Breaker Tripping
# ==============================================================================

class TestDeterministicCircuitBreaker:
    """Validate that circuit breaker trips deterministically when loop threshold is reached."""

    def test_circuit_breaker_trips_deterministically_in_stage2(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter)

        state = create_operational_initial_state(max_retries=3)
        state["retry_count"] = 3  # Exhausted

        result = nodes["diagnostic_stage2"](state)

        assert result["circuit_breaker_tripped"] is True
        assert result["status"] == "circuit_broken"
        assert result["autonomy_tier"] == "bounded"
        assert "Retry threshold exceeded" in result["error_message"]
        assert any(log["level"] == "critical" for log in result["execution_logs"])

        # Edge routing after stage2 directs straight to circuit_breaker node
        state.update(result)
        assert route_after_stage2(state) == "circuit_breaker"

    def test_circuit_breaker_node_safely_terminates(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter)

        state = create_operational_initial_state(max_retries=2)
        state["retry_count"] = 2

        cb_res = nodes["circuit_breaker"](state)
        assert cb_res["status"] == "circuit_broken"
        assert cb_res["circuit_breaker_tripped"] is True
        assert cb_res["autonomy_tier"] == "bounded"
        assert "Execution halted safely" in cb_res["error_message"]


# ==============================================================================
# 4. Pre-Flight Sandbox Pass Report & Signature Verification
# ==============================================================================

class TestPreflightSandboxReportAndSignatures:
    """Validate pre-flight sandbox execution, SHA-256 signature, and tampering rejection."""

    def test_preflight_pass_report_generation_and_clean_verification(self):
        adapter = MockContainerlabAdapter()
        report = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            step_tag="diag_iter_1",
            adapter=adapter,
            timeout=15,
        )

        assert report.all_passed is True
        assert report.network_isolated is True
        assert len(report.commands_executed) == 1
        assert report.exit_codes == [0]
        assert report.pass_signature is not None
        assert len(report.pass_signature) == 32  # SHA-256 hex digest prefix

        # verify_clean_pass() must succeed on authentic un-tampered report
        assert report.verify_clean_pass() is True

    def test_tampered_pass_signature_is_rejected_by_verify_clean_pass(self):
        adapter = MockContainerlabAdapter()
        report = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            step_tag="diag_iter_1",
            adapter=adapter,
        )

        assert report.verify_clean_pass() is True

        # Forge signature
        tampered_report = copy.deepcopy(report)
        tampered_report.pass_signature = "a" * 32
        assert tampered_report.verify_clean_pass() is False

        # Tampered commands executed
        tampered_cmds = copy.deepcopy(report)
        tampered_cmds.commands_executed.append("malicious command")
        assert tampered_cmds.verify_clean_pass() is False

        # Non-zero exit code
        failed_exit = copy.deepcopy(report)
        failed_exit.exit_codes = [1]
        assert failed_exit.verify_clean_pass() is False

        # Network not isolated
        non_isolated = copy.deepcopy(report)
        non_isolated.network_isolated = False
        assert non_isolated.verify_clean_pass() is False

    def test_sandbox_validation_node_emits_certified_preflight_report(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter)

        state = create_operational_initial_state()
        state["remediation_plan"] = {
            "plan_id": "plan-1",
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
        }
        state["current_step_tag"] = "diag_iter_1"

        res = nodes["sandbox_validation"](state)

        assert res["sandbox_passed"] is True
        assert res["autonomy_tier"] == "full_autonomy"
        assert res["status"] == "sandbox_passed"

        preflight = res["preflight_report"]
        assert preflight is not None
        assert preflight["all_passed"] is True
        assert preflight["network_isolated"] is True
        assert preflight["pass_signature"] is not None

        # Reconstructed report verifies clean pass
        pass_report = PreflightSandboxPassReport.model_validate(preflight)
        assert pass_report.verify_clean_pass() is True


# ==============================================================================
# 5. Guardrailed Bounded Autonomy HITL Approval Gate
# ==============================================================================

class TestGuardrailedHITLApprovalGate:
    """Validate HITL gate blocks uncertified patches and requires PreflightSandboxPassReport."""

    def test_approval_blocked_when_preflight_report_missing(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        # Even with auto_approve=True, missing preflight must block live execution
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, auto_approve=True)

        state = create_operational_initial_state(auto_approve=True)
        state["remediation_plan"] = {
            "plan_id": "plan-unverified",
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
        }
        # Preflight report is deliberately NOT set in state
        state["preflight_report"] = None

        approval_res = nodes["human_approval"](state)

        assert approval_res["human_approved"] is False
        assert approval_res["status"] == "rejected"
        assert approval_res["autonomy_tier"] == "bounded"
        assert "Blocked: Preflight sandbox pass report is missing or unverified" in approval_res["error_message"]

    def test_approval_blocked_when_preflight_report_fails_clean_pass(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, auto_approve=True)

        state = create_operational_initial_state(auto_approve=True)
        state["remediation_plan"] = {
            "plan_id": "plan-tampered",
            "target_entity": "frr1",
            "exec_commands": ["ip route add 10.2.2.0/24 via 10.1.12.2"],
        }
        # Preflight report with forged signature
        forged_report = PreflightSandboxPassReport(
            sandbox_id="sandbox-test",
            target_node="frr1",
            commands_executed=["ip route add 10.2.2.0/24 via 10.1.12.2"],
            all_passed=True,
            exit_codes=[0],
            pass_signature="bad_signature_digest" + "0" * 44,
        )
        state["preflight_report"] = forged_report.model_dump()

        approval_res = nodes["human_approval"](state)

        assert approval_res["human_approved"] is False
        assert approval_res["status"] == "rejected"
        assert approval_res["autonomy_tier"] == "bounded"
        assert "Blocked" in approval_res["error_message"]

    def test_approval_granted_when_preflight_verified_clean(self):
        adapter = MockUMLAdapter(healthy=False)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, auto_approve=True)

        valid_report = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            step_tag="diag_iter_1",
            adapter=adapter,
        )

        state = create_operational_initial_state(auto_approve=True)
        state["remediation_plan"] = {
            "plan_id": "plan-verified",
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
        }
        state["preflight_report"] = valid_report.model_dump()

        approval_res = nodes["human_approval"](state)

        assert approval_res["human_approved"] is True
        assert approval_res["status"] == "approved"
        assert approval_res["autonomy_tier"] == "bounded"

        # Edge routing after approval routes to live_hot_patch
        state.update(approval_res)
        assert route_after_approval(state) == "live_hot_patch"


# ==============================================================================
# 6. Automated Inverse Rollback Execution on Re-verification Failure
# ==============================================================================

class TestAutomatedInverseRollbackOnReVerificationFailure:
    """Validate automated inverse rollback execution when post-change verification fails."""

    def test_re_verification_failure_triggers_inverse_rollback(self):
        # Adapter configured so network remains unhealthy after patch
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=False)
        aal = AgentAccessLayer(adapter)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, aal=aal)

        state = create_operational_initial_state(max_retries=3)
        state["retry_count"] = 0
        state["current_step_tag"] = "diag_iter_1"
        state["remediation_plan"] = {
            "plan_id": "plan-failing-verify",
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            "rollback_steps": [
                {
                    "step_order": 1,
                    "command": "vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'",
                    "target_node": "frr1",
                    "description": "Remove route",
                }
            ],
        }

        re_ver_res = nodes["re_verification"](state)

        assert re_ver_res["status"] == "re_verify_failed"
        assert re_ver_res["retry_count"] == 1
        assert re_ver_res["circuit_breaker_tripped"] is False
        assert re_ver_res["autonomy_tier"] == "bounded"

        # Automated rollback was triggered and recorded
        assert re_ver_res["rollback_executed"] is True
        rollback_results = re_ver_res["rollback_results"]
        assert len(rollback_results) == 1
        assert "no ip route" in rollback_results[0]["command"]
        assert rollback_results[0]["success"] is True

        # Check routing: since retries remain (1 < 3), routes back to diagnostic_stage1
        state.update(re_ver_res)
        assert route_after_re_verification(state) == "diagnostic_stage1"

    def test_re_verification_failure_exhausting_retries_trips_circuit_breaker(self):
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=False)
        aal = AgentAccessLayer(adapter)
        llm = MockOperationalLLMProvider(target_node="frr1")
        nodes = create_operational_nodes(llm_provider=llm, lab_adapter=adapter, aal=aal)

        state = create_operational_initial_state(max_retries=2)
        state["retry_count"] = 1  # Next failure reaches limit (2)
        state["current_step_tag"] = "diag_iter_2"
        state["remediation_plan"] = {
            "plan_id": "plan-retry-exhaust",
            "target_entity": "frr1",
            "exec_commands": ["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            "rollback_steps": [
                {
                    "step_order": 1,
                    "command": "vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'",
                    "target_node": "frr1",
                }
            ],
        }

        re_ver_res = nodes["re_verification"](state)

        assert re_ver_res["status"] == "re_verify_failed"
        assert re_ver_res["retry_count"] == 2
        assert re_ver_res["circuit_breaker_tripped"] is True
        assert re_ver_res["rollback_executed"] is True

        # Edge routing after re_verification routes to circuit_breaker
        state.update(re_ver_res)
        assert route_after_re_verification(state) == "circuit_breaker"


# ==============================================================================
# 7. End-to-End Bounded Autonomy Lifecycle
# ==============================================================================

class TestEndToEndBoundedAutonomyLifecycle:
    """Full lifecycle validation of two-stage decision loop with bounded autonomy."""

    def test_full_operational_cycle_with_certified_pass_and_auto_approve(self):
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)
        llm = MockOperationalLLMProvider(target_node="frr1")

        final_state = run_operational_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=True,
            max_retries=3,
        )

        assert final_state["status"] == "fixed"
        assert final_state["human_approved"] is True

        # Verify state persistence of Milestone 4 attributes
        assert final_state["autonomy_tier"] == "bounded"
        assert final_state.get("preflight_report") is not None
        assert final_state.get("preflight_report")["all_passed"] is True
        assert final_state.get("canonical_intents") is not None
        assert final_state.get("compilation_results") is not None

        # Verify execution stages
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "telemetry_extraction" in stages
        assert "diagnostic_stage1" in stages
        assert "diagnostic_stage2" in stages
        assert "sandbox_validation" in stages
        assert "human_approval" in stages
        assert "live_hot_patch" in stages
        assert "re_verification" in stages
        assert "end_fixed" in stages
