"""Full end-to-end integration tests for Milestone 3: External Traffic Overload Healing.

Validates the complete closed-loop self-healing cycle conforming to the UML activity diagram:
1. Stage 1 Context Enrichment:
   - Detects external_overload / buffer_overlimit / TRAFFIC_OVERLOAD.
   - Dispatches read-only AAL tool calls for `tc -s qdisc show` and `ip -s link show` on bottleneck router.
   - Infers RAG search keywords including "overload", "overlimits", "buffer", "tc", "iptables", "traffic_overload".
2. Stage 2 Plan Generation:
   - Retrieves SOP-OVERLOAD-005 from SOPRetriever.
   - Targets the bottleneck router (dc-egress).
   - Formulates candidate remediation commands using iptables with offending source IP drop.
   - Explicitly tags commands with step_tag.
   - Produces structured RemediationPlan and DiagnosticReport.
3. Shadow Sandbox Validation:
   - Validates candidate iptables commands in shadow replica sandbox.
4. Human Approval Gate (HITL):
   - Supports auto_approve=True clearance.
   - Supports non-auto-approve pause (stops at pending_approval / end_rejected without patching live node).
5. Live Hot-Patch:
   - Applies iptables drop rules to live target node via AAL.
   - Clears active buffer overlimit fault in MockEngine.
6. Post-Change Re-verification:
   - Re-runs telemetry probe matrix confirming all drops, overlimits, and buffer anomalies are cleared.
   - Transitions to end_fixed with status='fixed'.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    AnomalyClassification,
    FiveTuple,
    NetworkDiscrepancy,
)
from langgraph_netagent.models.remediation import RemediationPlan
from langgraph_netagent.models.telemetry import NetworkHealthReport
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    RouteEntry,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.tools.sop_retriever import SOPRetriever
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
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)


def _setup_overload_mock_topology(
    fault_rule: FaultRule | None = None,
) -> MockContainerlabAdapter:
    """Helper to build a hermetic mock topology with dc-egress gateway, internal host, and attacker."""
    adapter = MockContainerlabAdapter()
    g = adapter.mock_engine.graph

    # Border gateway / router
    egress = VirtualNode(name="dc-egress", kind="frr", image="frrouting/frr")
    egress.add_interface(VirtualInterface(name="eth1", ip_cidr="203.0.113.1/24"))
    egress.add_interface(VirtualInterface(name="eth2", ip_cidr="192.168.100.1/24"))
    egress.add_route(RouteEntry(destination="203.0.113.0/24", next_hop=None, interface="eth1", protocol="connected"))
    egress.add_route(RouteEntry(destination="192.168.100.0/24", next_hop=None, interface="eth2", protocol="connected"))
    g.add_node(egress)
    g.register_ip("203.0.113.1/24", "dc-egress", "eth1")
    g.register_ip("192.168.100.1/24", "dc-egress", "eth2")

    # Internal protected host
    h1 = VirtualNode(name="h1", kind="linux")
    h1.add_interface(VirtualInterface(name="eth1", ip_cidr="203.0.113.10/24"))
    h1.default_gateway = "203.0.113.1"
    h1.add_route(RouteEntry(destination="default", next_hop="203.0.113.1", interface="eth1", protocol="static"))
    h1.add_route(RouteEntry(destination="203.0.113.0/24", next_hop=None, interface="eth1", protocol="connected"))
    g.add_node(h1)
    g.register_ip("203.0.113.10/24", "h1", "eth1")

    # External attacker
    attacker = VirtualNode(name="attacker", kind="linux")
    attacker.add_interface(VirtualInterface(name="eth1", ip_cidr="192.168.100.2/24"))
    attacker.default_gateway = "192.168.100.1"
    attacker.add_route(RouteEntry(destination="default", next_hop="192.168.100.1", interface="eth1", protocol="static"))
    attacker.add_route(RouteEntry(destination="192.168.100.0/24", next_hop=None, interface="eth1", protocol="connected"))
    g.add_node(attacker)
    g.register_ip("192.168.100.2/24", "attacker", "eth1")

    # Connect links
    g.add_link("dc-egress", "eth1", "h1", "eth1")
    g.add_link("attacker", "eth1", "dc-egress", "eth2")

    adapter._deployed = True

    if fault_rule is not None:
        adapter.fault_injector.add_rule(fault_rule)

    return adapter


# ==============================================================================
# 1. Stage 1 Context Enrichment & Stage 2 SOP Retrieval Tests
# ==============================================================================

class TestStage1ContextEnrichmentAndStage2SOPRetrieval:
    """Validate Stage 1 read-only inspection and Stage 2 plan formulation under overload."""

    def test_stage1_context_enrichment_under_buffer_overlimit(self):
        """Stage 1 dispatches read-only tc and ip link tool calls and infers overload keywords."""
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            target_interface="eth2",
            overlimits=25000,
            dropped=6000,
            source_ip="192.168.100.2",
            dest_port=80,
        )
        adapter = _setup_overload_mock_topology(rule)
        aal = AgentAccessLayer(lab_adapter=adapter)
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            aal=aal,
        )

        state = create_operational_initial_state()
        state["topology_path"] = ["dc-egress", "h1", "attacker"]
        state["node_kinds"] = {"dc-egress": "linux", "h1": "linux", "attacker": "linux"}
        state["suspect_devices"] = ["dc-egress"]
        state["discrepancies"] = [
            {
                "node": "dc-egress",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth2",
                "description": "Buffer overlimit on dc-egress:eth2: 6000 dropped, 25000 overlimits",
                "severity": "critical",
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "192.168.100.2",
                "destination_ip": "203.0.113.10",
                "protocol": "TCP",
                "destination_port": 80,
                "alert_type": "TRAFFIC_OVERLOAD",
                "overlimits_count": 25000,
                "dropped_packets": 6000,
                "is_external_overload": True,
            }
        ]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "confidence": 0.95,
            "bottleneck_node": "dc-egress",
            "bottleneck_interface": "eth2",
            "offending_source_ip": "192.168.100.2",
            "victim_destination_ip": "203.0.113.10",
        }

        result = nodes["diagnostic_stage1"](state)

        assert result["status"] == "stage1_enriched"
        enriched = result["enriched_context"]
        assert enriched["is_overload"] is True
        assert enriched["bottleneck_node"] == "dc-egress"

        # Verify read-only tc and ip link tool calls were recorded
        suspect_data = enriched["suspect_nodes"]["dc-egress"]
        assert "qdisc_raw" in suspect_data
        assert "link_stats_raw" in suspect_data
        assert "dropped 6000" in suspect_data["qdisc_raw"]
        assert "overlimits 25000" in suspect_data["qdisc_raw"]

        # Verify inferred RAG keywords
        rag_keywords = result["rag_keywords"]
        for expected_kw in ("overload", "overlimits", "buffer", "tc", "iptables", "traffic_overload"):
            assert expected_kw in rag_keywords, f"Missing expected keyword '{expected_kw}' in {rag_keywords}"

    def test_stage2_sop_retrieval_and_iptables_plan_formulation(self):
        """Stage 2 retrieves SOP-OVERLOAD-005 and formulates tagged iptables remediation commands."""
        adapter = _setup_overload_mock_topology()
        retriever = SOPRetriever()
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            sop_retriever=retriever,
        )

        state = create_operational_initial_state()
        state["topology_path"] = ["dc-egress", "h1", "attacker"]
        state["node_kinds"] = {"dc-egress": "linux", "h1": "linux", "attacker": "linux"}
        state["suspect_devices"] = ["dc-egress"]
        state["rag_keywords"] = ["buffer", "iptables", "overlimits", "overload", "tc", "traffic_overload"]
        state["discrepancies"] = [
            {
                "node": "dc-egress",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth2",
                "severity": "critical",
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "192.168.100.2",
                "destination_ip": "203.0.113.10",
                "protocol": "TCP",
                "destination_port": 80,
                "alert_type": "TRAFFIC_OVERLOAD",
                "is_external_overload": True,
            }
        ]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "confidence": 0.95,
            "bottleneck_node": "dc-egress",
            "offending_source_ip": "192.168.100.2",
            "victim_destination_ip": "203.0.113.10",
        }

        result = nodes["diagnostic_stage2"](state)

        assert result["status"] == "stage2_plan_generated"
        assert result["circuit_breaker_tripped"] is False

        # Verify SOP-OVERLOAD-005 retrieved
        retrieved = result["retrieved_sop"]
        assert len(retrieved) >= 1
        assert any(sop["sop_id"] == "SOP-OVERLOAD-005" for sop in retrieved)

        # Verify candidate remediation plan targets dc-egress
        plan = result["remediation_plan"]
        assert plan["target_entity"] == "dc-egress"
        assert plan["step_tag"] == "diag_iter_1"
        assert result["current_step_tag"] == "diag_iter_1"

        # Verify candidate commands use iptables DROP on offending source IP
        exec_cmds = plan["exec_commands"]
        assert len(exec_cmds) >= 1
        assert any("iptables" in cmd and "192.168.100.2" in cmd and "DROP" in cmd for cmd in exec_cmds)

        # Verify rollback steps exist
        rollback = plan["rollback_steps"]
        assert len(rollback) >= 1
        assert any("iptables -D" in step["payload"] for step in rollback)

        # Verify DiagnosticReport is structured and populated
        report = result["diagnostic_report"]
        assert report["affected_nodes"] == ["dc-egress"]
        assert "192.168.100.2" in report["root_cause"]


# ==============================================================================
# 2. Full End-to-End Operational Workflow Integration Tests
# ==============================================================================

class TestOverloadHealingEndToEndFullCycle:
    """End-to-end integration tests executing run_operational_workflow under buffer overload."""

    def test_full_cycle_overload_healing_auto_approve(self):
        """Full end-to-end cycle:

        baseline_ingestion -> telemetry_extraction -> diagnostic_stage1 ->
        diagnostic_stage2 -> sandbox_validation -> human_approval ->
        live_hot_patch -> re_verification -> end_fixed.
        """
        # Injected rule matching prompt specification:
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            node="dc-egress",
            source_ip="192.168.100.2",
        )
        adapter = _setup_overload_mock_topology(rule)

        # Confirm fault rule is initially active
        assert len(adapter.fault_injector.get_active_rules()) == 1

        final_state = run_operational_workflow(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            auto_approve=True,
            max_retries=3,
        )

        # 1. Verify final status is 'fixed'
        assert final_state["status"] == "fixed"

        # 2. Verify all UML workflow stages were traversed in order
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        expected_sequence = [
            "baseline_ingestion",
            "telemetry_extraction",
            "diagnostic_stage1",
            "diagnostic_stage2",
            "sandbox_validation",
            "human_approval",
            "live_hot_patch",
            "re_verification",
            "end_fixed",
        ]
        for stage in expected_sequence:
            assert stage in stages, f"Expected stage '{stage}' not found in execution logs: {stages}"

        # 3. Verify Stage 1 enriched context and RAG keywords
        assert final_state.get("enriched_context") is not None
        assert "dc-egress" in final_state["enriched_context"]["suspect_nodes"]
        rag_kws = final_state.get("rag_keywords", [])
        assert "overload" in rag_kws
        assert "iptables" in rag_kws

        # 4. Verify Stage 2 generated plan and tagged step
        plan = final_state.get("remediation_plan")
        assert plan is not None
        assert plan["target_entity"] == "dc-egress"
        assert "diag_iter_1" in plan["step_tag"]
        assert len(final_state.get("step_tags_history", [])) >= 1

        # 5. Verify sandbox validation passed before human approval
        assert final_state.get("sandbox_passed") is True
        sandbox_res = final_state.get("sandbox_result")
        assert sandbox_res is not None
        assert sandbox_res["all_passed"] is True
        assert sandbox_res["cloned_node"] == "dc-egress"

        # 6. Verify human approval was granted
        assert final_state.get("human_approved") is True

        # 7. Verify live hot patch succeeded
        patch_res = final_state.get("patch_result")
        assert patch_res is not None
        assert patch_res["all_ok"] is True
        assert patch_res["target"] == "dc-egress"

        # 8. Verify post-change re-verification passed cleanly
        re_ver = final_state.get("re_verify_results")
        assert re_ver is not None
        assert re_ver["all_passed"] is True
        assert len(re_ver.get("buffer_anomalies", [])) == 0
        assert len(re_ver.get("failures", [])) == 0

        # 9. Verify fault rule was cleared on live target node
        assert len(adapter.fault_injector.get_active_rules()) == 0

    def test_full_cycle_overload_with_port_and_vip_specifications(self):
        """Full end-to-end cycle with explicit target_node, target_interface, and dest_port."""
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            target_interface="eth2",
            overlimits=35000,
            dropped=9000,
            source_ip="192.168.100.2",
            dest_port=80,
        )
        adapter = _setup_overload_mock_topology(rule)

        final_state = run_operational_workflow(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            auto_approve=True,
            max_retries=3,
        )

        assert final_state["status"] == "fixed"
        plan = final_state["remediation_plan"]
        exec_cmds = plan["exec_commands"]

        # Should include boundary iptables drop
        assert any("iptables" in c and "192.168.100.2" in c and "DROP" in c for c in exec_cmds)

        # Fault rule should be cleared
        assert len(adapter.fault_injector.get_active_rules()) == 0


# ==============================================================================
# 3. Non-Auto-Approve / HITL Behavior Tests
# ==============================================================================

class TestNonAutoApproveBehavior:
    """Validate HITL gate behavior when auto_approve=False."""

    def test_non_auto_approve_pauses_before_live_patching(self):
        """When auto_approve=False in non-interactive mode, execution halts at pending_approval."""
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            node="dc-egress",
            source_ip="192.168.100.2",
        )
        adapter = _setup_overload_mock_topology(rule)

        final_state = run_operational_workflow(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            auto_approve=False,
            interactive=False,
            max_retries=3,
        )

        # Status must be pending_approval
        assert final_state["status"] in ("pending_approval", "rejected")

        # Stages must reach human_approval but NOT live_hot_patch or re_verification
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "sandbox_validation" in stages
        assert "human_approval" in stages
        assert "live_hot_patch" not in stages
        assert "re_verification" not in stages
        assert "end_fixed" not in stages

        # Candidate commands WERE tested in sandbox
        assert final_state.get("sandbox_passed") is True

        # Fault rule remains active since live patch was NOT deployed
        assert len(adapter.fault_injector.get_active_rules()) == 1

    def test_explicit_operator_rejection_halts_at_end_rejected(self):
        """When operator explicitly rejects candidate plan, status is 'rejected'."""
        adapter = _setup_overload_mock_topology()
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            auto_approve=False,
        )

        state = create_operational_initial_state(auto_approve=False)
        state["human_approved"] = False
        state["remediation_plan"] = {
            "plan_id": "test-plan-1",
            "target_entity": "dc-egress",
            "exec_commands": ["iptables -I FORWARD -s 192.168.100.2 -j DROP"],
        }

        approval_res = nodes["human_approval"](state)
        assert approval_res["human_approved"] is False
        assert approval_res["status"] == "rejected"

        state.update(approval_res)
        assert route_after_approval(state) == "end_rejected"

        end_res = nodes["end_rejected"](state)
        assert end_res["status"] == "rejected"


# ==============================================================================
# 4. Shadow Sandbox Safety & Isolation Tests
# ==============================================================================

class TestShadowSandboxIsolationAndSafety:
    """Validate sandbox execution does not mutate live state before hot-patching."""

    def test_sandbox_validation_does_not_clear_live_fault(self):
        """Sandbox validation on replica must NOT clear the live fault rule."""
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            source_ip="192.168.100.2",
        )
        adapter = _setup_overload_mock_topology(rule)
        aal = AgentAccessLayer(lab_adapter=adapter)

        # Run sandbox validation directly
        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="dc-egress",
            patch_commands=["iptables -I FORWARD -s 192.168.100.2 -j DROP"],
            adapter=adapter,
            aal=aal,
            step_tag="test_sandbox_tag",
        )

        assert res.all_passed is True
        assert res.cloned_node == "dc-egress"

        # Crucial check: live fault rule MUST still be intact!
        active_rules = adapter.fault_injector.get_active_rules()
        assert len(active_rules) == 1
        assert active_rules[0].fault_type == FaultType.BUFFER_OVERLIMIT

    def test_destructive_commands_blocked_by_aal(self):
        """Destructive command in candidate patch is blocked by AAL in sandbox."""
        adapter = _setup_overload_mock_topology()
        aal = AgentAccessLayer(lab_adapter=adapter)

        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="dc-egress",
            patch_commands=["rm -rf /etc/*"],
            adapter=adapter,
            aal=aal,
        )

        assert res.all_passed is False
        assert "SECURITY POLICY VIOLATION" in (res.error_message or "")
