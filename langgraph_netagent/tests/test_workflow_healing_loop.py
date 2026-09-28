"""End-to-End Automated Tests for Operational Closed-Loop Self-Healing.

Verifies the in-flight runtime healing loop:
Deployment -> Verification Probing (failure detected) -> Diagnosis & Healing
-> Configuration Patching -> Redeployment -> Verification Probing (pass) -> Verified.
"""

from pathlib import Path
import pytest

from langgraph_netagent.llm import MockLLMProvider
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.intent import LinkIntent, NetworkIntent, NodeIntent
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import build_network_agent_graph, run_network_agent_workflow
from langgraph_netagent.workflow.nodes import DiagnosticAndRemediation
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowHealingLoop:
    """Test suite for telemetry failure diagnosis, config patching, and closed-loop recovery."""

    def test_self_healing_ping_drop_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Test telemetry ping failure triggering diagnosis and successful patch recovery."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        heal_plan = sample_remediation_plan.model_copy(deep=True)
        heal_plan.configuration_patch.new_content = (
            "hostname frr1\ninterface eth1\n ip address 10.1.1.1/24\nip route 10.2.2.0/24 10.1.12.2\n"
        )
        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=heal_plan,
        )
        mock_llm.register_canned_response(combo)

        # Inject ping drop that clears on retry 1
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                loss_pct=100.0,
                active_until_retry=1,
            )
        )

        export_dir = tmp_path / "clab_ping_drop"
        final_state = run_network_agent_workflow(
            user_intent="Connect hosts with ping drop recovery",
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=export_dir,
            max_retries=3,
            auto_approve=True,
        )

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["diagnostic_report"] is not None
        assert final_state["diagnostic_report"]["root_cause"] == sample_diagnostic_report.root_cause
        assert final_state["remediation_plan"] is not None
        assert final_state["verification_results"]["all_passed"] is True

        # Verify trace logs record the healing sequence
        stages = [log["stage"] for log in final_state["execution_logs"]]
        assert "diagnosis_and_healing" in stages
        deploy_indices = [i for i, s in enumerate(stages) if s == "deployment"]
        heal_indices = [i for i, s in enumerate(stages) if s == "diagnosis_and_healing"]
        assert len(deploy_indices) >= 2
        assert len(heal_indices) == 1
        assert deploy_indices[0] < heal_indices[0] < deploy_indices[1]

    def test_self_healing_missing_route_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ):
        """Test missing route fault on router node causing ping drop and repaired via config patch."""
        four_node_intent = NetworkIntent(
            intent_id="intent-mv-04",
            raw_intent="Deploy 4-node multi-vendor network with pc1, frr1, srl1, pc2.",
            summary="Multi-vendor Alpine/FRR/SRLinux topology.",
            nodes=[
                NodeIntent(name="pc1", role="host", device_kind="linux", subnets=["10.1.1.0/24"]),
                NodeIntent(name="frr1", role="router", device_kind="frr", subnets=["10.1.1.0/24", "10.1.12.0/24"]),
                NodeIntent(name="srl1", role="router", device_kind="nokia_srlinux", subnets=["10.1.12.0/24", "10.2.2.0/24"]),
                NodeIntent(name="pc2", role="host", device_kind="linux", subnets=["10.2.2.0/24"]),
            ],
            links=[
                LinkIntent(source_node="pc1", target_node="frr1", subnet="10.1.1.0/24"),
                LinkIntent(source_node="frr1", target_node="srl1", subnet="10.1.12.0/24"),
                LinkIntent(source_node="srl1", target_node="pc2", subnet="10.2.2.0/24"),
            ],
            source_endpoints=["pc1"],
            target_endpoints=["pc2"],
            verification_targets=["pc1 -> pc2 ping"],
        )

        mock_llm.register_canned_response(four_node_intent)
        mock_llm.register_canned_response(full_multi_node_package)

        diag = DiagnosticReport(
            telemetry_trigger="Packet loss to 10.2.2.0/24 subnet",
            root_cause="Missing static route on frr1 for destination 10.2.2.0/24",
            affected_nodes=["frr1"],
            error_category=ErrorCategory.ROUTING_MISCONFIG,
            severity=SeverityLevel.HIGH,
            confidence_score=0.96,
            evidence=["Ping probing returned 100% loss to destination host"],
        )
        plan = RemediationPlan(
            action_type=RemediationActionType.PATCH_CONFIG_FILE,
            target_entity="frr1",
            configuration_patch=ConfigurationPatch(
                file_path="config/frr/frr.conf",
                patch_type="FULL_REPLACE",
                new_content="""hostname frr1
service integrated-vtysh-config
!
interface eth1
 ip address 10.1.1.1/24
!
interface eth2
 ip address 10.1.12.1/24
!
ip route 10.2.2.0/24 10.1.12.2
!
line vty
!
""",
            ),
            expected_outcome="Static route added, routing table restored",
            estimated_risk=SeverityLevel.LOW,
        )
        combo = DiagnosticAndRemediation(diagnostic=diag, remediation=plan)
        mock_llm.register_canned_response(combo)

        # Inject missing route that clears on retry 1
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.2.2.0/24",
                active_until_retry=1,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_missing_route",
            auto_approve=True,
        )

        initial = create_initial_state("Connect hosts with missing route healing", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["verification_results"]["all_passed"] is True

        # Check patched config in validated_topology
        patched_configs = final_state["validated_topology"]["configs"]
        frr_cfg = next(c for c in patched_configs if c["node_name"] == "frr1")
        assert "ip route 10.2.2.0/24" in frr_cfg["content"]

    def test_self_healing_with_exec_commands(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
    ):
        """Test remediation plan executing live commands on container node."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        plan = RemediationPlan(
            action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
            target_entity="frr1",
            configuration_patch=ConfigurationPatch(
                file_path="config/frr/frr.conf",
                patch_type="FULL_REPLACE",
                new_content="hostname frr1\ninterface eth1\n ip address 10.1.1.1/24\n",
            ),
            exec_commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            expected_outcome="Route injected dynamically via vtysh",
            estimated_risk=SeverityLevel.LOW,
        )
        combo = DiagnosticAndRemediation(diagnostic=sample_diagnostic_report, remediation=plan)
        mock_llm.register_canned_response(combo)

        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                active_until_retry=1,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_exec_cmd",
            auto_approve=True,
        )

        initial = create_initial_state("Live exec command healing test", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["remediation_plan"]["exec_commands"] == plan.exec_commands

    def test_self_healing_multi_round_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Test multi-round healing: fault clears only after 2 retries."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        heal_plan = sample_remediation_plan.model_copy(deep=True)
        heal_plan.configuration_patch.new_content = (
            "hostname frr1\ninterface eth1\n ip address 10.1.1.1/24\nip route 10.2.2.0/24 10.1.12.2\n"
        )
        combo1 = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=heal_plan,
        )
        combo2 = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=heal_plan,
        )
        mock_llm.register_canned_response(combo1)
        mock_llm.register_canned_response(combo2)

        # Fault is active until retry 2!
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                active_until_retry=2,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_multi_heal",
            auto_approve=True,
        )

        initial = create_initial_state("Multi-round healing test", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 2
        assert final_state["verification_results"]["all_passed"] is True
