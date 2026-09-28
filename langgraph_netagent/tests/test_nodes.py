"""Unit tests for the 8 discrete LangGraph workflow nodes."""

from pathlib import Path
import pytest

from langgraph_netagent.llm import MockLLMProvider
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    FullTopologyPackage,
)
from langgraph_netagent.tools.exporter import TopologyExporter
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.nodes import DiagnosticAndRemediation, create_workflow_nodes
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowNodes:
    """Test suite exercising each discrete workflow node callable."""

    def test_intent_parsing_node_success(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
    ):
        mock_llm.register_canned_response(sample_network_intent)
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Connect pc1 and pc2 via frr1")
        output = nodes["intent_parsing"](state)

        assert output["status"] == "intent_parsed"
        assert output["parsed_intent"] is not None
        assert output["parsed_intent"]["intent_id"] == sample_network_intent.intent_id
        assert len(output["execution_logs"]) == 1
        assert output["execution_logs"][0]["stage"] == "intent_parsing"

    def test_intent_parsing_node_failure(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
    ):
        # Force LLM exception by registering a runtime error response
        mock_llm.register_canned_response(RuntimeError("LLM API connection timeout"))
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Malformed prompt")
        output = nodes["intent_parsing"](state)

        assert output["status"] == "intent_parsing_failed"
        assert "timeout" in output["error_message"].lower()

    def test_topology_generation_node_with_validation_feedback(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        mock_llm.register_canned_response(sample_topology_package)
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        # Simulate state with previous validation errors
        state = create_initial_state("Generate lab")
        state["validation_result"] = {
            "is_valid": False,
            "errors": [
                {
                    "code": "IP_COLLISION",
                    "node": "pc1",
                    "field": "ip_allocations",
                    "message": "Duplicate IP 10.1.1.1",
                    "suggested_fix": "Change IP on pc1 to 10.1.1.2",
                }
            ],
        }

        output = nodes["topology_generation"](state)

        assert output["status"] == "topology_generated"
        assert output["raw_topology"] is not None
        assert output["raw_topology"]["topology"]["name"] == sample_topology_package.topology.name

    def test_offline_validation_node_passed(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Validate healthy")
        state["raw_topology"] = sample_topology_package.model_dump()

        output = nodes["offline_validation"](state)

        assert output["status"] == "validation_passed"
        assert output["validation_result"]["is_valid"] is True
        assert output["validated_topology"] is not None

    def test_offline_validation_node_failed_increments_retry(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        # Inject invalid node name into raw_topology
        bad_pkg = sample_topology_package.model_copy(deep=True)
        bad_pkg.topology.topology.nodes["invalid_name!"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )

        state = create_initial_state("Validate faulty")
        state["raw_topology"] = bad_pkg.model_dump()
        state["retry_count"] = 0

        output = nodes["offline_validation"](state)

        assert output["status"] == "validation_failed"
        assert output["validation_result"]["is_valid"] is False
        assert output["retry_count"] == 1
        assert output["error_message"] is not None

    def test_human_approval_node_modes(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
    ):
        # 1. Auto-approve True
        nodes_auto = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )
        state_auto = create_initial_state("Auto approve", auto_approve=True)
        out_auto = nodes_auto["human_approval"](state_auto)
        assert out_auto["human_approved"] is True
        assert out_auto["status"] == "approved"

        # 2. Auto-approve False (HITL pause)
        nodes_manual = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=False,
        )
        state_manual = create_initial_state("Manual approve", auto_approve=False)
        out_manual = nodes_manual["human_approval"](state_manual)
        assert out_manual["human_approved"] is None
        assert out_manual["status"] == "pending_approval"

        # 3. Explicit operator rejection
        state_rejected = create_initial_state("Rejected")
        state_rejected["human_approved"] = False
        out_rejected = nodes_auto["human_approval"](state_rejected)
        assert out_rejected["human_approved"] is False
        assert out_rejected["status"] == "rejected"

    def test_deployment_node_success(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Deploy lab")
        state["validated_topology"] = sample_topology_package.model_dump()

        output = nodes["deployment"](state)

        assert output["status"] == "deployed"
        assert output["deploy_status"]["success"] is True

    def test_deployment_node_failure(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        # Inject deployment failure into mock adapter
        mock_adapter.fault_injector.add_rule(
            FaultRule(fault_type=FaultType.DEPLOY_FAILURE, target_node=None)
        )
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Deploy lab failure")
        state["validated_topology"] = sample_topology_package.model_dump()
        state["retry_count"] = 0

        output = nodes["deployment"](state)

        assert output["status"] == "deployment_failed"
        assert output["retry_count"] == 1
        assert "deploy failure" in output["error_message"].lower()

    def test_verification_probing_node_healthy(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        exporter = TopologyExporter()
        written = exporter.export(package=sample_topology_package, export_dir=tmp_path)
        topo_file = next(p for rel, p in written.items() if str(rel).endswith(".clab.yml"))
        mock_adapter.deploy(topo_file=topo_file)

        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Verify healthy")
        state["validated_topology"] = sample_topology_package.model_dump()
        state["parsed_intent"] = {
            "verification_targets": ["pc1 -> 10.1.1.1 ping"]
        }

        output = nodes["verification_probing"](state)

        assert output["status"] == "verified"
        assert output["verification_results"]["all_passed"] is True

    def test_verification_probing_node_detects_ping_drop(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
    ):
        exporter = TopologyExporter()
        written = exporter.export(package=sample_topology_package, export_dir=tmp_path)
        topo_file = next(p for rel, p in written.items() if str(rel).endswith(".clab.yml"))
        mock_adapter.deploy(topo_file=topo_file)

        # Inject 100% ping packet drop
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
            )
        )

        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Verify with packet drop")
        state["validated_topology"] = sample_topology_package.model_dump()
        state["parsed_intent"] = {
            "verification_targets": ["pc1 -> 10.1.1.1 ping"]
        }

        output = nodes["verification_probing"](state)

        assert output["status"] == "verification_failed"
        assert output["verification_results"]["all_passed"] is False
        assert len(output["verification_results"]["failures"]) > 0

    def test_diagnosis_and_healing_node_patches_config(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        mock_llm.register_canned_response(combo)

        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Heal fault")
        state["validated_topology"] = sample_topology_package.model_dump()
        state["verification_results"] = {
            "all_passed": False,
            "failures": ["Ping failure: pc1 -> 10.2.2.2: 100% loss"],
        }
        state["retry_count"] = 0

        output = nodes["diagnosis_and_healing"](state)

        assert output["status"] == "healed"
        assert output["retry_count"] == 1
        assert output["diagnostic_report"] is not None
        assert output["remediation_plan"] is not None
        # Verify the configuration patch was applied to validated_topology
        patched_configs = output["validated_topology"]["configs"]
        frr_cfg = next(c for c in patched_configs if c["node_name"] == "frr1")
        assert "ip route 10.2.2.0/24 10.1.12.2" in frr_cfg["content"]

    def test_circuit_breaker_node(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
    ):
        nodes = create_workflow_nodes(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
        )

        state = create_initial_state("Exhausted retries", max_retries=3)
        state["retry_count"] = 3

        output = nodes["circuit_breaker"](state)

        assert output["status"] == "circuit_broken"
        assert "Circuit breaker tripped" in output["error_message"]
        assert len(output["execution_logs"]) == 1
        assert output["execution_logs"][0]["level"] == "critical"
