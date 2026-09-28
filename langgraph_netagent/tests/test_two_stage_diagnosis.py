"""Unit Tests for Two-Stage Diagnostic Engine & Loop Prevention.

Verifies:
1. Stage 1: Read-only context enrichment without mutating state.
2. Stage 1: RAG keyword inference from 5-tuples and discrepancies.
3. Stage 2: SOP context retrieval and incorporation into remediation plans.
4. Stage 2: Explicit step_tag attachment to commands and iteration history.
5. Loop prevention: Deterministic circuit breaker trip on retry threshold exhaustion.
"""

from pathlib import Path
import pytest

from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sop_retriever import SOPRetriever
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


@pytest.fixture
def deployed_adapter():
    adapter = MockContainerlabAdapter()
    default_clab = Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml"
    if default_clab.exists():
        adapter.deploy(default_clab)
    return adapter


@pytest.fixture
def mock_llm():
    from langgraph_netagent.llm.base import LLMConfig
    config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
    llm = MockLLMProvider(config=config)
    llm.register_canned_response(
        DiagnosticReport(
            telemetry_trigger="Ping failure: pc1 -> 10.2.2.2: 100% loss",
            root_cause="Missing static route to 10.2.2.0/24 on frr1",
            affected_nodes=["frr1"],
            error_category=ErrorCategory.ROUTING_MISCONFIG,
            severity=SeverityLevel.HIGH,
            confidence_score=0.92,
            evidence=["Ping failure"],
        )
    )
    llm.register_canned_response(
        RemediationPlan(
            action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
            target_entity="frr1",
            exec_commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
            rollback_steps=[],
            expected_outcome="Route restored",
            estimated_risk=SeverityLevel.LOW,
        )
    )
    return llm


@pytest.fixture
def nodes(mock_llm, deployed_adapter):
    return create_operational_nodes(
        llm_provider=mock_llm,
        lab_adapter=deployed_adapter,
        auto_approve=True,
    )


class TestTwoStageDiagnosis:
    """Verify strictly separated Stage 1 and Stage 2 diagnostic flow."""

    def test_stage1_read_only_and_keyword_inference(self, nodes):
        state = create_operational_initial_state()
        state["suspect_devices"] = ["frr1"]
        state["node_kinds"] = {"frr1": "frr", "pc1": "linux", "pc2": "linux"}
        state["failure_5tuples"] = [
            {
                "source_ip": "10.1.1.2",
                "destination_ip": "10.2.2.2",
                "protocol": "ICMP",
                "alert_type": "PACKET_DROP",
            }
        ]
        state["discrepancies"] = [
            {
                "node": "frr1",
                "discrepancy_type": "missing_route",
                "target_destination": "10.2.2.0/24",
                "description": "Missing static route on frr1",
            }
        ]

        result = nodes["diagnostic_stage1"](state)
        assert result["status"] == "stage1_enriched"
        assert result["enriched_context"] is not None
        assert "frr1" in result["enriched_context"]["suspect_nodes"]
        # Inferred keywords must include protocol, route, and target
        keywords = result["rag_keywords"]
        assert any("frr" in k for k in keywords)
        assert any("route" in k for k in keywords)
        assert any("10.2.2.0/24" in k for k in keywords)

    def test_stage2_sop_retrieval_and_step_tagging(self, nodes):
        state = create_operational_initial_state(max_retries=3)
        state["suspect_devices"] = ["frr1"]
        state["node_kinds"] = {"frr1": "frr"}
        state["rag_keywords"] = ["frr", "static", "route", "missing_route", "10.2.2.0/24"]
        state["enriched_context"] = {"suspect_nodes": {"frr1": {}}}
        state["retry_count"] = 0

        result = nodes["diagnostic_stage2"](state)
        assert result["status"] == "stage2_plan_generated"
        assert result["current_step_tag"] == "diag_iter_1"
        assert "diag_iter_1" in result["step_tags_history"]
        assert len(result["retrieved_sop"]) >= 1
        assert result["remediation_plan"]["step_tag"] == "diag_iter_1"
        assert result["circuit_breaker_tripped"] is False

    def test_stage2_trips_circuit_breaker_on_retry_exhaustion(self, nodes):
        """When retries exceed max_retries, Stage 2 immediately flags circuit_breaker."""
        state = create_operational_initial_state(max_retries=2)
        state["retry_count"] = 2  # Already at limit
        state["suspect_devices"] = ["frr1"]

        result = nodes["diagnostic_stage2"](state)
        assert result["status"] == "circuit_broken"
        assert result["circuit_breaker_tripped"] is True
        assert any("critical" == log["level"] for log in result["execution_logs"])


class TestSOPRetriever:
    """Verify SOP retrieval based on keywords."""

    def test_retrieve_matching_sop(self):
        retriever = SOPRetriever()
        sops = retriever.retrieve(["frr", "route", "static"])
        assert len(sops) >= 1
        assert sops[0]["sop_id"] == "SOP-ROUTING-001"
        assert "configure terminal" in sops[0]["remediation_template"][0]

    def test_retrieve_interface_sop(self):
        retriever = SOPRetriever()
        sops = retriever.retrieve(["interface", "link", "down"])
        assert len(sops) >= 1
        assert sops[0]["sop_id"] == "SOP-INTERFACE-002"
