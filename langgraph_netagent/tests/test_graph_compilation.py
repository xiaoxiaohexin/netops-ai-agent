"""Integration tests for StateGraph compilation and closed-loop execution."""

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
    ContainerlabNodeConfig,
    FullTopologyPackage,
)
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import (
    END,
    START,
    SimpleMemorySaver,
    SimpleStateGraph,
    build_network_agent_graph,
    run_network_agent_workflow,
)
from langgraph_netagent.workflow.nodes import DiagnosticAndRemediation
from langgraph_netagent.workflow.state import create_initial_state, create_log_entry


class TestSimpleStateGraphEngine:
    """Test suite for the self-contained SimpleStateGraph engine and memory checkpointer."""

    def test_simple_state_graph_basic_flow(self):
        graph = SimpleStateGraph()
        graph.add_node("step_a", lambda s: {"status": "in_a", "execution_logs": [create_log_entry("a", "In A")]})
        graph.add_node("step_b", lambda s: {"status": "in_b", "execution_logs": [create_log_entry("b", "In B")]})
        graph.add_edge(START, "step_a")
        graph.add_edge("step_a", "step_b")
        graph.add_edge("step_b", END)

        saver = SimpleMemorySaver()
        compiled = graph.compile(checkpointer=saver)

        initial = create_initial_state("Basic test")
        config = {"configurable": {"thread_id": "session-1"}}
        result = compiled.invoke(initial, config=config)

        assert result["status"] == "in_b"
        assert len(result["execution_logs"]) == 3  # init + step_a + step_b
        # Checkpointer verification
        saved = saver.get(config)
        assert saved is not None
        assert saved["status"] == "in_b"

    def test_simple_state_graph_conditional_routing(self):
        graph = SimpleStateGraph()
        graph.add_node("check", lambda s: {"val": s.get("input_val", 0)})
        graph.add_node("branch_high", lambda s: {"status": "high"})
        graph.add_node("branch_low", lambda s: {"status": "low"})

        graph.set_entry_point("check")
        graph.add_conditional_edges(
            "check",
            lambda s: "high" if s.get("val", 0) > 10 else "low",
            {"high": "branch_high", "low": "branch_low"},
        )
        graph.add_edge("branch_high", END)
        graph.add_edge("branch_low", END)

        compiled = graph.compile()

        res_high = compiled.invoke({"input_val": 100})
        assert res_high["status"] == "high"

        res_low = compiled.invoke({"input_val": 5})
        assert res_low["status"] == "low"

    def test_simple_state_graph_streaming(self):
        graph = SimpleStateGraph()
        graph.add_node("first", lambda s: {"stage_1": True})
        graph.add_node("second", lambda s: {"stage_2": True})
        graph.add_edge(START, "first")
        graph.add_edge("first", "second")
        graph.add_edge("second", END)

        compiled = graph.compile()
        steps = list(compiled.stream({"init": True}))

        assert len(steps) == 2
        assert "first" in steps[0]
        assert "second" in steps[1]


class TestNetworkAgentClosedLoopExecution:
    """End-to-end integration tests for the full 8-node state machine and closed loops."""

    def test_happy_path_workflow(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Verify: START -> Intent -> Topology -> Validation -> Approval -> Deploy -> Verify -> END."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Connect pc1 and pc2 via frr1")
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["parsed_intent"] is not None
        assert final_state["raw_topology"] is not None
        assert final_state["validated_topology"] is not None
        assert final_state["validation_result"]["is_valid"] is True
        assert final_state["human_approved"] is True
        assert final_state["deploy_status"]["success"] is True
        assert final_state["verification_results"]["all_passed"] is True
        assert final_state["retry_count"] == 0

    def test_validation_failure_recovery_loop(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Verify: Validation failure loops back to topology_generation with feedback and recovers."""
        mock_llm.register_canned_response(sample_network_intent)

        # 1st topology generation: bad node name triggering validation failure
        bad_pkg = sample_topology_package.model_copy(deep=True)
        bad_pkg.topology.topology.nodes["bad_node@error"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        mock_llm.register_canned_response(bad_pkg)

        # 2nd topology generation: clean topology package
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Connect hosts with initial failure", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        # 1 validation retry was consumed
        assert final_state["retry_count"] == 1
        assert final_state["verification_results"]["all_passed"] is True

    def test_self_healing_telemetry_loop(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Verify: Probing failure triggers diagnosis_and_healing, patches config, redeploys and passes."""
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

        # Inject ping drop that clears after 1 retry
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
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Connect hosts with self-healing", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["diagnostic_report"] is not None
        assert final_state["remediation_plan"] is not None

    def test_circuit_breaker_trips_on_retry_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Verify: Unrecoverable failures exhaust retries and trip the circuit breaker gracefully."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        # Register enough canned remediation responses for retries
        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        for _ in range(5):
            mock_llm.register_canned_response(combo)

        # Inject permanent deployment failure (cleared_on_remediation=False)
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.DEPLOY_FAILURE,
                target_node=None,
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            auto_approve=True,
        )

        initial = create_initial_state("Failing deployment", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] >= 2
        assert "Circuit breaker tripped" in final_state["error_message"]

    def test_run_network_agent_workflow_convenience_function(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        result = run_network_agent_workflow(
            user_intent="Convenience workflow runner test",
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path,
            max_retries=3,
            auto_approve=True,
        )

        assert result["status"] == "verified"
        assert result["verification_results"]["all_passed"] is True
