"""End-to-End Automated Tests for Circuit Breaker Tripping and Anti-Flapping.

Verifies that unrecoverable failures across validation, deployment, and active telemetry
healing correctly increment the monotonic retry counter, divert to the `circuit_breaker` node
when `retry_count >= max_retries`, set status="circuit_broken", emit critical audit logs,
and halt gracefully without infinite loops.
"""

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
    IPAllocation,
)
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import build_network_agent_graph, run_network_agent_workflow
from langgraph_netagent.workflow.nodes import DiagnosticAndRemediation
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowCircuitBreaker:
    """Test suite for safety circuit breaking across all operational stages."""

    def test_circuit_breaker_validation_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Verify circuit breaker trips when pre-flight validation fails continuously."""
        mock_llm.register_canned_response(sample_network_intent)

        # Continually generate broken package with illegal character
        broken_pkg = sample_topology_package.model_copy(deep=True)
        broken_pkg.topology.topology.nodes["bad_node@always_broken"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        for _ in range(5):
            mock_llm.register_canned_response(broken_pkg)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_cb_val",
            auto_approve=True,
        )

        initial = create_initial_state("Persistent validation failure", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] >= 2
        assert "Circuit breaker tripped" in final_state["error_message"]

        # Verify critical audit log
        crit_logs = [
            log for log in final_state["execution_logs"]
            if log["stage"] == "circuit_breaker" and log["level"] == "critical"
        ]
        assert len(crit_logs) == 1
        assert "retry limit exceeded" in crit_logs[0]["message"]

    def test_circuit_breaker_deployment_failure_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Verify circuit breaker trips when Containerlab deployment fails persistently."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        for _ in range(5):
            mock_llm.register_canned_response(combo)

        # Inject permanent deployment failure
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.DEPLOY_FAILURE,
                target_node=None,
                cleared_on_remediation=False,
                error_message="Mock Docker daemon connection refused",
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_cb_deploy",
            auto_approve=True,
        )

        initial = create_initial_state("Persistent deployment failure", max_retries=2)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] >= 2
        assert "Circuit breaker tripped" in final_state["error_message"]

    def test_circuit_breaker_telemetry_healing_exhaustion(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Verify circuit breaker trips when active telemetry healing cannot clear fault."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        for _ in range(6):
            mock_llm.register_canned_response(combo)

        # Inject permanent ping drop that never clears
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                cleared_on_remediation=False,
            )
        )

        export_dir = tmp_path / "clab_cb_heal"
        final_state = run_network_agent_workflow(
            user_intent="Persistent telemetry failure",
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=export_dir,
            max_retries=3,
            auto_approve=True,
        )

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] >= 3
        assert "Circuit breaker tripped" in final_state["error_message"]

    def test_circuit_breaker_zero_retries_configured(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """When max_retries is 0, any validation error trips circuit breaker on first attempt."""
        mock_llm.register_canned_response(sample_network_intent)

        broken_pkg = sample_topology_package.model_copy(deep=True)
        broken_pkg.ip_allocations.append(
            IPAllocation(node_name="frr1", interface_name="eth2", ipv4_address="10.1.1.2/24")
        )
        mock_llm.register_canned_response(broken_pkg)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_cb_zero",
            auto_approve=True,
        )

        initial = create_initial_state("Zero retry circuit break test", max_retries=0)
        final_state = app.invoke(initial)

        assert final_state["status"] == "circuit_broken"
        assert final_state["retry_count"] == 1
        assert "Circuit breaker tripped" in final_state["error_message"]

    def test_circuit_breaker_anti_flapping_bounded_steps(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        sample_diagnostic_report: DiagnosticReport,
        sample_remediation_plan: RemediationPlan,
    ):
        """Verify the anti-flapping guard ensures bounded execution steps without hanging."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        combo = DiagnosticAndRemediation(
            diagnostic=sample_diagnostic_report,
            remediation=sample_remediation_plan,
        )
        for _ in range(10):
            mock_llm.register_canned_response(combo)

        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.1.1.1",
                cleared_on_remediation=False,
            )
        )

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_cb_bound",
            auto_approve=True,
        )

        initial = create_initial_state("Anti-flapping bounded test", max_retries=2)
        # Streaming step count must be strictly bounded
        steps = list(app.stream(initial))

        assert len(steps) < 20, f"Execution flapped with too many steps: {len(steps)}"
        last_step = steps[-1]
        assert "circuit_breaker" in last_step
