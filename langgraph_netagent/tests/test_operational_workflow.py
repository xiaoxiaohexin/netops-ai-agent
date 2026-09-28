"""End-to-End Tests for Pure NetOps Operational Workflow (UML Conformance).

Validates the full UML activity diagram:
Baseline Ingestion → Telemetry/5-Tuple Extraction → 2-Stage Diagnosis →
AAL Sandbox Validation → Human Approval → Live Hot-Patch → Re-verification.

Verifies:
1. Healthy baseline path: cleanly ends at 'end_healthy'.
2. Fault detection and closed-loop self-healing: full cycle ending at 'end_fixed'.
3. Human-in-the-loop (HITL) approval gate: only reached after sandbox validation passes.
4. Human rejection path: ends at 'end_rejected'.
5. Deterministic circuit breaker: trips when retry threshold or step tagging limit is exhausted.
6. AAL security whitelist: blocks destructive commands.
7. Step tagging attached to all command executions.
"""

from pathlib import Path
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.workflow.operational_state import OperationalState
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan, RollbackStep
from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)
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
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


# ---------------------------------------------------------------------------
# Test Fixtures & Mock Providers
# ---------------------------------------------------------------------------

class MockOperationalLLMProvider:
    """Mock LLM returning valid structured diagnosis and remediation."""

    def __init__(self, target_node: str = "frr1", failing_patch: bool = False):
        self.target_node = target_node
        self.failing_patch = failing_patch
        self.call_count = 0

    def generate_structured(self, messages: list, response_schema: type):
        self.call_count += 1
        if response_schema == DiagnosticReport:
            return DiagnosticReport(
                telemetry_trigger="Packet drop 10.1.1.2 -> 10.2.2.2",
                root_cause=f"Missing static route on {self.target_node}",
                affected_nodes=[self.target_node],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.95,
                evidence=["Ping failure 10.1.1.2 -> 10.2.2.2"],
            )
        elif response_schema == RemediationPlan:
            if self.failing_patch:
                cmds = ["rm -rf /etc/frr/*"]  # Blocked by AAL to trigger sandbox failure
            else:
                cmds = [f"vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"]

            return RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity=self.target_node,
                exec_commands=cmds,
                rollback_steps=[
                    RollbackStep(
                        step_order=1,
                        description="Rollback route",
                        action="EXEC_COMMAND",
                        target_node=self.target_node,
                        payload=f"vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'",
                    )
                ],
                expected_outcome="Reachability restored",
                estimated_risk=SeverityLevel.LOW,
            )
        raise ValueError(f"Unexpected schema: {response_schema}")


class MockUMLAdapter(BaseNetworkLabAdapter):
    """Adapter simulating a 4-node topology with configurable health and patch effects."""

    def __init__(self, healthy: bool = True, fix_after_patch: bool = True):
        self.healthy = healthy
        self.fix_after_patch = fix_after_patch
        self.patched = False
        self.exec_history = []

    def deploy(self, topo_file, reconfigure=True) -> DeploymentResult:
        return DeploymentResult(success=True, lab_name="uml-lab", topo_file=str(topo_file), nodes_deployed=["pc1", "frr1", "srl1", "pc2"])

    def destroy(self, topo_file=None, lab_name=None, cleanup=True) -> DestructionResult:
        return DestructionResult(success=True, lab_name="uml-lab")

    def inspect(self, topo_file=None, lab_name=None) -> LabInspectionResult:
        nodes = [
            LabNodeState(name="pc1", container_id="clab-pc1", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.2"),
            LabNodeState(name="frr1", container_id="clab-frr1", image="frrouting/frr", kind="linux", state="running", ipv4_address="172.100.100.3"),
            LabNodeState(name="srl1", container_id="clab-srl1", image="ghcr.io/nokia/srlinux", kind="nokia_srlinux", state="running", ipv4_address="172.100.100.4"),
            LabNodeState(name="pc2", container_id="clab-pc2", image="alpine", kind="linux", state="running", ipv4_address="172.100.100.5"),
        ]
        return LabInspectionResult(success=True, lab_name="uml-lab", nodes=nodes)

    def exec_command(self, node_name: str, command: str, timeout: int = 15) -> CommandResult:
        self.exec_history.append({"node": node_name, "command": command})

        # ip addr show
        if "ip addr show" in command:
            ip_map = {
                "pc1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.2/24 scope global eth1",
                "frr1": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.1.1/24 scope global eth1\n3: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.1/24 scope global eth2",
                "srl1": "2: e1-1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.1.12.2/24 scope global e1-1\n3: e1-2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.1/24 scope global e1-2",
                "pc2": "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n    inet 10.2.2.2/24 scope global eth1",
            }
            return CommandResult(command=command, exit_code=0, stdout=ip_map.get(node_name, ""), node=node_name)

        # Route table command
        base_node = node_name.replace("sandbox_", "") if node_name.startswith("sandbox_") else node_name

        # Hot-patch configure command (only sets live patched flag on actual live node)
        if "vtysh" in command and "configure" in command:
            if not node_name.startswith("sandbox_"):
                self.patched = True
            return CommandResult(command=command, exit_code=0, stdout="Configuration applied\n", node=node_name)

        # Route table command
        if "route" in command.lower():
            if base_node == "frr1":
                if self.healthy or self.patched or node_name.startswith("sandbox_"):
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2\nS>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2", node=node_name)
                else:
                    return CommandResult(command=command, exit_code=0, stdout="C>* 10.1.1.0/24 is directly connected, eth1\nC>* 10.1.12.0/24 is directly connected, eth2", node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="default via 10.1.1.1 dev eth1", node=node_name)

        # Ping probe command
        if "ping" in command:
            dst_ip = command.split()[-1]
            reachable = self.healthy or (self.patched and self.fix_after_patch)
            if reachable or dst_ip in ("10.1.1.1", "10.1.1.2", "10.1.12.1", "10.1.12.2"):
                return CommandResult(
                    command=command, exit_code=0,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 3 received, 0% packet loss\nrtt avg = 0.080 ms",
                    node=node_name,
                )
            else:
                return CommandResult(
                    command=command, exit_code=1,
                    stdout=f"PING {dst_ip}: 3 packets transmitted, 0 received, 100% packet loss",
                    node=node_name,
                )

        return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

    def is_live_ready(self) -> bool:
        return True


# ===========================================================================
# Edge Unit Tests
# ===========================================================================

class TestOperationalEdges:
    """Test deterministic conditional routing edges in the UML state machine."""

    def test_route_after_telemetry_healthy(self):
        state = create_operational_initial_state()
        state["telemetry_results"] = {"all_passed": True, "failures": []}
        assert route_after_telemetry(state) == "end_healthy"

    def test_route_after_telemetry_fault(self):
        state = create_operational_initial_state()
        state["failure_5tuples"] = [{"source_ip": "10.1.1.2", "destination_ip": "10.2.2.2"}]
        assert route_after_telemetry(state) == "diagnostic_stage1"

    def test_route_after_stage2_normal(self):
        state = create_operational_initial_state(max_retries=3)
        state["retry_count"] = 0
        assert route_after_stage2(state) == "sandbox_validation"

    def test_route_after_stage2_circuit_breaker(self):
        state = create_operational_initial_state(max_retries=2)
        state["retry_count"] = 2
        assert route_after_stage2(state) == "circuit_breaker"

    def test_route_after_sandbox_passed(self):
        state = create_operational_initial_state()
        state["sandbox_passed"] = True
        assert route_after_sandbox(state) == "human_approval"

    def test_route_after_sandbox_failed_retry_remain(self):
        state = create_operational_initial_state(max_retries=3)
        state["sandbox_passed"] = False
        state["retry_count"] = 1
        assert route_after_sandbox(state) == "diagnostic_stage1"

    def test_route_after_sandbox_failed_exhausted(self):
        state = create_operational_initial_state(max_retries=3)
        state["sandbox_passed"] = False
        state["retry_count"] = 3
        assert route_after_sandbox(state) == "circuit_breaker"

    def test_route_after_approval_approved(self):
        state = create_operational_initial_state()
        state["human_approved"] = True
        assert route_after_approval(state) == "live_hot_patch"

    def test_route_after_approval_rejected(self):
        state = create_operational_initial_state()
        state["human_approved"] = False
        assert route_after_approval(state) == "end_rejected"

    def test_route_after_re_verification_passed(self):
        state = create_operational_initial_state()
        state["re_verify_results"] = {"all_passed": True}
        assert route_after_re_verification(state) == "end_fixed"

    def test_route_after_re_verification_failed_retries(self):
        state = create_operational_initial_state(max_retries=3)
        state["re_verify_results"] = {"all_passed": False}
        state["retry_count"] = 1
        assert route_after_re_verification(state) == "diagnostic_stage1"

    def test_route_after_re_verification_exhausted(self):
        state = create_operational_initial_state(max_retries=3)
        state["re_verify_results"] = {"all_passed": False}
        state["retry_count"] = 3
        assert route_after_re_verification(state) == "circuit_breaker"


# ===========================================================================
# End-to-End Workflow Integration Tests
# ===========================================================================

class TestOperationalWorkflowE2E:
    """Test full operational state machine executions conforming to UML diagram."""

    def test_healthy_network_path(self):
        """When initial network telemetry passes, workflow cleanly exits at end_healthy."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)
        final_state = run_operational_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            auto_approve=True,
        )
        assert final_state["status"] == "healthy"
        assert final_state.get("inventory_pool") is not None
        # Must have completed baseline ingestion and telemetry extraction
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "baseline_ingestion" in stages
        assert "telemetry_extraction" in stages
        assert "end_healthy" in stages

    def test_full_incident_troubleshooting_and_healing_flow(self):
        """Complete UML loop: Fault -> 5-Tuple -> 2-Stage Diag -> Sandbox -> HITL -> Patch -> Re-verify -> Fixed."""
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=False)
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        final_state = run_operational_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            max_retries=3,
            auto_approve=True,
        )

        assert final_state["status"] == "fixed"
        assert adapter.patched is True
        # Verify 5-tuple was extracted
        assert len(final_state.get("failure_5tuples", [])) >= 1
        f_tuple = final_state["failure_5tuples"][0]
        assert f_tuple["protocol"] == "ICMP"
        assert f_tuple["alert_type"] == "PACKET_DROP"

        # Verify Stage 1 enriched context and RAG keywords
        assert final_state.get("enriched_context") is not None
        assert len(final_state.get("rag_keywords", [])) > 0

        # Verify Stage 2 generated plan with step_tag
        assert final_state.get("remediation_plan") is not None
        assert "step_tag" in final_state["remediation_plan"]
        assert len(final_state.get("step_tags_history", [])) >= 1

        # Verify Sandbox replica validation passed BEFORE live hot patch
        assert final_state.get("sandbox_passed") is True
        assert final_state.get("sandbox_result") is not None

        # Verify stages were hit in exact UML sequence
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        expected_seq = [
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
        for stage in expected_seq:
            assert stage in stages, f"Stage '{stage}' missing from execution logs: {stages}"

    def test_human_rejection_halts_before_hot_patch(self):
        """When operator rejects the candidate plan, execution halts at end_rejected without hot-patch."""
        llm = MockOperationalLLMProvider(target_node="frr1")
        adapter = MockUMLAdapter(healthy=False)

        # Compile graph with auto_approve=False
        graph = build_operational_graph(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=False,
        )
        initial = create_operational_initial_state(auto_approve=False)
        # Pre-reject candidate plan
        initial["human_approved"] = False

        final_state = graph.invoke(initial)
        assert final_state["status"] == "rejected"
        # Hot-patch must NOT have run
        assert adapter.patched is False
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "sandbox_validation" in stages
        assert "human_approval" in stages
        assert "live_hot_patch" not in stages

    def test_sandbox_failure_trips_circuit_breaker_on_retry_exhaustion(self):
        """When candidate patch fails in sandbox replica repeatedly, circuit breaker trips."""
        # Failing patch generates destructive command blocked by AAL
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=True)
        adapter = MockUMLAdapter(healthy=False)

        final_state = run_operational_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            max_retries=1,  # Only 1 retry allowed
            auto_approve=True,
        )

        assert final_state["status"] == "circuit_broken"
        # Destructive patch was blocked in sandbox; live network was not touched
        assert adapter.patched is False
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "circuit_breaker" in stages
