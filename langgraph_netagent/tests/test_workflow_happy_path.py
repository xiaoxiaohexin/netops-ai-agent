"""End-to-End Automated Tests for Happy Path Workflow Execution.

Verifies the complete forward pipeline:
START -> Intent Parsing -> Topology Generation -> Offline Pre-flight Validation
-> Human Approval -> Containerlab Deployment -> Verification Probing -> END (verified).

Checks state progression, audit log chronological ordering, and exported disk artifacts.
"""

from pathlib import Path
import pytest

from langgraph_netagent.llm import MockLLMProvider
from langgraph_netagent.models.intent import (
    IsolationMode,
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    ProtocolType,
    QoSLevel,
)
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import (
    build_network_agent_graph,
    create_memory_saver,
    run_network_agent_workflow,
)
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowHappyPath:
    """Test suite for flawless end-to-end execution across multiple topology variants."""

    def test_standard_three_node_happy_path(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Test complete 3-node host-router-host happy path execution."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        user_intent = "Connect pc1 and pc2 via frr1 router with static routing and verify reachability"
        export_dir = tmp_path / "clab_export_happy"

        final_state = run_network_agent_workflow(
            user_intent=user_intent,
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=export_dir,
            max_retries=3,
            auto_approve=True,
        )

        # 1. State Progression & Status
        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 0
        assert final_state["error_message"] is None
        assert final_state["user_intent"] == user_intent

        # 2. Parsed Intent Contract
        assert final_state["parsed_intent"] is not None
        assert final_state["parsed_intent"]["summary"] == sample_network_intent.summary
        assert len(final_state["parsed_intent"]["nodes"]) == len(sample_network_intent.nodes)

        # 3. Raw and Validated Topology
        assert final_state["raw_topology"] is not None
        assert final_state["validated_topology"] is not None
        assert final_state["raw_topology"] == final_state["validated_topology"]

        # 4. Pre-Flight Validation
        assert final_state["validation_result"] is not None
        assert final_state["validation_result"]["is_valid"] is True
        assert final_state["validation_result"]["checked_items_count"] > 0
        assert len(final_state["validation_result"]["errors"]) == 0

        # 5. Human Approval
        assert final_state["human_approved"] is True

        # 6. Deployment
        assert final_state["deploy_status"] is not None
        assert final_state["deploy_status"]["success"] is True
        assert len(final_state["deploy_status"]["nodes_deployed"]) >= 2

        # 7. Verification Probing Telemetry
        assert final_state["verification_results"] is not None
        assert final_state["verification_results"]["all_passed"] is True
        assert len(final_state["verification_results"]["failures"]) == 0
        assert len(final_state["verification_results"]["ping_results"]) > 0
        for ping in final_state["verification_results"]["ping_results"]:
            assert ping["is_reachable"] is True
            assert ping["loss_pct"] == 0.0

        # 8. Chronological Trace Logs Progression
        logs = final_state["execution_logs"]
        assert len(logs) >= 7
        stages = [log["stage"] for log in logs]
        expected_stages = [
            "init",
            "intent_parsing",
            "topology_generation",
            "offline_validation",
            "human_approval",
            "deployment",
            "verification_probing",
        ]
        for exp in expected_stages:
            assert exp in stages, f"Missing stage '{exp}' in trace logs: {stages}"

        # Verify no error-level logs were emitted in happy path
        for log in logs:
            assert log["level"] != "error", f"Unexpected error in happy path: {log}"
            assert log["level"] != "critical", f"Unexpected critical log: {log}"

        # 9. Filesystem Artifacts & POSIX LF line endings
        assert export_dir.exists()
        topo_files = list(export_dir.glob("*.clab.yml"))
        assert len(topo_files) == 1
        clab_content_bytes = topo_files[0].read_bytes()
        assert b"\r\n" not in clab_content_bytes, "Containerlab topology must have POSIX LF line endings"

        config_files = list(export_dir.rglob("*.conf")) + list(export_dir.rglob("*.sh"))
        assert len(config_files) >= 1
        for cfg in config_files:
            assert b"\r\n" not in cfg.read_bytes(), f"Config file '{cfg}' must have POSIX LF line endings"

    def test_multi_vendor_four_node_happy_path(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ):
        """Test happy path with 4 nodes: Alpine (pc1, pc2), FRR (frr1), SR Linux (srl1)."""
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
            protocols=[ProtocolType.STATIC],
            qos=QoSLevel.HIGH_PRIORITY,
            isolation=IsolationMode.VLAN,
            source_endpoints=["pc1"],
            target_endpoints=["pc2"],
            verification_targets=["pc1 -> pc2 ping"],
        )

        mock_llm.register_canned_response(four_node_intent)
        mock_llm.register_canned_response(full_multi_node_package)

        export_dir = tmp_path / "clab_multi_vendor"
        final_state = run_network_agent_workflow(
            user_intent=four_node_intent.raw_intent,
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=export_dir,
            max_retries=3,
            auto_approve=True,
        )

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 0
        assert final_state["verification_results"]["all_passed"] is True

        # Check nodes deployed
        deployed_nodes = final_state["deploy_status"]["nodes_deployed"]
        assert set(deployed_nodes) == {"pc1", "frr1", "srl1", "pc2"}

        # Verify route tables collected for router nodes
        route_tables = final_state["verification_results"]["route_tables"]
        assert "frr1" in route_tables
        assert "srl1" in route_tables

    def test_happy_path_streaming_step_yields(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Verify graph.stream yields state dictionary at each node step."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_stream",
            auto_approve=True,
        )

        initial = create_initial_state("Streaming happy path test")
        steps = list(app.stream(initial))

        step_node_names = [list(step.keys())[0] for step in steps]
        expected_sequence = [
            "intent_parsing",
            "topology_generation",
            "offline_validation",
            "human_approval",
            "deployment",
            "verification_probing",
        ]
        assert step_node_names == expected_sequence

    def test_happy_path_with_memory_checkpointing(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        checkpoint_state,
    ):
        """Verify execution with a memory checkpointer preserves intermediate state."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        saver = create_memory_saver()
        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_checkpoint",
            checkpointer=saver,
            auto_approve=True,
        )

        initial = create_initial_state("Checkpointed happy path")
        config = {"configurable": {"thread_id": "thread-e2e-happy-1"}}
        final = app.invoke(initial, config=config)

        assert final["status"] == "verified"
        saved = checkpoint_state(saver.get(config))
        assert saved is not None
        assert saved["status"] == "verified"
        assert saved["parsed_intent"] is not None
        assert saved["validated_topology"] is not None
