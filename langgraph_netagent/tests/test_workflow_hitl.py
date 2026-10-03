"""End-to-End Automated Tests for Human-in-the-Loop (HITL) Workflow Interruption.

Verifies operator approval gates before deployment:
- Auto-approval execution path.
- Operator explicit rejection halting deployment and setting status="rejected".
- State persistence and checkpointed resumption across operator approval pauses.
"""

from pathlib import Path
import pytest

from langgraph_netagent.llm import MockLLMProvider
from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import (
    build_network_agent_graph,
    create_memory_saver,
    run_network_agent_workflow,
)
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowHumanInTheLoop:
    """Test suite for human approval checkpointing, operator rejection, and state resumption."""

    def test_hitl_auto_approval_enabled(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """When auto_approve is True, approval gate automatically passes without pause."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        final_state = run_network_agent_workflow(
            user_intent="Connect pc1 and pc2 with auto-approval",
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_hitl_auto",
            auto_approve=True,
        )

        assert final_state["status"] == "verified"
        assert final_state["human_approved"] is True
        assert final_state["deploy_status"]["success"] is True

        approval_logs = [log for log in final_state["execution_logs"] if log["stage"] == "human_approval"]
        assert len(approval_logs) == 1
        assert "approved by operator" in approval_logs[0]["message"].lower()

    def test_hitl_rejection_halts_deployment(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """When human operator rejects, execution halts immediately and deployment is bypassed."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_hitl_reject",
            auto_approve=False,
        )

        # Initialize with human_approved explicitly set to False
        initial = create_initial_state("Connect hosts with operator rejection", auto_approve=False)
        initial["human_approved"] = False

        final_state = app.invoke(initial)

        assert final_state["status"] == "rejected"
        assert final_state["human_approved"] is False
        assert final_state["deploy_status"] is None
        assert final_state["verification_results"] is None

        # Verify deployment was NEVER called on the adapter
        assert mock_adapter._deployed is False

        # Verify rejection audit log
        reject_logs = [
            log for log in final_state["execution_logs"]
            if log["stage"] == "human_approval" and log["level"] == "warning"
        ]
        assert len(reject_logs) == 1
        assert "rejected by operator" in reject_logs[0]["message"].lower()

    def test_hitl_pending_pause_checkpoint_and_resume(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
        checkpoint_state,
    ):
        """Test two-stage flow: graph pauses at human_approval, checkpointer saves, resumes upon approval."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        saver = create_memory_saver()
        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_hitl_resume",
            checkpointer=saver,
            auto_approve=False,
        )

        config = {"configurable": {"thread_id": "thread-hitl-pause-01"}}

        # Stage 1: Invoke without pre-approval
        initial = create_initial_state("Interactive approval session", auto_approve=False)
        assert initial["human_approved"] is None

        paused_state = app.invoke(initial, config=config)

        # Graph paused at approval stage
        assert paused_state["status"] == "pending_approval"
        assert paused_state["human_approved"] is None
        assert paused_state["deploy_status"] is None
        assert mock_adapter._deployed is False

        # Verify state stored in checkpointer
        saved_checkpoint = checkpoint_state(saver.get(config))
        assert saved_checkpoint is not None
        assert saved_checkpoint["status"] == "pending_approval"
        assert saved_checkpoint["validated_topology"] is not None

        # Stage 2: Operator grants approval and resumes workflow
        resumed_input = dict(saved_checkpoint)
        resumed_input["human_approved"] = True

        completed_state = app.invoke(resumed_input, config=config)

        # Graph continued through deployment and telemetry probing
        assert completed_state["status"] == "verified"
        assert completed_state["human_approved"] is True
        assert completed_state["deploy_status"]["success"] is True
        assert completed_state["verification_results"]["all_passed"] is True
        assert mock_adapter._deployed is True

    def test_hitl_circuit_breaker_on_retry_exhaustion_unapproved(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """When retries are already exhausted before approval, route_after_approval trips circuit breaker."""
        mock_llm.register_canned_response(sample_network_intent)
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_hitl_cb",
            auto_approve=False,
        )

        initial = create_initial_state("Exhausted retries before approval", max_retries=2, auto_approve=False)
        initial["retry_count"] = 2  # Already at max_retries!
        initial["human_approved"] = None

        final_state = app.invoke(initial)
        # Should divert to circuit_breaker because retry_count >= max_retries
        assert final_state["status"] == "circuit_broken"
