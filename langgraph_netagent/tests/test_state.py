"""Unit tests for NetworkAgentState and LogEntry reducer semantics."""

from datetime import datetime
import operator
import pytest
from langgraph_netagent.workflow.state import (
    LogEntry,
    NetworkAgentState,
    create_initial_state,
    create_log_entry,
)


class TestNetworkAgentState:
    """Test suite for NetworkAgentState initialization, schema, and logs."""

    def test_create_initial_state_defaults(self):
        intent = "Deploy 2 Alpine hosts connected by FRR router with OSPF."
        state = create_initial_state(user_intent=intent)

        assert state["user_intent"] == intent
        assert state["parsed_intent"] is None
        assert state["raw_topology"] is None
        assert state["validated_topology"] is None
        assert state["validation_result"] is None
        assert state["human_approved"] is True
        assert state["deploy_status"] is None
        assert state["verification_results"] is None
        assert state["diagnostic_report"] is None
        assert state["remediation_plan"] is None
        assert state["retry_count"] == 0
        assert state["max_retries"] == 3
        assert state["error_message"] is None
        assert state["status"] == "initialized"
        assert len(state["execution_logs"]) == 1
        assert state["execution_logs"][0]["stage"] == "init"

    def test_create_initial_state_manual_approval(self):
        state = create_initial_state(
            user_intent="Test manual approval",
            max_retries=5,
            auto_approve=False,
        )
        assert state["human_approved"] is None
        assert state["max_retries"] == 5

    def test_create_log_entry_attributes(self):
        meta = {"target_node": "pc1", "code": 100}
        log = create_log_entry(
            stage="deployment",
            message="Node pc1 started",
            level="info",
            metadata=meta,
        )
        assert log["stage"] == "deployment"
        assert log["message"] == "Node pc1 started"
        assert log["level"] == "info"
        assert log["metadata"] == meta
        # Verify ISO timestamp can be parsed
        parsed_dt = datetime.fromisoformat(log["timestamp"])
        assert parsed_dt is not None

    def test_log_reducer_operator_add(self):
        """Verify that operator.add correctly appends log entries across state steps."""
        state = create_initial_state(user_intent="Reducer test")
        assert len(state["execution_logs"]) == 1

        update_1 = [create_log_entry("intent_parsing", "Parsed intent")]
        new_logs = operator.add(state["execution_logs"], update_1)
        assert len(new_logs) == 2
        assert new_logs[1]["stage"] == "intent_parsing"

        update_2 = [
            create_log_entry("topology_gen", "Generated lab.clab.yml"),
            create_log_entry("validation", "Validation passed"),
        ]
        final_logs = operator.add(new_logs, update_2)
        assert len(final_logs) == 4
        assert [log["stage"] for log in final_logs] == ["init", "intent_parsing", "topology_gen", "validation"]

    def test_state_typed_dict_keys_completeness(self):
        state = create_initial_state("Full keys check")
        expected_keys = {
            "user_intent",
            "parsed_intent",
            "raw_topology",
            "validated_topology",
            "validation_result",
            "human_approved",
            "deploy_status",
            "verification_results",
            "diagnostic_report",
            "remediation_plan",
            "retry_count",
            "max_retries",
            "error_message",
            "status",
            "execution_logs",
        }
        assert set(state.keys()) == expected_keys
