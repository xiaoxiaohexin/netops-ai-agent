"""Unit and Integration Tests for ExecutionLogger and Audit Tracing."""

from datetime import datetime, timezone
from enum import Enum
import json
from pathlib import Path
import pytest
from pydantic import BaseModel

from langgraph_netagent.execution_logger import (
    ExecutionLogEntry,
    ExecutionLogger,
    get_execution_logger,
    log_execution,
    safe_serialize,
    wrap_logged_nodes,
)


class SampleEnum(str, Enum):
    ACTIVE = "active"
    STANDBY = "standby"


class SampleModel(BaseModel):
    name: str
    count: int
    enum_val: SampleEnum


class TestSafeSerialize:
    """Tests for safe_serialize converter."""

    def test_primitives(self):
        assert safe_serialize(123) == 123
        assert safe_serialize("hello") == "hello"
        assert safe_serialize(True) is True
        assert safe_serialize(None) is None
        assert safe_serialize(3.14) == 3.14

    def test_datetime_and_path(self, tmp_path: Path):
        now = datetime.now(timezone.utc)
        assert safe_serialize(now) == now.isoformat()
        assert safe_serialize(tmp_path) == str(tmp_path)

    def test_pydantic_model(self):
        m = SampleModel(name="test_node", count=42, enum_val=SampleEnum.ACTIVE)
        res = safe_serialize(m)
        assert res["name"] == "test_node"
        assert res["count"] == 42
        assert res["enum_val"] == "active"

    def test_exception_handling(self):
        exc = ValueError("Invalid interface config")
        res = safe_serialize(exc)
        assert res["error_type"] == "ValueError"
        assert "Invalid interface config" in res["error_message"]

    def test_deep_nesting_truncation(self):
        # Nested dict beyond max_depth 3
        nested = {"l1": {"l2": {"l3": {"l4": "too deep"}}}}
        res = safe_serialize(nested, max_depth=2)
        assert "<Truncated" in str(res["l1"]["l2"])


class TestExecutionLogger:
    """Tests for ExecutionLogger file logging and wrapping."""

    @pytest.fixture
    def custom_logger(self, tmp_path: Path) -> ExecutionLogger:
        log_file = tmp_path / "audit_test.jsonl"
        return ExecutionLogger(log_file=log_file, enabled=True)

    def test_wrap_node_success(self, custom_logger: ExecutionLogger):
        def sample_node(state: dict) -> dict:
            return {"status": "processed", "counter": state.get("counter", 0) + 1}

        wrapped = custom_logger.wrap_node("sample_node", sample_node, module_name="test_workflow")
        input_data = {"counter": 10, "lab_name": "CLOS-5"}
        
        output = wrapped(input_data)
        assert output["status"] == "processed"
        assert output["counter"] == 11

        logs = custom_logger.get_recent_logs()
        assert len(logs) == 1
        entry = logs[0]
        
        # Verify complete required information
        assert entry["node_name"] == "sample_node"
        assert entry["module"] == "test_workflow"
        assert "start_time" in entry
        assert "end_time" in entry
        assert entry["duration_seconds"] >= 0
        assert entry["duration_ms"] >= 0
        assert entry["success"] is True
        assert entry["error"] is None

        # Verify exact input and output capture
        assert entry["input_state"]["counter"] == 10
        assert entry["input_state"]["lab_name"] == "CLOS-5"
        assert entry["output_state_update"]["status"] == "processed"
        assert entry["output_state_update"]["counter"] == 11

    def test_wrap_node_exception(self, custom_logger: ExecutionLogger):
        def failing_node(state: dict) -> dict:
            raise RuntimeError("Hardware link timeout on eth1")

        wrapped = custom_logger.wrap_node("failing_node", failing_node)
        input_data = {"device": "leaf-1", "action": "flap"}

        with pytest.raises(RuntimeError, match="Hardware link timeout"):
            wrapped(input_data)

        logs = custom_logger.get_recent_logs()
        assert len(logs) == 1
        entry = logs[0]
        assert entry["node_name"] == "failing_node"
        assert entry["success"] is False
        assert "Hardware link timeout" in entry["error"]
        assert entry["traceback"] is not None
        assert entry["input_state"]["device"] == "leaf-1"

    def test_trace_decorator(self, custom_logger: ExecutionLogger):
        @custom_logger.trace(module="diagnostic_engine", name="analyze_bottleneck")
        def analyze_bottleneck(vip: str, threshold: float = 0.8) -> dict:
            return {"vip": vip, "bottleneck_detected": threshold > 0.5}

        res = analyze_bottleneck("10.0.0.1", threshold=0.9)
        assert res["bottleneck_detected"] is True

        logs = custom_logger.get_recent_logs()
        assert len(logs) == 1
        entry = logs[0]
        assert entry["node_name"] == "analyze_bottleneck"
        assert entry["module"] == "diagnostic_engine"
        assert entry["input_args"] == ["10.0.0.1"]
        assert entry["input_kwargs"] == {"threshold": 0.9}
        assert entry["output"]["bottleneck_detected"] is True
        assert entry["success"] is True

    def test_tool_execution_logging(self, custom_logger: ExecutionLogger):
        custom_logger.log_tool_execution(
            tool_name="ip_route_show",
            node_name="spine1",
            command="ip route show",
            read_only=True,
            step_tag="step-1",
            success=True,
            exit_code=0,
            output={"routes": ["default via 172.16.0.1"]},
        )

        logs = custom_logger.get_recent_logs()
        assert len(logs) == 1
        entry = logs[0]
        assert entry["module"] == "tools.aal"
        assert entry["node_name"] == "spine1"
        assert entry["function_name"] == "aal_tool:ip_route_show"
        assert entry["input_args"] == ["ip route show"]
        assert entry["output"]["routes"] == ["default via 172.16.0.1"]

    def test_clear_logs(self, custom_logger: ExecutionLogger):
        custom_logger.log({"test": "entry"})
        assert len(custom_logger.get_recent_logs()) == 1
        custom_logger.clear_logs()
        assert len(custom_logger.get_recent_logs()) == 0


class TestWorkflowIntegration:
    """Verify that operational and day2 node factories record input and output."""

    def test_operational_nodes_logging_integration(self, tmp_path: Path):
        test_log_file = tmp_path / "op_logs.jsonl"
        logger = get_execution_logger()
        logger.configure(log_file=test_log_file)
        logger.clear_logs()

        from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
        from langgraph_netagent.workflow.operational_state import create_operational_initial_state
        from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
        from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter

        nodes = create_operational_nodes(
            llm_provider=MockLLMProvider(),
            lab_adapter=MockContainerlabAdapter(),
        )

        state = create_operational_initial_state()
        state["initial_alerts"] = ["BGP neighbor down"]

        # Call end_rejected node as a quick unit test
        state_update = nodes["end_rejected"](state)
        assert state_update["status"] == "rejected"

        # Check that JSONL file contains the entry with both input_state and output_state_update
        logs = logger.get_recent_logs()
        assert len(logs) >= 1
        matched = next(l for l in logs if l["node_name"] == "end_rejected")
        assert matched["input_state"]["initial_alerts"] == ["BGP neighbor down"]
        assert matched["output_state_update"]["status"] == "rejected"
        assert matched["success"] is True
        assert "start_time" in matched
        assert "end_time" in matched
