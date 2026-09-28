"""Unit and integration tests for Milestone 2: Telemetry Extraction & Anomaly Classification.

Validates:
1. OperationalState schema additions: anomaly_classification initialized to None.
2. classify_anomaly function:
   - external_overload detection on buffer overlimits, queue drops, and volumetric overload.
   - single_exit_failure detection on missing routes and interface down.
   - internal_link_failure detection on adjacent hop reachability drops.
   - healthy classification when all checks pass.
3. telemetry_extraction_node:
   - Healthy network extraction -> category="healthy", all_passed=True, status="healthy".
   - Missing route discrepancy -> category="single_exit_failure", status="fault_detected".
   - Injected buffer overlimits fault -> category="external_overload", 5-tuple extracted,
     discrepancy populated with severity="critical", bottleneck suspect included,
     status="fault_detected".
4. route_after_telemetry conditional routing:
   - Routes to diagnostic_stage1 when buffer overlimits are detected.
   - Routes to end_healthy when network baseline is healthy.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock
import pytest

from langgraph_netagent.models.operational import (
    AnomalyClassification,
    FiveTuple,
    NetworkDiscrepancy,
)
from langgraph_netagent.models.telemetry import (
    NetworkHealthReport,
    PingTelemetry,
    QdiscTelemetry,
    RouteEntry,
)
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.workflow.operational_edges import route_after_telemetry
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)


# ==============================================================================
# 1. OperationalState Schema & Initialization Tests
# ==============================================================================

class TestOperationalStateSchema:
    """Tests for anomaly_classification state field initialization."""

    def test_state_initialization_contains_anomaly_classification(self) -> None:
        state = create_operational_initial_state(max_retries=3, auto_approve=True)
        assert "anomaly_classification" in state
        assert state["anomaly_classification"] is None

    def test_state_typed_dict_annotations(self) -> None:
        annotations = OperationalState.__annotations__
        assert "anomaly_classification" in annotations


# ==============================================================================
# 2. classify_anomaly Function Unit Tests
# ==============================================================================

class TestClassifyAnomalyFunction:
    """Comprehensive decision matrix tests for classify_anomaly."""

    def test_classify_healthy_network(self) -> None:
        report = NetworkHealthReport(all_passed=True)
        result = classify_anomaly(
            report=report,
            discrepancies=[],
            failure_5tuples=[],
            inventory={},
        )
        assert isinstance(result, AnomalyClassification)
        assert result.category == "healthy"
        assert result.confidence == 1.0
        assert "healthy baselines" in result.reason
        assert result.recommended_action == "No remediation needed"
        assert result.bottleneck_node is None

    def test_classify_external_overload_from_buffer_anomaly(self) -> None:
        report = NetworkHealthReport(
            all_passed=False,
            buffer_anomalies=[
                {
                    "node": "dc-egress",
                    "interface": "eth2",
                    "dropped": 4200,
                    "overlimits": 18000,
                }
            ],
        )
        ft = FiveTuple.from_traffic_overload(
            src_ip="192.168.100.2",
            dst_ip="203.0.113.10",
            protocol="TCP",
            dst_port=80,
            overlimits=18000,
            dropped=4200,
        )
        disc = NetworkDiscrepancy(
            node="dc-egress",
            discrepancy_type="buffer_overlimit",
            affected_interface="eth2",
            description="Qdisc queue overflow",
            suspect_nodes=["dc-egress"],
        )

        result = classify_anomaly(
            report=report,
            discrepancies=[disc],
            failure_5tuples=[ft],
            inventory={},
        )
        assert result.category == "external_overload"
        assert result.confidence >= 0.9
        assert result.bottleneck_node == "dc-egress"
        assert result.bottleneck_interface == "eth2"
        assert result.offending_source_ip == "192.168.100.2"
        assert result.victim_destination_ip == "203.0.113.10"
        assert "iptables" in result.recommended_action

    def test_classify_external_overload_with_dicts(self) -> None:
        discrepancies = [
            {
                "node": "dc-egress",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth2",
                "description": "Buffer drop",
            }
        ]
        failure_5tuples = [
            {
                "source_ip": "192.168.100.2",
                "destination_ip": "203.0.113.10",
                "alert_type": "TRAFFIC_OVERLOAD",
                "is_external_overload": True,
            }
        ]
        result = classify_anomaly(
            report={"all_passed": False, "buffer_anomalies": []},
            discrepancies=discrepancies,
            failure_5tuples=failure_5tuples,
        )
        assert result.category == "external_overload"
        assert result.bottleneck_node == "dc-egress"
        assert result.offending_source_ip == "192.168.100.2"

    def test_classify_single_exit_failure_missing_route(self) -> None:
        disc = NetworkDiscrepancy(
            node="frr1",
            discrepancy_type="missing_route",
            target_destination="10.2.2.0/24",
            description="frr1 lacks route to 10.2.2.0/24",
            suspect_nodes=["frr1"],
        )
        result = classify_anomaly(
            report=None,
            discrepancies=[disc],
            failure_5tuples=[],
            inventory={},
        )
        assert result.category == "single_exit_failure"
        assert result.confidence >= 0.9
        assert result.bottleneck_node == "frr1"
        assert result.victim_destination_ip == "10.2.2.0/24"
        assert "route" in result.recommended_action

    def test_classify_single_exit_failure_interface_down(self) -> None:
        disc = NetworkDiscrepancy(
            node="ext-router",
            discrepancy_type="interface_down",
            affected_interface="eth1",
            description="Interface eth1 is DOWN",
            suspect_nodes=["ext-router"],
        )
        result = classify_anomaly(
            report=None,
            discrepancies=[disc],
            failure_5tuples=[],
            inventory={},
        )
        assert result.category == "single_exit_failure"
        assert result.bottleneck_node == "ext-router"
        assert result.bottleneck_interface == "eth1"

    def test_classify_internal_link_failure(self) -> None:
        disc = NetworkDiscrepancy(
            node="leaf1",
            discrepancy_type="reachability_loss",
            target_destination="spine1",
            description="Adjacent link drop between leaf1 and spine1",
            suspect_nodes=["leaf1", "spine1"],
        )
        result = classify_anomaly(
            report=None,
            discrepancies=[disc],
            failure_5tuples=[],
            inventory={},
        )
        assert result.category == "internal_link_failure"
        assert result.confidence == 0.85
        assert result.bottleneck_node == "leaf1"
        assert "link" in result.recommended_action


# ==============================================================================
# 3. Telemetry Extraction Node Integration Tests
# ==============================================================================

class TestTelemetryExtractionNodeIntegration:
    """Integration tests for telemetry_extraction_node under various scenarios."""

    @pytest.fixture
    def test_env(self) -> Dict[str, Any]:
        """Build a mock adapter with healthy Clos topology."""
        adapter = MockContainerlabAdapter()
        g = adapter.mock_engine.graph

        # Add PC1
        pc1 = VirtualNode(name="pc1", kind="linux")
        g.add_node(pc1)

        # Add Router
        gw1 = VirtualNode(name="gw1", kind="frr")
        g.add_node(gw1)

        # Add PC2
        pc2 = VirtualNode(name="pc2", kind="linux")
        g.add_node(pc2)

        g.register_ip("10.1.1.2/24", "pc1", "eth1")
        g.register_ip("10.1.1.1/24", "gw1", "eth1")
        g.register_ip("10.2.2.1/24", "gw1", "eth2")
        g.register_ip("10.2.2.2/24", "pc2", "eth1")

        g.add_link("pc1", "eth1", "gw1", "eth1")
        g.add_link("gw1", "eth2", "pc2", "eth1")

        pc1.add_route(RouteEntry(destination="default", next_hop="10.1.1.1", interface="eth1", protocol="static"))
        pc2.add_route(RouteEntry(destination="default", next_hop="10.2.2.1", interface="eth1", protocol="static"))
        gw1.add_route(RouteEntry(destination="10.1.1.0/24", next_hop=None, interface="eth1", protocol="connected"))
        gw1.add_route(RouteEntry(destination="10.2.2.0/24", next_hop=None, interface="eth2", protocol="connected"))

        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
        )

        base_state = create_operational_initial_state()
        base_state["topology_path"] = ["pc1", "gw1", "pc2"]
        base_state["node_kinds"] = {"pc1": "linux", "gw1": "frr", "pc2": "linux"}
        base_state["baseline"] = {
            "nodes": {
                "pc1": {"ip_addr": "2: eth1: inet 10.1.1.2/24"},
                "gw1": {"ip_addr": "2: eth1: inet 10.1.1.1/24\n3: eth2: inet 10.2.2.1/24"},
                "pc2": {"ip_addr": "2: eth1: inet 10.2.2.2/24"},
            }
        }
        base_state["inventory_pool"] = {
            "subnets": ["10.1.1.0/24", "10.2.2.0/24"],
            "ip_to_node": {"10.1.1.2": "pc1", "10.2.2.2": "pc2", "10.1.1.1": "gw1", "10.2.2.1": "gw1"},
        }

        return {
            "adapter": adapter,
            "nodes": nodes,
            "state": base_state,
        }

    def test_healthy_network_telemetry_extraction(self, test_env: Dict[str, Any]) -> None:
        """Healthy network telemetry returns category='healthy', all_passed=True, status='healthy'."""
        nodes = test_env["nodes"]
        state = test_env["state"]

        result = nodes["telemetry_extraction"](state)

        assert result["status"] == "healthy"
        assert result["telemetry_results"]["all_passed"] is True
        assert len(result["discrepancies"]) == 0
        assert len(result["failure_5tuples"]) == 0

        # Anomaly classification must be healthy
        classification = result.get("anomaly_classification")
        assert classification is not None
        assert classification["category"] == "healthy"
        assert classification["confidence"] == 1.0

        # Execution log entry verification
        logs = result["execution_logs"]
        assert len(logs) >= 1
        assert "anomaly_category='healthy'" in logs[0]["message"]
        assert logs[0]["level"] == "info"

        # Edge routing verification: must route to end_healthy
        updated_state = dict(state)
        updated_state.update(result)
        decision = route_after_telemetry(updated_state)
        assert decision == "end_healthy"

    def test_missing_route_discrepancy_classification(self, test_env: Dict[str, Any]) -> None:
        """Missing route discrepancy is extracted and classified as 'single_exit_failure'."""
        adapter = test_env["adapter"]
        nodes = test_env["nodes"]
        state = test_env["state"]

        # Mock adapter returning route table lacking 10.2.2.0/24
        def mock_exec(node_name: str, command: str, timeout: int = 15) -> CommandResult:
            if "route" in command:
                return CommandResult(
                    command=command,
                    exit_code=0,
                    stdout="C>* 10.1.1.0/24 is directly connected, eth1",
                    node=node_name,
                )
            if "ping" in command:
                return CommandResult(command=command, exit_code=1, stdout="100% packet loss", node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

        adapter.exec_command = mock_exec

        result = nodes["telemetry_extraction"](state)

        assert result["status"] == "fault_detected"
        discrepancies = result["discrepancies"]
        assert any(d["discrepancy_type"] == "missing_route" for d in discrepancies)

        classification = result["anomaly_classification"]
        assert classification["category"] == "single_exit_failure"
        assert classification["bottleneck_node"] == "gw1"

        updated_state = dict(state)
        updated_state.update(result)
        assert route_after_telemetry(updated_state) == "diagnostic_stage1"

    def test_injected_buffer_overlimits_fault(self, test_env: Dict[str, Any]) -> None:
        """Buffer overlimits fault injection triggers external_overload classification and 5-tuple extraction."""
        adapter = test_env["adapter"]
        nodes = test_env["nodes"]
        state = test_env["state"]

        # Inject BUFFER_OVERLIMIT rule
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="gw1",
            target_interface="eth1",
            overlimits=18000,
            dropped=4200,
            source_ip="192.168.100.2",
            dest_port=80,
        )
        adapter.fault_injector.add_rule(rule)

        result = nodes["telemetry_extraction"](state)

        # 1. Status must be fault_detected
        assert result["status"] == "fault_detected"

        # 2. NetworkDiscrepancy populated
        discrepancies = result["discrepancies"]
        buffer_disc = [d for d in discrepancies if d["discrepancy_type"] == "buffer_overlimit"]
        assert len(buffer_disc) >= 1
        assert buffer_disc[0]["node"] == "gw1"
        assert buffer_disc[0]["affected_interface"] == "eth1"
        assert buffer_disc[0].get("severity") == "critical"

        # 3. FiveTuple extracted
        failure_5tuples = result["failure_5tuples"]
        overload_ft = [ft for ft in failure_5tuples if ft.get("alert_type") == "TRAFFIC_OVERLOAD"]
        assert len(overload_ft) >= 1
        top_ft = overload_ft[0]
        assert top_ft["source_ip"] == "192.168.100.2"
        assert top_ft["destination_port"] == 80
        assert top_ft["overlimits_count"] == 18000
        assert top_ft["dropped_packets"] == 4200
        assert top_ft["is_external_overload"] is True

        # 4. Suspect devices includes bottleneck router
        assert "gw1" in result["suspect_devices"]

        # 5. Anomaly classification
        classification = result["anomaly_classification"]
        assert classification["category"] == "external_overload"
        assert classification["confidence"] >= 0.9
        assert classification["bottleneck_node"] == "gw1"
        assert classification["bottleneck_interface"] == "eth1"
        assert classification["offending_source_ip"] == "192.168.100.2"

        # 6. Log entry
        logs = result["execution_logs"]
        assert any("anomaly_category='external_overload'" in log["message"] for log in logs)

        # 7. Edge routing
        updated_state = dict(state)
        updated_state.update(result)
        decision = route_after_telemetry(updated_state)
        assert decision == "diagnostic_stage1"

    def test_injected_buffer_overlimits_on_dc_egress(self) -> None:
        """Buffer overlimits on dc-egress gateway triggers external_overload classification and VIP extraction."""
        adapter = MockContainerlabAdapter()
        g = adapter.mock_engine.graph

        dc_egress = VirtualNode(name="dc-egress", kind="linux")
        g.add_node(dc_egress)
        g.register_ip("203.0.113.1/24", "dc-egress", "eth1")
        g.register_ip("192.168.100.1/24", "dc-egress", "eth2")

        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            target_interface="eth2",
            overlimits=25000,
            dropped=5500,
            source_ip="192.168.100.2",
            dest_port=80,
        )
        adapter.fault_injector.add_rule(rule)

        nodes = create_operational_nodes(llm_provider=MagicMock(), lab_adapter=adapter)
        state = create_operational_initial_state()
        state["topology_path"] = ["dc-egress"]
        state["node_kinds"] = {"dc-egress": "linux"}
        state["baseline"] = {
            "nodes": {
                "dc-egress": {"ip_addr": "2: eth1: inet 203.0.113.1/24\n3: eth2: inet 192.168.100.1/24"}
            }
        }
        state["inventory_pool"] = {
            "subnets": ["203.0.113.0/24", "192.168.100.0/24"],
            "ip_to_node": {"203.0.113.1": "dc-egress", "203.0.113.10": "vip-h1"},
        }

        result = nodes["telemetry_extraction"](state)
        assert result["status"] == "fault_detected"
        assert result["anomaly_classification"]["category"] == "external_overload"
        assert result["anomaly_classification"]["bottleneck_node"] == "dc-egress"
        assert result["anomaly_classification"]["bottleneck_interface"] == "eth2"
        assert result["anomaly_classification"]["offending_source_ip"] == "192.168.100.2"
        assert "dc-egress" in result["suspect_devices"]


# ==============================================================================
# 4. Edge Routing Tests on Buffer Overlimits
# ==============================================================================

class TestRouteAfterTelemetryBufferOverlimits:
    """Validate route_after_telemetry transitions with buffer anomalies."""

    def test_route_to_diagnostic_stage1_on_buffer_discrepancy(self) -> None:
        state = create_operational_initial_state()
        state["discrepancies"] = [
            {
                "node": "dc-egress",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth2",
                "description": "Buffer drop",
            }
        ]
        decision = route_after_telemetry(state)
        assert decision == "diagnostic_stage1"

    def test_route_to_diagnostic_stage1_on_overload_5tuple(self) -> None:
        state = create_operational_initial_state()
        state["failure_5tuples"] = [
            {
                "source_ip": "192.168.100.2",
                "destination_ip": "203.0.113.10",
                "alert_type": "TRAFFIC_OVERLOAD",
            }
        ]
        decision = route_after_telemetry(state)
        assert decision == "diagnostic_stage1"

    def test_route_to_end_healthy_when_clean(self) -> None:
        state = create_operational_initial_state()
        state["telemetry_results"] = {"all_passed": True, "failures": []}
        state["failure_5tuples"] = []
        state["discrepancies"] = []
        decision = route_after_telemetry(state)
        assert decision == "end_healthy"
