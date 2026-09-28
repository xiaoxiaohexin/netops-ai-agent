"""Unit and integration tests for Qdisc overlimits probe, interface stats, and buffer fault simulation."""

from __future__ import annotations
import pytest

from langgraph_netagent.models.operational import (
    AnomalyClassification,
    FiveTuple,
)
from langgraph_netagent.models.telemetry import (
    InterfaceStatsTelemetry,
    NetworkHealthReport,
    QdiscTelemetry,
)
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, VirtualInterface, VirtualNode
from langgraph_netagent.tools.probes import InterfaceStatsProbe, NetworkTelemetryCollector, QdiscProbe
from langgraph_netagent.tools.sop_retriever import SOPRetriever


# ==============================================================================
# 1. Qdisc Probe Parsing Tests
# ==============================================================================

class TestQdiscProbeParsing:
    """Tests for QdiscProbe.parse_tc_output and run."""

    def test_parse_healthy_fq_codel(self) -> None:
        raw = (
            "qdisc fq_codel 0: dev eth1 root refcnt 2 limit 10240p flows 1024 quantum 1514\n"
            " Sent 1024 bytes 12 pkt (dropped 0, overlimits 0 requeues 0)\n"
            " backlog 0b 0p requeues 0\n"
        )
        results = QdiscProbe.parse_tc_output(node="router1", raw_output=raw)
        assert len(results) == 1
        q = results[0]
        assert q.node == "router1"
        assert q.interface == "eth1"
        assert q.qdisc_type == "fq_codel"
        assert q.handle == "0:"
        assert q.parent is None
        assert q.bytes_sent == 1024
        assert q.packets_sent == 12
        assert q.dropped == 0
        assert q.overlimits == 0
        assert q.requeues == 0
        assert q.backlog_bytes == 0
        assert q.backlog_packets == 0

    def test_parse_realistic_congested_qdisc(self) -> None:
        """Parse multi-qdisc output from realistic attack report."""
        raw = (
            "qdisc netem 1: dev eth2 root refcnt 17 limit 1000 delay 8.0ms  1.0ms\n"
            " Sent 373237035 bytes 3291492 pkt (dropped 5561645, overlimits 0 requeues 0)\n"
            " backlog 0b 0p requeues 0\n"
            "qdisc tbf 10: dev eth2 parent 1: rate 50Mbit burst 2Kb lat 4.9ms\n"
            " Sent 373237035 bytes 3291492 pkt (dropped 1957605, overlimits 14071085 requeues 0)\n"
            " backlog 1280b 10p requeues 0\n"
        )
        results = QdiscProbe.parse_tc_output(node="dc-egress", raw_output=raw)
        assert len(results) == 2

        netem = results[0]
        assert netem.node == "dc-egress"
        assert netem.interface == "eth2"
        assert netem.qdisc_type == "netem"
        assert netem.handle == "1:"
        assert netem.parent is None
        assert netem.dropped == 5561645
        assert netem.overlimits == 0

        tbf = results[1]
        assert tbf.node == "dc-egress"
        assert tbf.interface == "eth2"
        assert tbf.qdisc_type == "tbf"
        assert tbf.handle == "10:"
        assert tbf.parent == "1:"
        assert tbf.bytes_sent == 373237035
        assert tbf.packets_sent == 3291492
        assert tbf.dropped == 1957605
        assert tbf.overlimits == 14071085
        assert tbf.backlog_bytes == 1280
        assert tbf.backlog_packets == 10

    def test_parse_empty_and_malformed(self) -> None:
        assert QdiscProbe.parse_tc_output(node="r1", raw_output="") == []
        assert QdiscProbe.parse_tc_output(node="r1", raw_output="mock: command not found") == []
        assert QdiscProbe.parse_tc_output(node="r1", raw_output="  \n\n  ") == []


# ==============================================================================
# 2. Interface Stats Probe Parsing Tests
# ==============================================================================

class TestInterfaceStatsProbeParsing:
    """Tests for InterfaceStatsProbe.parse_ip_link_stats."""

    def test_parse_ip_link_stats_healthy(self) -> None:
        raw = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    RX:  bytes packets errors dropped missed mcast\n"
            "          1234      10      0       0      0     0\n"
            "    TX:  bytes packets errors dropped carrier collsns\n"
            "          1234      10      0       0       0       0\n"
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\n"
            "    link/ether 00:16:3e:20:01:02 brd ff:ff:ff:ff:ff:ff\n"
            "    RX:  bytes packets errors dropped missed mcast\n"
            "         50000     500      1       5      0     0\n"
            "    TX:  bytes packets errors dropped carrier collsns\n"
            "         60000     600      2       8       0       0\n"
        )
        stats = InterfaceStatsProbe.parse_ip_link_stats(node="host1", raw_output=raw)
        assert len(stats) == 2

        lo = stats[0]
        assert lo.node == "host1"
        assert lo.interface == "lo"
        assert lo.rx_packets == 10
        assert lo.rx_bytes == 1234
        assert lo.rx_dropped == 0
        assert lo.tx_dropped == 0

        eth1 = stats[1]
        assert eth1.node == "host1"
        assert eth1.interface == "eth1"
        assert eth1.rx_bytes == 50000
        assert eth1.rx_packets == 500
        assert eth1.rx_errors == 1
        assert eth1.rx_dropped == 5
        assert eth1.tx_bytes == 60000
        assert eth1.tx_packets == 600
        assert eth1.tx_errors == 2
        assert eth1.tx_dropped == 8

    def test_parse_empty_stats(self) -> None:
        assert InterfaceStatsProbe.parse_ip_link_stats(node="h1", raw_output="") == []


# ==============================================================================
# 3. FiveTuple and AnomalyClassification Model Tests
# ==============================================================================

class TestModelsExtension:
    """Tests for FiveTuple extensions and AnomalyClassification."""

    def test_five_tuple_from_traffic_overload(self) -> None:
        ft = FiveTuple.from_traffic_overload(
            src_ip="192.168.100.2",
            dst_ip="203.0.113.10",
            protocol="TCP",
            src_port=45678,
            dst_port=80,
            overlimits=145000,
            dropped=8200,
        )
        assert ft.source_ip == "192.168.100.2"
        assert ft.destination_ip == "203.0.113.10"
        assert ft.protocol == "TCP"
        assert ft.source_port == 45678
        assert ft.destination_port == 80
        assert ft.alert_type == "TRAFFIC_OVERLOAD"
        assert ft.overlimits_count == 145000
        assert ft.dropped_packets == 8200
        assert ft.is_external_overload is True
        assert "145000 overlimits" in (ft.raw_log or "")

    def test_five_tuple_from_qdisc_overlimits_alias(self) -> None:
        ft = FiveTuple.from_qdisc_overlimits(
            src_ip="192.168.100.5",
            dst_ip="203.0.113.20",
            overlimits=1000,
            dropped=50,
        )
        assert ft.source_ip == "192.168.100.5"
        assert ft.destination_ip == "203.0.113.20"
        assert ft.alert_type == "TRAFFIC_OVERLOAD"
        assert ft.is_external_overload is True

    def test_five_tuple_backward_compatibility(self) -> None:
        ft_default = FiveTuple(source_ip="10.1.1.2", destination_ip="10.2.2.2")
        assert ft_default.alert_type == "PACKET_DROP"
        assert ft_default.overlimits_count == 0
        assert ft_default.dropped_packets == 0
        assert ft_default.is_external_overload is False

        ft_ping = FiveTuple.from_ping_failure("10.1.1.2", "10.2.2.2")
        assert ft_ping.protocol == "ICMP"
        assert ft_ping.is_external_overload is False

    def test_anomaly_classification(self) -> None:
        ac = AnomalyClassification(
            category="external_overload",
            confidence=0.95,
            reason="Qdisc buffer overlimits and packet drops detected under high ingress traffic",
            bottleneck_node="dc-egress",
            bottleneck_interface="eth2",
            offending_source_ip="192.168.100.2",
            victim_destination_ip="203.0.113.10",
            recommended_action="Deploy border iptables packet filtering and rate-limiting at ingress edge",
        )
        assert ac.category == "external_overload"
        assert ac.confidence == 0.95
        assert ac.bottleneck_node == "dc-egress"
        assert ac.bottleneck_interface == "eth2"
        assert ac.offending_source_ip == "192.168.100.2"

        data = ac.model_dump()
        ac_rebuilt = AnomalyClassification.model_validate(data)
        assert ac_rebuilt.category == ac.category
        assert ac_rebuilt.reason == ac.reason


# ==============================================================================
# 4. MockEngine Simulation & Fault Clearance Tests
# ==============================================================================

class TestMockEngineSimulationAndRemediation:
    """Tests for MockEngine tc simulation and FaultInjector on_remediation."""

    @pytest.fixture
    def test_lab_adapter(self) -> MockContainerlabAdapter:
        adapter = MockContainerlabAdapter()
        # Add virtual node
        node = VirtualNode(name="dc-egress", kind="linux")
        node.add_interface(VirtualInterface(name="eth1", ip_cidr="203.0.113.1/24"))
        node.add_interface(VirtualInterface(name="eth2", ip_cidr="192.168.100.1/24"))
        adapter.mock_engine.graph.add_node(node)
        return adapter

    def test_mock_engine_tc_healthy(self, test_lab_adapter: MockContainerlabAdapter) -> None:
        res = test_lab_adapter.exec_command("dc-egress", "tc -s qdisc show dev eth1")
        assert res.success is True
        assert "dropped 0" in res.stdout
        assert "overlimits 0" in res.stdout

        qdiscs = QdiscProbe.run(test_lab_adapter, "dc-egress", "eth1")
        assert len(qdiscs) == 1
        assert qdiscs[0].dropped == 0
        assert qdiscs[0].overlimits == 0

    def test_mock_engine_tc_fault_injection(self, test_lab_adapter: MockContainerlabAdapter) -> None:
        # Inject buffer overlimit fault
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            target_interface="eth2",
            overlimits=18000,
            dropped=4200,
            source_ip="192.168.100.2",
            dest_port=80,
        )
        test_lab_adapter.fault_injector.add_rule(rule)

        res = test_lab_adapter.exec_command("dc-egress", "tc -s qdisc show dev eth2")
        assert res.success is True
        assert "dropped 4200" in res.stdout
        assert "overlimits 18000" in res.stdout

        qdiscs = QdiscProbe.run(test_lab_adapter, "dc-egress", "eth2")
        assert len(qdiscs) == 2
        tbf = next(q for q in qdiscs if q.qdisc_type == "tbf")
        assert tbf.dropped == 4200
        assert tbf.overlimits == 18000

    def test_mock_engine_iptables_remediation_clears_fault(
        self,
        test_lab_adapter: MockContainerlabAdapter,
    ) -> None:
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="dc-egress",
            source_ip="192.168.100.2",
            overlimits=20000,
            dropped=6000,
        )
        test_lab_adapter.fault_injector.add_rule(rule)
        assert len(test_lab_adapter.fault_injector.get_active_rules()) == 1

        # Execute remediation iptables drop command
        patch_cmd = "iptables -I FORWARD -s 192.168.100.2 -j DROP"
        res = test_lab_adapter.exec_command("dc-egress", patch_cmd)
        assert res.success is True

        # Fault rule should be auto-cleared
        assert len(test_lab_adapter.fault_injector.get_active_rules()) == 0

        # After remediation, tc probe shows healthy zero drops
        post_qdiscs = QdiscProbe.run(test_lab_adapter, "dc-egress", "eth2")
        assert all(q.dropped == 0 and q.overlimits == 0 for q in post_qdiscs)


# ==============================================================================
# 5. NetworkTelemetryCollector with Buffer Anomalies Tests
# ==============================================================================

class TestCollectorWithBufferAnomalies:
    """Tests for NetworkTelemetryCollector buffer anomaly detection."""

    def test_collector_flags_buffer_anomaly(self) -> None:
        adapter = MockContainerlabAdapter()
        node = VirtualNode(name="gw1", kind="linux")
        node.add_interface(VirtualInterface(name="eth1", ip_cidr="203.0.113.1/24"))
        adapter.mock_engine.graph.add_node(node)

        # Inject buffer overlimit fault
        adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.BUFFER_OVERLIMIT,
                target_node="gw1",
                overlimits=15000,
                dropped=3000,
            )
        )

        report = NetworkTelemetryCollector.collect(
            adapter=adapter,
            ping_targets=[],
            router_nodes=["gw1"],
        )

        assert report.all_passed is False
        assert len(report.buffer_anomalies) > 0
        assert report.buffer_anomalies[0]["node"] == "gw1"
        assert report.buffer_anomalies[0]["overlimits"] == 15000
        assert any("Buffer overlimit on gw1" in f for f in report.failures)
        assert any("iptables" in r for r in report.recommendations)

        # Markdown includes buffer anomaly indicator
        md = report.to_summary_markdown()
        assert "❌ FAILED" in md
        assert f"Buffer Anomalies Detected: {len(report.buffer_anomalies)}" in md


# ==============================================================================
# 6. SOP Knowledge Base Retrieval for Overload
# ==============================================================================

class TestSOPRetrieverOverload:
    """Tests for SOP-OVERLOAD-005 retrieval."""

    def test_retrieve_overload_sop(self) -> None:
        retriever = SOPRetriever()
        results = retriever.retrieve(["overlimits", "buffer", "ddos", "traffic_overload"])
        assert len(results) > 0
        top_sop = results[0]
        assert top_sop["sop_id"] == "SOP-OVERLOAD-005"
        assert "Buffer Overlimit" in top_sop["title"]
        assert top_sop["category"] == "TRAFFIC_OVERLOAD"
        assert any("iptables -I FORWARD" in cmd for cmd in top_sop["remediation_template"])
