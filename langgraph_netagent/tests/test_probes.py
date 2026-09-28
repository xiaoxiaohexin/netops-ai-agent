"""Unit tests for multi-vendor network probes and telemetry collector."""

from pathlib import Path
import pytest

from langgraph_netagent.models.telemetry import NetworkHealthReport
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.probes import (
    InterfaceProbe,
    NetworkTelemetryCollector,
    PingProbe,
    RouteTableProbe,
)


class TestPingProbe:
    """Test suite for PingProbe regex output parsers."""

    def test_parse_healthy_ping_output(self) -> None:
        raw = """PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.
64 bytes from 10.2.2.2: icmp_seq=1 ttl=62 time=0.082 ms
64 bytes from 10.2.2.2: icmp_seq=2 ttl=62 time=0.075 ms
64 bytes from 10.2.2.2: icmp_seq=3 ttl=62 time=0.079 ms

--- 10.2.2.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.075/0.079/0.082/0.003 ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.src_node == "pc1"
        assert telemetry.dst_ip == "10.2.2.2"
        assert telemetry.transmitted == 3
        assert telemetry.received == 3
        assert telemetry.loss_pct == 0.0
        assert telemetry.is_reachable is True
        assert telemetry.rtt_min_ms == 0.075
        assert telemetry.rtt_avg_ms == 0.079
        assert telemetry.rtt_max_ms == 0.082
        assert telemetry.rtt_mdev_ms == 0.003
        assert telemetry.error_message is None

    def test_parse_net_unreachable_ping_output(self) -> None:
        raw = """PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.
From 10.1.1.1 icmp_seq=1 Destination Net Unreachable
From 10.1.1.1 icmp_seq=2 Destination Net Unreachable

--- 10.2.2.2 ping statistics ---
2 packets transmitted, 0 received, +2 errors, 100% packet loss, time 2000ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.transmitted == 2
        assert telemetry.received == 0
        assert telemetry.loss_pct == 100.0
        assert telemetry.is_reachable is False
        assert "Destination Net Unreachable" in (telemetry.error_message or "")

    def test_parse_host_unreachable_ping_output(self) -> None:
        raw = """PING 10.1.1.99 (10.1.1.99) 56(84) bytes of data.
From 10.1.1.2 icmp_seq=1 Destination Host Unreachable

--- 10.1.1.99 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.1.1.99")
        assert telemetry.is_reachable is False
        assert "Destination Host Unreachable" in (telemetry.error_message or "")

    def test_parse_ttl_exceeded_loop_output(self) -> None:
        raw = """PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.
From 10.1.12.1 icmp_seq=1 Time to live exceeded

--- 10.2.2.2 ping statistics ---
1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.is_reachable is False
        assert "TTL" in (telemetry.error_message or "") or "Time to Live" in (telemetry.error_message or "")

    def test_ping_probe_run_against_mock_adapter(
        self,
        mock_adapter: MockContainerlabAdapter,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_adapter.mock_engine.load_topology_package(full_multi_node_package)
        telemetry = PingProbe.run(adapter=mock_adapter, src_node="pc1", dst_ip="10.2.2.2", count=2)
        assert telemetry.is_reachable is True
        assert telemetry.loss_pct == 0.0


class TestRouteTableProbe:
    """Test suite for RouteTableProbe multi-vendor parsing."""

    def test_parse_linux_routes(self) -> None:
        raw = """default via 10.1.1.1 dev eth1
10.1.1.0/24 dev eth1 proto kernel scope link src 10.1.1.2
10.2.2.0/24 via 10.1.12.2 dev eth2 proto static
"""
        rt = RouteTableProbe.parse_linux_routes(node="pc1", raw_output=raw)
        assert rt.node == "pc1"
        assert rt.has_default_route is True
        assert len(rt.routes) == 3
        assert rt.has_route_to("default")
        assert rt.has_route_to("10.1.1.0/24")
        assert rt.has_route_to("10.2.2.0/24")
        assert rt.get_nexthop("10.2.2.0/24") == "10.1.12.2"

    def test_parse_frr_routes_json(self) -> None:
        raw = """{
  "10.1.1.0/24": [
    {
      "prefix": "10.1.1.0/24",
      "protocol": "connected",
      "nexthops": [
        {"ip": "0.0.0.0", "interfaceName": "eth1", "active": true}
      ]
    }
  ],
  "10.2.2.0/24": [
    {
      "prefix": "10.2.2.0/24",
      "protocol": "static",
      "nexthops": [
        {"ip": "10.1.12.2", "interfaceName": "eth2", "active": true}
      ]
    }
  ]
}"""
        rt = RouteTableProbe.parse_frr_routes_json(node="frr1", raw_output=raw)
        assert rt.node == "frr1"
        assert rt.has_route_to("10.2.2.0/24")
        assert rt.get_nexthop("10.2.2.0/24") == "10.1.12.2"

    def test_parse_frr_routes_text(self) -> None:
        raw = """Codes: K - kernel route, C - connected, S - static, O - OSPF, B - BGP

C>* 10.1.1.0/24 is directly connected, eth1, 00:01:23
S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2, weight 1, 00:01:23
"""
        rt = RouteTableProbe.parse_frr_routes_text(node="frr1", raw_output=raw)
        assert rt.has_route_to("10.2.2.0/24")
        assert rt.get_nexthop("10.2.2.0/24") == "10.1.12.2"
        assert rt.has_route_to("10.1.1.0/24")

    def test_parse_srl_routes(self) -> None:
        raw = """-------------------------------------------------------------------
Network-instance : default
-------------------------------------------------------------------
IPv4 Prefix          Type         Next-hop           Interface   
-------------------------------------------------------------------
10.1.1.0/24          static       10.1.12.1          e1-1        
10.2.2.0/24          direct       direct             e1-2        
-------------------------------------------------------------------
"""
        rt = RouteTableProbe.parse_srl_routes(node="srl1", raw_output=raw)
        assert rt.has_route_to("10.1.1.0/24")
        assert rt.get_nexthop("10.1.1.0/24") == "10.1.12.1"
        assert rt.has_route_to("10.2.2.0/24")

    def test_route_table_probe_run(
        self,
        mock_adapter: MockContainerlabAdapter,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_adapter.mock_engine.load_topology_package(full_multi_node_package)

        rt_linux = RouteTableProbe.run(adapter=mock_adapter, node="pc1", device_kind="linux")
        assert rt_linux.has_default_route is True

        rt_frr = RouteTableProbe.run(adapter=mock_adapter, node="frr1", device_kind="frr")
        assert rt_frr.has_route_to("10.2.2.0/24")


class TestInterfaceProbe:
    """Test suite for InterfaceProbe parsing."""

    def test_parse_linux_ip_addr(self) -> None:
        raw = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    link/ether 00:16:3e:aa:01:02 brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.2/24 scope global eth1
3: eth2: <BROADCAST,MULTICAST> mtu 1500 qdisc fq_codel state DOWN
    link/ether 00:16:3e:bb:01:02 brd ff:ff:ff:ff:ff:ff
"""
        ifaces = InterfaceProbe.parse_linux_ip_addr(node="pc1", raw_output=raw)
        assert len(ifaces) == 3

        eth1 = next(i for i in ifaces if i.interface_name == "eth1")
        assert eth1.admin_state == "UP"
        assert eth1.oper_state == "UP"
        assert eth1.is_healthy is True
        assert eth1.ip_addresses == ["10.1.1.2/24"]
        assert eth1.mtu == 1500
        assert eth1.mac_address == "00:16:3e:aa:01:02"

        eth2 = next(i for i in ifaces if i.interface_name == "eth2")
        assert eth2.admin_state == "DOWN"
        assert eth2.is_healthy is False


class TestNetworkTelemetryCollector:
    """Test suite for composite NetworkTelemetryCollector."""

    def test_collector_healthy_network(
        self,
        mock_adapter: MockContainerlabAdapter,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_adapter.mock_engine.load_topology_package(full_multi_node_package)

        report = NetworkTelemetryCollector.collect(
            adapter=mock_adapter,
            ping_targets=[
                ("pc1", "10.2.2.2"),
                ("pc2", "10.1.1.2"),
            ],
            router_nodes=["frr1", "srl1"],
            all_nodes=["pc1", "frr1", "srl1", "pc2"],
            node_kinds={"frr1": "frr", "srl1": "nokia_srlinux"},
            required_routes={"frr1": ["10.2.2.0/24"], "srl1": ["10.1.1.0/24"]},
        )

        assert report.all_passed is True
        assert len(report.failures) == 0
        assert len(report.ping_results) == 2
        assert "frr1" in report.route_tables
        assert "srl1" in report.route_tables
        assert len(report.interfaces) == 4

        # Markdown summary
        md = report.to_summary_markdown()
        assert "✅ PASSED" in md
        assert "Pings Checked: 2 (Failed: 0)" in md

    def test_collector_detects_ping_and_route_failures(
        self,
        mock_adapter: MockContainerlabAdapter,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_adapter.mock_engine.load_topology_package(full_multi_node_package)

        # Inject missing route on frr1
        mock_adapter.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.2.2.0/24",
            )
        )

        report = NetworkTelemetryCollector.collect(
            adapter=mock_adapter,
            ping_targets=[("pc1", "10.2.2.2")],
            router_nodes=["frr1"],
            node_kinds={"frr1": "frr"},
            required_routes={"frr1": ["10.2.2.0/24"]},
        )

        assert report.all_passed is False
        assert len(report.failures) >= 2  # Ping failure + Missing route failure
        assert any("pc1 -> 10.2.2.2" in f for f in report.failures)
        assert any("Missing route on router 'frr1'" in f for f in report.failures)
        assert any("Configure static or dynamic route" in r for r in report.recommendations)

        md = report.to_summary_markdown()
        assert "❌ FAILED" in md
        assert "Pings Checked: 1 (Failed: 1)" in md
        assert "- Failures:" in md
