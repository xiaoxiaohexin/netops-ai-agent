"""Adversarial and boundary test suite for Milestone M2 tools and probes."""

import json
from pathlib import Path
import pytest

from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
)
from langgraph_netagent.tools.exporter import TopologyExporter
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine
from langgraph_netagent.tools.probes import (
    InterfaceProbe,
    NetworkTelemetryCollector,
    PingProbe,
    RouteTableProbe,
)
from langgraph_netagent.tools.runner import (
    SubprocessRunner,
    strip_ansi_codes,
    windows_to_wsl_path,
    wsl_to_windows_path,
)


class TestAdversarialPingParser:
    """Test ping parser resilience against malformed, partial, or corrupted outputs."""

    def test_completely_empty_output(self) -> None:
        telemetry = PingProbe.parse_ping_output(raw_output="", src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.transmitted == 3
        assert telemetry.received == 0
        assert telemetry.loss_pct == 100.0
        assert telemetry.is_reachable is False

    def test_garbage_and_binary_garbage(self) -> None:
        garbage = "%%%$$$@@@\x00\x01\x02\nRandom crash dump\nSegmentation fault\n"
        telemetry = PingProbe.parse_ping_output(raw_output=garbage, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.is_reachable is False
        assert telemetry.loss_pct == 100.0

    def test_ping_with_header_only_no_stats(self) -> None:
        truncated = "PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.\n"
        telemetry = PingProbe.parse_ping_output(raw_output=truncated, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.is_reachable is False
        assert telemetry.loss_pct == 100.0

    def test_ping_with_strange_whitespace_and_mixed_casing(self) -> None:
        text = """
        5    PACKETS   TRANSMITTED,   5   RECEIVED,  0.0%  PACKET LOSS
        rtt min/avg/max/mdev = 1.000/2.000/3.000/0.500 ms
        """
        telemetry = PingProbe.parse_ping_output(raw_output=text, src_node="nodeA", dst_ip="1.2.3.4")
        assert telemetry.transmitted == 5
        assert telemetry.received == 5
        assert telemetry.loss_pct == 0.0
        assert telemetry.is_reachable is True
        assert telemetry.rtt_avg_ms == 2.0


class TestAdversarialRouteParser:
    """Test route table parsers resilience against strange or malformed outputs."""

    def test_empty_route_table(self) -> None:
        rt = RouteTableProbe.parse_linux_routes(node="n1", raw_output="")
        assert len(rt.routes) == 0
        assert rt.has_default_route is False

    def test_malformed_frr_json_falls_back_gracefully(self) -> None:
        malformed = "{prefix: invalid json"
        # Should not raise, falls back to text parser
        rt = RouteTableProbe.parse_frr_routes_json(node="frr1", raw_output=malformed)
        assert rt.node == "frr1"

    def test_frr_json_with_empty_or_missing_nexthops(self) -> None:
        data = {
            "10.0.0.0/8": [
                {"prefix": "10.0.0.0/8", "protocol": "kernel", "nexthops": []}
            ]
        }
        rt = RouteTableProbe.parse_frr_routes_json(node="frr1", raw_output=json.dumps(data))
        assert rt.has_route_to("10.0.0.0/8")
        assert rt.get_nexthop("10.0.0.0/8") is None

    def test_srl_route_table_with_empty_lines(self) -> None:
        raw = "\n\n-----------------\n   \n"
        rt = RouteTableProbe.parse_srl_routes(node="srl1", raw_output=raw)
        assert len(rt.routes) == 0


class TestAdversarialMockEngine:
    """Test mock engine boundary cases, forwarding loops, and error paths."""

    def test_routing_loop_detection_prevents_infinite_recursion(self) -> None:
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="loop-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "r1": ContainerlabNodeConfig(kind="linux", image="alpine"),
                    "r2": ContainerlabNodeConfig(kind="linux", image="alpine"),
                    "r3": ContainerlabNodeConfig(kind="linux", image="alpine"),
                },
                links=[ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r2:eth1"])],
            ),
        )
        engine.load_topology(topo)
        engine.graph.register_ip("10.0.0.1/24", "r1", "eth1")
        engine.graph.register_ip("10.0.0.2/24", "r2", "eth1")
        engine.graph.register_ip("192.168.99.1/24", "r3", "eth1")

        # Create routing loop for destination 192.168.99.1:
        # r1 routes to r2 (10.0.0.2), r2 routes back to r1 (10.0.0.1)
        from langgraph_netagent.models.telemetry import RouteEntry
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="192.168.99.1/32", next_hop="10.0.0.2"))
        engine.graph.nodes["r2"].add_route(RouteEntry(destination="192.168.99.1/32", next_hop="10.0.0.1"))

        # Ping should fail cleanly without recursion depth error
        res = engine.simulate_ping(src_node="r1", dst_ip="192.168.99.1")
        assert res.exit_code == 1
        assert "100% packet loss" in res.stdout
        assert "Time to live exceeded" in res.stdout or "loop" in res.stdout.lower()

    def test_mock_engine_node_not_found(self) -> None:
        engine = MockEngine()
        res = engine.exec_command("ghost_node", "ping -c 1 10.0.0.1")
        assert res.exit_code == 1
        assert "ghost_node" in res.stderr

    def test_mock_engine_empty_command(self) -> None:
        engine = MockEngine()
        res = engine.exec_command("pc1", "   ")
        assert res.exit_code == 0


class TestAdversarialExporter:
    """Test exporter boundary cases with odd file names, permissions, and contents."""

    def test_exporter_handles_crlf_and_cr_only(self, tmp_path: Path) -> None:
        exporter = TopologyExporter()
        cfg = DeviceConfigFile(
            node_name="node1",
            file_path="config/mixed.sh",
            content="line1\r\nline2\rline3\n",
            permissions="0755",
        )
        dest = exporter.export_config_file(cfg, export_dir=tmp_path)
        raw = dest.read_bytes()
        assert b"\r" not in raw
        assert raw == b"line1\nline2\nline3\n"
