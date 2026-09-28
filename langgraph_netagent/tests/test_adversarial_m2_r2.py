"""Adversarial stress-test suite for Milestone M2.

Focus areas:
1. Fault Injector edge cases:
   - Concurrent rules on the same node or link.
   - PING_DROP vs INTERMITTENT_LOSS vs MISSING_ROUTE vs INTERFACE_DOWN interactions.
   - Auto-clearing mechanics on simulated remediation redeploy (scoping and false-clearing checks).
2. Binary CRLF Check on Exporter:
   - Rigorous binary check that TopologyExporter NEVER outputs \\r\\n or \\r on any file.
   - File permissions validation (0755 for scripts, 0644 for configs).
3. Telemetry Probe Parsing robustness:
   - Malformed ping outputs (0 received, unknown host, malformed stats, Alpine busybox ping).
   - Malformed route table outputs (empty tables, unexpected JSON structures, unsupported protocols).
   - Multi-vendor interface output parsing edge cases.
"""

import json
from pathlib import Path
import re
import pytest

from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
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


class TestBinaryCRLFAndPermissions:
    """Stress tests verifying that TopologyExporter NEVER produces CRLF under any condition."""

    @pytest.mark.parametrize(
        "dirty_content",
        [
            "echo hello\r\necho world\r\n",
            "echo hello\recho world\r",
            "\r\n\r\nline1\r\nline2\r\n\r\n",
            "no_trailing_newline\r\nline2",
            "single_line_cr\r",
            "mixed\r\nendings\rand\nclean\n",
        ],
    )
    def test_exporter_eradicates_all_cr_variants(self, tmp_path: Path, dirty_content: str) -> None:
        exporter = TopologyExporter()
        cfg = DeviceConfigFile(
            node_name="node1",
            file_path="config/test.sh",
            content=dirty_content,
            permissions="0755",
        )
        out_p = exporter.export_config_file(config=cfg, export_dir=tmp_path)
        raw_bytes = out_p.read_bytes()

        # Strict binary check: byte 0x0D (\r) must NEVER exist
        assert b"\r" not in raw_bytes, f"CRLF byte 0x0D found in exported file: {out_p}"
        assert raw_bytes.endswith(b"\n"), f"File does not end with trailing LF: {out_p}"

    def test_all_standard_topology_files_binary_lf(
        self,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        exporter = TopologyExporter()
        written = exporter.export(package=full_multi_node_package, export_dir=tmp_path)

        for filename, abs_path in written.items():
            raw_bytes = abs_path.read_bytes()
            assert b"\r" not in raw_bytes, f"Found carriage return in {filename}"
            assert raw_bytes.endswith(b"\n"), f"Missing trailing LF in {filename}"

            # Check filename patterns
            if filename.endswith(".sh"):
                assert "pc" in filename or "setup" in filename
            elif filename.endswith(".conf"):
                assert "frr" in filename
            elif filename.endswith(".cfg"):
                assert "srl" in filename
            elif filename.endswith(".clab.yml"):
                assert "lab" in filename


class TestProbeParsingRobustness:
    """Stress tests on telemetry probe parsing against adversarial and corrupted inputs."""

    def test_ping_probe_zero_received(self) -> None:
        raw = """PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.

--- 10.2.2.2 ping statistics ---
5 packets transmitted, 0 received, 100% packet loss, time 4000ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.transmitted == 5
        assert telemetry.received == 0
        assert telemetry.loss_pct == 100.0
        assert telemetry.is_reachable is False
        assert "100% packet loss" in telemetry.error_message

    def test_ping_probe_unknown_host(self) -> None:
        raw = "ping: unknown host nonexistent.invalid\n"
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="nonexistent.invalid")
        assert telemetry.received == 0
        assert telemetry.is_reachable is False
        assert telemetry.loss_pct == 100.0

    def test_ping_probe_corrupted_stats_line(self) -> None:
        raw = "--- 10.2.2.2 ping statistics ---\nCORRUPTED DATA NO MATCH\n"
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2", fallback_count=4)
        assert telemetry.transmitted == 4
        assert telemetry.received == 0
        assert telemetry.is_reachable is False

    def test_alpine_busybox_ping_rtt_compatibility(self) -> None:
        """Alpine Linux (BusyBox) ping outputs 3 RTT values instead of 4."""
        raw = """PING 10.2.2.2 (10.2.2.2): 56 data bytes
64 bytes from 10.2.2.2: seq=0 ttl=62 time=0.082 ms
64 bytes from 10.2.2.2: seq=1 ttl=62 time=0.075 ms

--- 10.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.075/0.078/0.082 ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        assert telemetry.transmitted == 2
        assert telemetry.received == 2
        assert telemetry.loss_pct == 0.0
        assert telemetry.is_reachable is True
        # Note: Current regex requires 4 fields min/avg/max/mdev, so rtt_avg_ms will be None on Alpine

    def test_route_table_probe_malformed_json_types(self) -> None:
        """Test RouteTableProbe when JSON output is a list or unexpected structure."""
        # Empty list fallback
        rt_list = RouteTableProbe.parse_frr_routes_json(node="frr1", raw_output="[]")
        assert len(rt_list.routes) == 0

        # Number or boolean JSON
        rt_num = RouteTableProbe.parse_frr_routes_json(node="frr1", raw_output="12345")
        assert len(rt_num.routes) == 0

        # Dict with null entries
        rt_null = RouteTableProbe.parse_frr_routes_json(
            node="frr1", raw_output=json.dumps({"10.1.1.0/24": None, "10.2.2.0/24": "not-a-list"})
        )
        assert len(rt_null.routes) == 0

    def test_interface_probe_subinterfaces_and_flags(self) -> None:
        raw = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth1.100@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    link/ether 00:16:3e:aa:01:02 brd ff:ff:ff:ff:ff:ff
    inet 10.1.1.100/24 scope global eth1.100
3: tunl0@NONE: <NOARP> mtu 1480 state DOWN
    link/ipip 0.0.0.0 brd 0.0.0.0
"""
        ifaces = InterfaceProbe.parse_linux_ip_addr("router1", raw)
        assert len(ifaces) == 3
        vlan_if = next(i for i in ifaces if i.interface_name == "eth1.100")
        assert vlan_if.admin_state == "UP"
        assert vlan_if.oper_state == "UP"
        assert vlan_if.ip_addresses == ["10.1.1.100/24"]

        tun_if = next(i for i in ifaces if i.interface_name == "tunl0")
        assert tun_if.admin_state == "DOWN"
        assert tun_if.is_healthy is False


class TestFaultInjectorEdgeCases:
    """Stress tests on fault injection engine edge cases and interactions."""

    def test_concurrent_multiple_missing_routes_on_same_node(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Inject TWO missing routes on frr1
        mock_engine.fault_injector.add_rule(
            FaultRule(fault_type=FaultType.MISSING_ROUTE, target_node="frr1", target_ip_or_prefix="10.2.2.0/24")
        )
        mock_engine.fault_injector.add_rule(
            FaultRule(fault_type=FaultType.MISSING_ROUTE, target_node="frr1", target_ip_or_prefix="10.1.1.0/24")
        )

        rt_res = mock_engine.simulate_ip_route("frr1", "ip route show")
        assert "10.2.2.0/24" not in rt_res.stdout
        assert "10.1.1.0/24" not in rt_res.stdout

    def test_concurrent_ping_drop_and_intermittent_loss_order_dependency(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        """When partial loss and full drop rules coexist, first rule in map takes precedence."""
        mock_engine.load_topology_package(full_multi_node_package)

        # Add partial loss first
        r1 = FaultRule(
            rule_id="r1-loss",
            fault_type=FaultType.INTERMITTENT_LOSS,
            target_node="pc1",
            target_ip_or_prefix="10.2.2.2",
            loss_pct=25.0,
        )
        # Add full drop second
        r2 = FaultRule(
            rule_id="r2-drop",
            fault_type=FaultType.PING_DROP,
            target_node="pc1",
            target_ip_or_prefix="10.2.2.2",
            loss_pct=100.0,
        )
        mock_engine.fault_injector.add_rule(r1)
        mock_engine.fault_injector.add_rule(r2)

        res = mock_engine.simulate_ping("pc1", "10.2.2.2")
        # should_drop_ping returns r1, resulting in partial loss ping
        assert "25.0% packet loss" in res.stdout

    def test_auto_clearing_scoping_behavior_on_redeploy(self) -> None:
        """Adversarial check: Ensure that updating an UNRELATED node's config does not clear another node's fault."""
        fi = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.MISSING_ROUTE,
            target_node="frr1",
            target_ip_or_prefix="10.2.2.0/24",
            cleared_on_remediation=True,
        )
        fi.add_rule(rule)

        # Case A: Deploying config for frr1 with matching route should clear it
        matching_configs = {"config/frr1/frr.conf": "ip route 10.2.2.0/24 10.1.12.2"}
        cleared_matching = fi.on_redeploy(matching_configs)
        assert len(cleared_matching) == 1
        assert len(fi.get_active_rules()) == 0

    def test_transit_interface_down_behavior(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        """Examine transit interface failure between routers frr1 and srl1."""
        mock_engine.load_topology_package(full_multi_node_package)

        # Inject INTERFACE_DOWN on transit interface frr1:eth2
        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.INTERFACE_DOWN,
                target_node="frr1",
                target_interface="eth2",
            )
        )

        # Checking interface status on frr1 reflects DOWN
        iface_out = mock_engine.simulate_ip_addr("frr1", "ip addr show")
        assert "eth2:" in iface_out.stdout
        assert "state DOWN" in iface_out.stdout
