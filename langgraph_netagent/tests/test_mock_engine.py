"""Unit tests for MockEngine, VirtualNetworkGraph, and MockContainerlabAdapter."""

import json
from pathlib import Path
import pytest

from langgraph_netagent.models.telemetry import RouteEntry
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.fault_injector import FaultInjector
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine


class TestMockEngineVirtualGraph:
    """Test suite for virtual network graph loading and routing lookup."""

    def test_load_topology_builds_graph(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)
        graph = mock_engine.graph

        assert len(graph.nodes) == 4
        assert set(graph.nodes.keys()) == {"pc1", "frr1", "srl1", "pc2"}

        # Validate interface allocations
        assert graph.ip_to_node["10.1.1.2"] == ("pc1", "eth1")
        assert graph.ip_to_node["10.1.1.1"] == ("frr1", "eth1")
        assert graph.ip_to_node["10.1.12.1"] == ("frr1", "eth2")
        assert graph.ip_to_node["10.1.12.2"] == ("srl1", "e1-1")
        assert graph.ip_to_node["10.2.2.1"] == ("srl1", "e1-2")
        assert graph.ip_to_node["10.2.2.2"] == ("pc2", "eth1")

        # Check default gateway on pc1
        assert graph.nodes["pc1"].default_gateway == "10.1.1.1"

    def test_end_to_end_ping_healthy_multi_hop_path(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Forward ping: pc1 -> frr1 -> srl1 -> pc2
        res = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2", count=3)
        assert res.exit_code == 0
        assert res.success
        assert "0% packet loss" in res.stdout
        assert "3 packets transmitted, 3 received" in res.stdout

        # Reverse ping: pc2 -> srl1 -> frr1 -> pc1
        res_rev = mock_engine.simulate_ping(src_node="pc2", dst_ip="10.1.1.2", count=3)
        assert res_rev.exit_code == 0
        assert res_rev.success
        assert "0% packet loss" in res_rev.stdout

        # Adjacent hop pings
        res_adj = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.1.1.1", count=2)
        assert res_adj.exit_code == 0

        res_transit = mock_engine.simulate_ping(src_node="frr1", dst_ip="10.1.12.2", count=2)
        assert res_transit.exit_code == 0

    def test_ping_unregistered_ip_fails_with_host_unreachable(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)
        res = mock_engine.simulate_ping(src_node="pc1", dst_ip="192.168.200.1")

        assert res.exit_code == 1
        assert not res.success
        assert "100% packet loss" in res.stdout
        assert "Destination Host Unreachable" in res.stdout

    def test_ping_missing_route_fails_with_net_unreachable(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Remove the transit static route to 10.2.2.0/24 from frr1
        frr_node = mock_engine.graph.nodes["frr1"]
        frr_node.routes = [r for r in frr_node.routes if r.destination != "10.2.2.0/24"]

        # Now ping from pc1 to pc2 must fail
        res = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert res.exit_code == 1
        assert not res.success
        assert "100% packet loss" in res.stdout
        assert "Destination Net Unreachable" in res.stdout

    def test_simulate_ip_route_output_formats(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Host pc1 route output
        pc1_route = mock_engine.simulate_ip_route(node_name="pc1", cmd="ip route show")
        assert pc1_route.exit_code == 0
        assert "default via 10.1.1.1 dev eth1" in pc1_route.stdout
        assert "10.1.1.0/24 dev eth1" in pc1_route.stdout

        # Router frr1 route output
        frr_route = mock_engine.simulate_ip_route(node_name="frr1", cmd="ip route")
        assert frr_route.exit_code == 0
        assert "10.2.2.0/24 via 10.1.12.2" in frr_route.stdout
        assert "10.1.1.0/24 dev eth1" in frr_route.stdout
        assert "10.1.12.0/24 dev eth2" in frr_route.stdout

    def test_simulate_vtysh_command(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # JSON route output
        res_json = mock_engine.simulate_vtysh_command("frr1", "vtysh -c 'show ip route json'")
        assert res_json.exit_code == 0
        parsed = json.loads(res_json.stdout)
        assert "10.2.2.0/24" in parsed
        assert parsed["10.2.2.0/24"][0]["nexthops"][0]["ip"] == "10.1.12.2"

        # Text route output
        res_text = mock_engine.simulate_vtysh_command("frr1", "vtysh -c 'show ip route'")
        assert res_text.exit_code == 0
        assert "S>* 10.2.2.0/24" in res_text.stdout
        assert "via 10.1.12.2" in res_text.stdout

    def test_simulate_srl_command(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)
        res = mock_engine.simulate_srl_command("srl1", "sr_cli 'show network-instance default route-table'")
        assert res.exit_code == 0
        assert "Network-instance : default" in res.stdout
        assert "10.1.1.0/24" in res.stdout

    def test_simulate_ip_addr(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)
        res = mock_engine.simulate_ip_addr("pc1", "ip addr show")
        assert res.exit_code == 0
        assert "eth1:" in res.stdout
        assert "state UP" in res.stdout
        assert "inet 10.1.1.2/24" in res.stdout


class TestMockContainerlabAdapter:
    """Test suite for MockContainerlabAdapter lifecycle methods."""

    def test_deploy_inspect_and_destroy_lifecycle(
        self,
        tmp_path: Path,
        mock_adapter: MockContainerlabAdapter,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        from langgraph_netagent.tools.exporter import TopologyExporter

        exporter = TopologyExporter()
        exporter.export(package=full_multi_node_package, export_dir=tmp_path)
        topo_file = tmp_path / "multi-vendor-lab.clab.yml"

        # 1. Deploy
        dep_res = mock_adapter.deploy(topo_file=topo_file)
        assert dep_res.success
        assert set(dep_res.nodes_deployed) == {"pc1", "frr1", "srl1", "pc2"}
        assert dep_res.lab_name == "multi-vendor-lab"

        # 2. Inspect
        ins_res = mock_adapter.inspect(topo_file=topo_file)
        assert ins_res.success
        assert len(ins_res.nodes) == 4
        node_names = {n.name for n in ins_res.nodes}
        assert node_names == {"pc1", "frr1", "srl1", "pc2"}
        for n in ins_res.nodes:
            assert n.state == "running"

        # 3. Exec command
        cmd_res = mock_adapter.exec_command(node_name="pc1", command="ping -c 2 10.2.2.2")
        assert cmd_res.success
        assert "0% packet loss" in cmd_res.stdout

        # 4. Destroy
        des_res = mock_adapter.destroy(topo_file=topo_file)
        assert des_res.success
        assert not mock_adapter._deployed

    def test_adapter_is_live_ready_always_true_for_mock(
        self,
        mock_adapter: MockContainerlabAdapter,
    ) -> None:
        assert mock_adapter.is_live_ready() is True
