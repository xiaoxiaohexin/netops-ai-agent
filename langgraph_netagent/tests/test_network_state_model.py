"""Comprehensive Test Suite for NetworkState Model & State Diff Engine (R2).

Verifies:
1. Pydantic v2 model creation, validation, normalization, and serialization.
2. compute_state_diff with Link Down, Route Missing, Packet Loss, Latency, and Qdisc drop scenarios.
3. to_llm_markdown token and size efficiency (<500B).
4. NetworkStateSnapshotter end-to-end integration against MockContainerlabAdapter with virtual nodes.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List
import pytest

from langgraph_netagent.models.network_state import (
    InterfaceDiff,
    InterfaceState,
    NetworkState,
    NodeState,
    QdiscDiff,
    QdiscState,
    ReachabilityDiff,
    ReachabilityState,
    RouteDiff,
    RouteState,
    StateDiff,
    compute_state_diff,
)
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule
from langgraph_netagent.tools.mock_engine import (
    FullTopologyPackage,
    MockContainerlabAdapter,
    MockEngine,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter


# ==============================================================================
# 1. Pydantic Models Creation, Validation, and Serialization Tests
# ==============================================================================

class TestNetworkStateModels:
    """Tests schema validation, normalization, and serialization across all state models."""

    def test_interface_state_creation_and_normalization(self) -> None:
        """Test InterfaceState creates correctly and normalizes states."""
        ifc = InterfaceState(
            name="eth1",
            admin_state="UP",
            oper_state="UP",
            ipv4_addresses=["172.16.1.1/24"],
            mtu=1500,
            rx_bytes=1024,
            tx_bytes=2048,
            rx_dropped=0,
            tx_dropped=0,
            rx_errors=0,
            tx_errors=0,
        )
        assert ifc.name == "eth1"
        assert ifc.admin_state == "UP"
        assert ifc.oper_state == "UP"
        assert ifc.is_healthy is True

        # Test state normalization from lower/alternative strings
        ifc_down = InterfaceState(
            name="eth2",
            admin_state="down",
            oper_state="NO-CARRIER",
        )
        assert ifc_down.admin_state == "DOWN"
        assert ifc_down.oper_state == "DOWN"
        assert ifc_down.is_healthy is False

        # Serialization / deserialization roundtrip
        dumped = ifc.model_dump()
        restored = InterfaceState.model_validate(dumped)
        assert restored.name == ifc.name
        assert restored.ipv4_addresses == ["172.16.1.1/24"]

    def test_route_state_creation_and_compatibility(self) -> None:
        """Test RouteState creation and destination alias backwards-compatibility."""
        route = RouteState(
            prefix="172.16.2.0/24",
            next_hop="172.16.254.2",
            interface="eth1",
            protocol="static",
            metric=10,
            active=True,
        )
        assert route.prefix == "172.16.2.0/24"
        assert route.destination == "172.16.2.0/24"
        assert route.next_hop == "172.16.254.2"
        assert route.active is True

        # Initializing via 'destination' keyword
        compat_route = RouteState.model_validate({"destination": "10.0.0.0/8", "next_hop": "10.0.0.1"})
        assert compat_route.prefix == "10.0.0.0/8"
        assert compat_route.destination == "10.0.0.0/8"

    def test_qdisc_state_creation_and_compatibility(self) -> None:
        """Test QdiscState creation and dropped alias backwards-compatibility."""
        qd = QdiscState(
            interface="eth1",
            qdisc_type="netem",
            loss_percent=5.0,
            delay_ms=10.0,
            dropped_packets=12,
            overlimits=3,
        )
        assert qd.interface == "eth1"
        assert qd.dropped == 12
        assert qd.loss_percent == 5.0
        assert qd.delay_ms == 10.0

        # Initializing via 'dropped'
        compat_qd = QdiscState.model_validate({"interface": "eth2", "dropped": 25})
        assert compat_qd.dropped_packets == 25
        assert compat_qd.dropped == 25

    def test_reachability_state_creation_and_compatibility(self) -> None:
        """Test ReachabilityState creation and telemetry field aliases."""
        reach = ReachabilityState(
            source="h1",
            destination="h2",
            reachable=True,
            latency_ms=1.45,
            packet_loss_pct=0.0,
        )
        assert reach.source == "h1"
        assert reach.destination == "h2"
        assert reach.is_reachable is True
        assert reach.loss_pct == 0.0
        assert reach.rtt_avg_ms == 1.45

        # Initializing via telemetry naming
        compat_reach = ReachabilityState.model_validate({
            "src_node": "h3",
            "dst_node": "h4",
            "is_reachable": False,
            "loss_pct": 100.0,
            "rtt_avg_ms": None,
        })
        assert compat_reach.source == "h3"
        assert compat_reach.destination == "h4"
        assert compat_reach.reachable is False
        assert compat_reach.packet_loss_pct == 100.0

    def test_node_state_and_network_state_assembly(self) -> None:
        """Test NodeState and overall NetworkState creation and health assessment."""
        ifc = InterfaceState(name="eth1", admin_state="UP", oper_state="UP")
        rt = RouteState(prefix="172.16.1.0/24", next_hop="172.16.254.1")
        qd = QdiscState(interface="eth1")

        node = NodeState(
            node_name="leaf1",
            role="leaf",
            status="healthy",
            interfaces={"eth1": ifc},
            routes=[rt],
            qdiscs={"eth1": qd},
        )
        assert node.name == "leaf1"
        assert node.has_route_to("172.16.1.0/24") is True
        assert node.has_route_to("10.99.0.0/16") is False

        reach = ReachabilityState(source="h1", destination="h2", reachable=True, packet_loss_pct=0.0)
        net_state = NetworkState(
            timestamp=time.time(),
            lab_name="clos5",
            nodes={"leaf1": node},
            reachability_matrix=[reach],
            healthy=True,
        )
        assert net_state.is_healthy() is True
        assert "leaf1" in net_state.nodes
        assert len(net_state.reachability_matrix) == 1

        # JSON dump & restore
        raw_json = net_state.model_dump_json()
        restored_net = NetworkState.model_validate_json(raw_json)
        assert restored_net.lab_name == "clos5"
        assert restored_net.nodes["leaf1"].interfaces["eth1"].name == "eth1"


# ==============================================================================
# 2. StateDiff Engine Scenario Tests
# ==============================================================================

class TestStateDiffEngineScenarios:
    """Tests compute_state_diff across link failure, route drop, packet loss, and latency."""

    @pytest.fixture
    def healthy_baseline(self) -> NetworkState:
        """Provides a healthy 4-node Clos baseline snapshot."""
        leaf1_ifaces = {
            "eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.1.1/24"]),
            "eth2": InterfaceState(name="eth2", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.254.1/30"]),
        }
        leaf1_routes = [
            RouteState(prefix="172.16.1.0/24", interface="eth1", protocol="connected"),
            RouteState(prefix="172.16.2.0/24", next_hop="172.16.254.2", interface="eth2", protocol="bgp"),
        ]
        leaf1_qdiscs = {
            "eth1": QdiscState(interface="eth1", dropped_packets=0, overlimits=0),
        }
        leaf1 = NodeState(node_name="leaf1", role="leaf", interfaces=leaf1_ifaces, routes=leaf1_routes, qdiscs=leaf1_qdiscs)

        h1 = NodeState(
            node_name="h1",
            role="host",
            interfaces={"eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.1.2/24"])},
            routes=[RouteState(prefix="default", next_hop="172.16.1.1", interface="eth1")],
        )
        h2 = NodeState(
            node_name="h2",
            role="host",
            interfaces={"eth1": InterfaceState(name="eth1", admin_state="UP", oper_state="UP", ipv4_addresses=["172.16.2.2/24"])},
            routes=[RouteState(prefix="default", next_hop="172.16.2.1", interface="eth1")],
        )

        reach_list = [
            ReachabilityState(source="h1", destination="h2", reachable=True, latency_ms=1.1, packet_loss_pct=0.0),
            ReachabilityState(source="h2", destination="h1", reachable=True, latency_ms=1.1, packet_loss_pct=0.0),
        ]

        return NetworkState(
            timestamp=100.0,
            lab_name="clos5",
            nodes={"leaf1": leaf1, "h1": h1, "h2": h2},
            reachability_matrix=reach_list,
            healthy=True,
        )

    def test_scenario_no_changes(self, healthy_baseline: NetworkState) -> None:
        """Diff between two identical states reports no anomalies."""
        diff = compute_state_diff(baseline=healthy_baseline, current=healthy_baseline)
        assert diff.has_anomalies() is False
        assert diff.has_link_failure() is False
        assert diff.has_route_failure() is False
        assert diff.has_packet_loss() is False
        assert diff.affected_nodes() == []
        md = diff.to_llm_markdown()
        assert "OK (No anomalies)" in md

    def test_scenario_link_failure(self, healthy_baseline: NetworkState) -> None:
        """Scenario: leaf1:eth2 link is dropped."""
        curr = healthy_baseline.model_copy(deep=True)
        curr.nodes["leaf1"].interfaces["eth2"].oper_state = "DOWN"
        curr.nodes["leaf1"].interfaces["eth2"].admin_state = "DOWN"

        diff = compute_state_diff(baseline=healthy_baseline, current=curr)
        assert diff.has_anomalies() is True
        assert diff.has_link_failure() is True
        assert "leaf1" in diff.affected_nodes()
        assert "leaf1" in diff.interface_diffs
        idiff = diff.interface_diffs["leaf1"]
        assert "eth2" in idiff.changed
        assert idiff.changed["eth2"]["oper_state"] == ("UP", "DOWN")
        assert idiff.changed["eth2"]["admin_state"] == ("UP", "DOWN")

        md = diff.to_llm_markdown()
        assert "leaf1:eth2 (UP->DOWN)" in md
        assert len(md.encode("utf-8")) < 500

    def test_scenario_route_missing(self, healthy_baseline: NetworkState) -> None:
        """Scenario: route to 172.16.2.0/24 is withdrawn from leaf1."""
        curr = healthy_baseline.model_copy(deep=True)
        # Remove route 172.16.2.0/24
        curr.nodes["leaf1"].routes = [
            r for r in curr.nodes["leaf1"].routes if r.prefix != "172.16.2.0/24"
        ]

        diff = compute_state_diff(baseline=healthy_baseline, current=curr)
        assert diff.has_anomalies() is True
        assert diff.has_route_failure() is True
        assert "leaf1" in diff.affected_nodes()
        assert "leaf1" in diff.route_diffs
        rdiff = diff.route_diffs["leaf1"]
        assert len(rdiff.removed) == 1
        assert rdiff.removed[0].prefix == "172.16.2.0/24"

        md = diff.to_llm_markdown()
        assert "leaf1 missing 172.16.2.0/24" in md
        assert len(md.encode("utf-8")) < 500

    def test_scenario_packet_loss_and_unreachable(self, healthy_baseline: NetworkState) -> None:
        """Scenario: h1 -> h2 becomes completely unreachable (100% loss)."""
        curr = healthy_baseline.model_copy(deep=True)
        curr.reachability_matrix = [
            ReachabilityState(source="h1", destination="h2", reachable=False, latency_ms=None, packet_loss_pct=100.0),
            ReachabilityState(source="h2", destination="h1", reachable=False, latency_ms=None, packet_loss_pct=100.0),
        ]

        diff = compute_state_diff(baseline=healthy_baseline, current=curr)
        assert diff.has_anomalies() is True
        assert diff.has_packet_loss() is True
        assert ("h1", "h2") in diff.reachability_diffs.newly_unreachable
        assert "h1" in diff.affected_nodes()
        assert "h2" in diff.affected_nodes()
        assert diff.reachability_diffs.loss_changes["h1->h2"] == (0.0, 100.0)

        md = diff.to_llm_markdown()
        assert "Unreachable: h1->h2" in md
        assert len(md.encode("utf-8")) < 500

    def test_scenario_latency_spike(self, healthy_baseline: NetworkState) -> None:
        """Scenario: latency spike from 1.1ms to 85.0ms between h1 and h2."""
        curr = healthy_baseline.model_copy(deep=True)
        curr.reachability_matrix = [
            ReachabilityState(source="h1", destination="h2", reachable=True, latency_ms=85.0, packet_loss_pct=0.0),
            ReachabilityState(source="h2", destination="h1", reachable=True, latency_ms=85.0, packet_loss_pct=0.0),
        ]

        diff = compute_state_diff(baseline=healthy_baseline, current=curr)
        assert "h1->h2" in diff.reachability_diffs.latency_changes
        assert diff.reachability_diffs.latency_changes["h1->h2"] == (1.1, 85.0)

    def test_scenario_qdisc_buffer_drop(self, healthy_baseline: NetworkState) -> None:
        """Scenario: buffer overflow causes packet drops and overlimits on leaf1:eth1."""
        curr = healthy_baseline.model_copy(deep=True)
        curr.nodes["leaf1"].qdiscs["eth1"].dropped_packets = 42
        curr.nodes["leaf1"].qdiscs["eth1"].overlimits = 100

        diff = compute_state_diff(baseline=healthy_baseline, current=curr)
        assert diff.has_anomalies() is True
        assert diff.has_packet_loss() is True
        assert "leaf1" in diff.qdisc_diffs
        qdiff = diff.qdisc_diffs["leaf1"]
        assert "eth1" in qdiff.changed
        assert qdiff.changed["eth1"]["dropped_packets"] == (0, 42)
        assert qdiff.changed["eth1"]["overlimits"] == (0, 100)

        md = diff.to_llm_markdown()
        assert "leaf1:eth1 (+42 drops)" in md
        assert len(md.encode("utf-8")) < 500


# ==============================================================================
# 3. LLM Markdown Token and Size Efficiency Tests (<500B / <200 tokens)
# ==============================================================================

class TestMarkdownEfficiency:
    """Tests strict byte size and concise token density of to_llm_markdown."""

    def test_multi_anomaly_stays_under_500_bytes(self) -> None:
        """Even with simultaneous link, route, queue, and ping failures, summary <500B."""
        idiff = InterfaceDiff(
            node="leaf1",
            changed={"eth1": {"oper_state": ("UP", "DOWN")}, "eth2": {"oper_state": ("UP", "DOWN")}},
        )
        rdiff = RouteDiff(
            node="leaf1",
            removed=[
                RouteState(prefix="172.16.2.0/24", next_hop="172.16.254.2"),
                RouteState(prefix="172.16.3.0/24", next_hop="172.16.254.3"),
            ],
        )
        qdiff = QdiscDiff(
            node="leaf2",
            changed={"eth1": {"dropped_packets": (0, 150), "overlimits": (0, 500)}},
        )
        reach_diff = ReachabilityDiff(
            newly_unreachable=[("h1", "h2"), ("h1", "h3")],
            loss_changes={"h1->h4": (0.0, 50.0)},
        )

        diff = StateDiff(
            interface_diffs={"leaf1": idiff},
            route_diffs={"leaf1": rdiff},
            qdisc_diffs={"leaf2": qdiff},
            reachability_diffs=reach_diff,
        )

        md = diff.to_llm_markdown()
        byte_len = len(md.encode("utf-8"))
        word_count = len(md.split())

        # Assert hard limits
        assert byte_len < 500, f"Markdown exceeds 500 bytes: {byte_len} bytes:\n{md}"
        assert word_count < 100, f"Markdown token count unexpectedly high: {word_count} words"

        # Assert key diagnostic signals are preserved
        assert "Links Down: leaf1:eth1 (UP->DOWN)" in md
        assert "Missing Routes: leaf1 missing 172.16.2.0/24" in md
        assert "Unreachable: h1->h2, h1->h3" in md
        assert "Packet Loss: h1->h4 (0%->50%)" in md
        assert "Queue Drops: leaf2:eth1 (+150 drops)" in md

    def test_to_dict_preserves_structure(self) -> None:
        """to_dict returns a valid Python dictionary representation."""
        diff = StateDiff(
            interface_diffs={"leaf1": InterfaceDiff(node="leaf1")},
            reachability_diffs=ReachabilityDiff(newly_unreachable=[("h1", "h2")]),
        )
        d = diff.to_dict()
        assert isinstance(d, dict)
        assert "interface_diffs" in d
        assert "reachability_diffs" in d
        assert d["reachability_diffs"]["newly_unreachable"] == [("h1", "h2")]


# ==============================================================================
# 4. NetworkStateSnapshotter Integration with MockContainerlabAdapter
# ==============================================================================

class TestSnapshotterMockIntegration:
    """Tests NetworkStateSnapshotter executing against MockContainerlabAdapter with virtual nodes."""

    def test_snapshotter_captures_virtual_topology(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Snapshotter successfully queries pc1, frr1, srl1, pc2 and populates NetworkState."""
        adapter = MockContainerlabAdapter()
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        snapshotter = NetworkStateSnapshotter(lab_adapter=adapter, lab_name="multi-vendor-lab")
        snap = snapshotter.capture_snapshot()

        assert snap.lab_name == "multi-vendor-lab"
        assert len(snap.nodes) >= 4
        assert "pc1" in snap.nodes
        assert "frr1" in snap.nodes
        assert "pc2" in snap.nodes

        # Verify interfaces collected on pc1
        pc1_node = snap.nodes["pc1"]
        assert "eth1" in pc1_node.interfaces
        assert pc1_node.interfaces["eth1"].oper_state == "UP"
        assert pc1_node.interfaces["eth1"].admin_state == "UP"
        assert len(pc1_node.interfaces["eth1"].ipv4_addresses) > 0

        # Verify routes collected on frr1 (FRR vtysh json or text)
        frr_node = snap.nodes["frr1"]
        assert len(frr_node.routes) > 0
        prefixes = [r.prefix for r in frr_node.routes]
        assert any("10." in p for p in prefixes)

        # Verify reachability probes ran
        assert len(snap.reachability_matrix) > 0
        pc1_to_pc2 = [r for r in snap.reachability_matrix if r.source == "pc1" and r.destination == "pc2"]
        assert len(pc1_to_pc2) == 1
        assert pc1_to_pc2[0].reachable is True
        assert pc1_to_pc2[0].packet_loss_pct == 0.0

        assert snap.is_healthy() is True

    def test_snapshotter_detects_injected_fault(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Snapshotter detects link down and route drop injected into mock lab."""
        injector = FaultInjector()
        adapter = MockContainerlabAdapter(fault_injector=injector)
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        # 1. Baseline capture
        baseline = NetworkStateSnapshotter.snapshot(adapter=adapter)
        assert baseline.is_healthy() is True

        # 2. Inject Link Down on pc1 eth1
        injector.add_rule(
            FaultRule(
                fault_type="interface_down",
                target_node="pc1",
                target_interface="eth1",
            )
        )

        # 3. Capture current snapshot
        current = NetworkStateSnapshotter.snapshot(adapter=adapter)

        # 4. Compute StateDiff
        diff = baseline.diff(current)
        assert diff.has_anomalies() is True
        assert diff.has_link_failure() is True
        assert "pc1" in diff.affected_nodes()

        # Oper state should be DOWN
        pc1_idiff = diff.interface_diffs["pc1"]
        assert "eth1" in pc1_idiff.changed
        assert pc1_idiff.changed["eth1"]["oper_state"][1] == "DOWN"

        # Reachability should drop
        assert diff.has_packet_loss() is True
        assert ("pc1", "pc2") in diff.reachability_diffs.newly_unreachable

        # LLM markdown summary
        md = diff.to_llm_markdown()
        assert "Links Down: pc1:eth1" in md
        assert "Unreachable: pc1->pc2" in md
        assert len(md.encode("utf-8")) < 500

    def test_snapshotter_target_nodes_scoping(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Snapshotter respects target_nodes scoping and only queries specified nodes."""
        adapter = MockContainerlabAdapter()
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        snapshotter = NetworkStateSnapshotter(lab_adapter=adapter)
        snap = snapshotter.capture_snapshot(target_nodes=["pc1", "pc2"])

        assert set(snap.nodes.keys()) == {"pc1", "pc2"}
        assert "frr1" not in snap.nodes
        assert "srl1" not in snap.nodes

    def test_snapshotter_detects_buffer_overlimit_fault(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Snapshotter detects buffer overlimit and packet drops injected via fault injector."""
        injector = FaultInjector()
        adapter = MockContainerlabAdapter(fault_injector=injector)
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        # Baseline snapshot
        baseline = NetworkStateSnapshotter.snapshot(adapter=adapter)

        # Inject buffer overlimit fault on frr1 eth1
        injector.add_rule(
            FaultRule(
                fault_type="buffer_overlimit",
                target_node="frr1",
                target_interface="eth1",
                dropped=50,
                overlimits=120,
            )
        )

        current = NetworkStateSnapshotter.snapshot(adapter=adapter)
        diff = baseline.diff(current)

        assert diff.has_anomalies() is True
        assert diff.has_packet_loss() is True
        assert "frr1" in diff.affected_nodes()
        assert "frr1" in diff.qdisc_diffs
        assert diff.qdisc_diffs["frr1"].changed["eth1"]["dropped_packets"] == (0, 50)
        assert diff.qdisc_diffs["frr1"].changed["eth1"]["overlimits"] == (0, 120)

    def test_snapshotter_robust_parsing_fallbacks(self) -> None:
        """Directly verify robust parsing of JSON and text CLI outputs."""
        adapter = MockContainerlabAdapter()
        snapshotter = NetworkStateSnapshotter(lab_adapter=adapter)

        # 1. IP Addr JSON
        json_ip_addr = json.dumps([
            {
                "ifname": "eth0",
                "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
                "mtu": 1500,
                "operstate": "UP",
                "addr_info": [{"family": "inet", "local": "192.168.1.10", "prefixlen": 24}],
            }
        ])
        ifaces_json = snapshotter._parse_ip_addr_json(json_ip_addr)
        assert "eth0" in ifaces_json
        assert ifaces_json["eth0"].oper_state == "UP"
        assert ifaces_json["eth0"].ipv4_addresses == ["192.168.1.10/24"]

        # 2. IP Addr Text CLI
        text_ip_addr = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
            "    inet 172.16.1.1/24 scope global eth1\n"
        )
        ifaces_text = snapshotter._parse_ip_addr_text(text_ip_addr)
        assert "eth1" in ifaces_text
        assert ifaces_text["eth1"].oper_state == "UP"
        assert ifaces_text["eth1"].ipv4_addresses == ["172.16.1.1/24"]

        # 3. FRR Routes JSON
        json_routes = json.dumps({
            "172.16.10.0/24": [
                {
                    "protocol": "bgp",
                    "nexthops": [{"ip": "172.16.254.1", "interfaceName": "eth2", "active": True}],
                }
            ]
        })
        frr_routes = snapshotter._parse_frr_routes_json(json_routes)
        assert len(frr_routes) == 1
        assert frr_routes[0].prefix == "172.16.10.0/24"
        assert frr_routes[0].next_hop == "172.16.254.1"
        assert frr_routes[0].protocol == "bgp"

        # 4. Linux Routes Text CLI
        text_linux_routes = (
            "default via 10.0.0.1 dev eth0 proto static\n"
            "10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2\n"
        )
        linux_routes = snapshotter._parse_linux_routes_text(text_linux_routes)
        assert len(linux_routes) == 2
        assert linux_routes[0].prefix == "default"
        assert linux_routes[0].next_hop == "10.0.0.1"

        # 5. Ping parser: 0% loss, 100% loss, and partial loss
        success_ping = (
            "--- 10.1.1.2 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 2000ms\n"
            "rtt min/avg/max/mdev = 0.075/0.082/0.090/0.005 ms"
        )
        reach, loss, rtt = snapshotter._parse_ping_output(success_ping)
        assert reach is True
        assert loss == 0.0
        assert rtt == 0.082

        fail_ping = (
            "--- 10.1.1.2 ping statistics ---\n"
            "3 packets transmitted, 0 received, 100% packet loss, time 2000ms"
        )
        reach, loss, rtt = snapshotter._parse_ping_output(fail_ping)
        assert reach is False
        assert loss == 100.0

    def test_massive_anomalies_hard_truncation(self) -> None:
        """When dozens of anomalies occur, to_llm_markdown is strictly truncated to <500 bytes."""
        changed_ifaces = {
            f"eth{i}": {"oper_state": ("UP", "DOWN")}
            for i in range(1, 30)
        }
        diff = StateDiff(
            interface_diffs={
                f"spine{i}": InterfaceDiff(node=f"spine{i}", changed=changed_ifaces)
                for i in range(1, 5)
            },
            reachability_diffs=ReachabilityDiff(
                newly_unreachable=[(f"h{i}", f"h{j}") for i in range(1, 10) for j in range(1, 10) if i != j],
            ),
        )

        md = diff.to_llm_markdown()
        byte_len = len(md.encode("utf-8"))
        assert byte_len < 500, f"Markdown exceeded 500 bytes under stress: {byte_len} bytes"
        assert "... [truncated]" in md

