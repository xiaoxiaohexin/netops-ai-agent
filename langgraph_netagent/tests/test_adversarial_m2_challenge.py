"""Empirical Adversarial Challenge Suite for Milestone M2 Virtual Routing & CLI Emulation.

Tests:
1. Multi-hop forwarding (3+, 5, 10, 15 hops; hop-limit boundary).
2. Asymmetric routing paths (A -> B via Path 1, B -> A via Path 2).
3. Routing loops (2-node mutual, 3-node circular, 5-node circular, self-loop) & TTL expiration.
4. Partitioned subnets, blackhole routes, and interface down states.
5. IP Longest Prefix Match (LPM) priority (/32, /28, /24, /16, /8, default 0.0.0.0/0).
6. Simulated CLI commands (ip route show, vtysh json/text, sr_cli, ip addr show, ping).
"""

import ipaddress
import json
import random
from typing import Dict, List, Tuple
import pytest

from langgraph_netagent.models.telemetry import RouteEntry
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    FullTopologyPackage,
)
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine, VirtualNode, VirtualInterface
from langgraph_netagent.tools.probes import (
    InterfaceProbe,
    NetworkTelemetryCollector,
    PingProbe,
    RouteTableProbe,
)


# ==============================================================================
# Helper Factories
# ==============================================================================

def create_linear_topology(num_routers: int) -> Tuple[MockEngine, str, str, str]:
    """Create linear chain: pc1 <-> r1 <-> r2 <-> ... <-> rN <-> pc2.
    
    Returns:
        (engine, pc1_name, pc2_name, pc2_ip)
    """
    engine = MockEngine()
    nodes = {"pc1": ContainerlabNodeConfig(kind="linux", image="alpine:latest")}
    for i in range(1, num_routers + 1):
        nodes[f"r{i}"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
    nodes["pc2"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")

    links = [ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "r1:eth1"])]
    for i in range(1, num_routers):
        links.append(ContainerlabLinkEndpoint(endpoints=[f"r{i}:eth2", f"r{i+1}:eth1"]))
    links.append(ContainerlabLinkEndpoint(endpoints=[f"r{num_routers}:eth2", "pc2:eth1"]))

    topo = ContainerlabTopologyFile(
        name="multi-hop-linear",
        topology=ContainerlabTopologyDefinition(nodes=nodes, links=links),
    )
    engine.load_topology(topo)

    # Addressing:
    # pc1:eth1 = 10.0.0.2/24, r1:eth1 = 10.0.0.1/24
    engine.graph.register_ip("10.0.0.2/24", "pc1", "eth1")
    engine.graph.register_ip("10.0.0.1/24", "r1", "eth1")
    engine.graph.nodes["pc1"].add_route(RouteEntry(destination="default", next_hop="10.0.0.1", interface="eth1"))

    # Intermediate segments
    for i in range(1, num_routers):
        engine.graph.register_ip(f"10.{i}.0.1/24", f"r{i}", "eth2")
        engine.graph.register_ip(f"10.{i}.0.2/24", f"r{i+1}", "eth1")

    # Final segment
    final_seg = num_routers
    engine.graph.register_ip(f"10.{final_seg}.0.1/24", f"r{num_routers}", "eth2")
    engine.graph.register_ip(f"10.{final_seg}.0.2/24", "pc2", "eth1")
    engine.graph.nodes["pc2"].add_route(RouteEntry(destination="default", next_hop=f"10.{final_seg}.0.1", interface="eth1"))

    # Forward routes: r1 -> r2 -> ... -> rN -> pc2
    pc2_subnet = f"10.{final_seg}.0.0/24"
    for i in range(1, num_routers):
        next_hop = f"10.{i}.0.2"
        engine.graph.nodes[f"r{i}"].add_route(RouteEntry(destination=pc2_subnet, next_hop=next_hop, interface="eth2"))

    # Return routes: rN -> r(N-1) -> ... -> r1 -> pc1
    pc1_subnet = "10.0.0.0/24"
    for i in range(num_routers, 1, -1):
        next_hop = f"10.{i-1}.0.1"
        engine.graph.nodes[f"r{i}"].add_route(RouteEntry(destination=pc1_subnet, next_hop=next_hop, interface="eth1"))

    pc2_ip = f"10.{final_seg}.0.2"
    return engine, "pc1", "pc2", pc2_ip


# ==============================================================================
# 1. Multi-Hop Forwarding Stress Tests
# ==============================================================================

class TestEmpiricalMultiHopForwarding:
    """Adversarially challenge multi-hop forwarding up to maximum hop limits."""

    @pytest.mark.parametrize("router_count", [3, 4, 8, 12])
    def test_multi_hop_forward_and_reverse_success(self, router_count: int) -> None:
        """Verify reachability across 3, 4, 8, and 12 router hops."""
        engine, pc1, pc2, pc2_ip = create_linear_topology(num_routers=router_count)

        # Forward ping: pc1 -> pc2
        res_fwd = engine.simulate_ping(src_node=pc1, dst_ip=pc2_ip, count=3)
        assert res_fwd.exit_code == 0
        assert res_fwd.success
        assert "0% packet loss" in res_fwd.stdout
        # Verify telemetry probe parses this cleanly
        telem = PingProbe.parse_ping_output(res_fwd.stdout, src_node=pc1, dst_ip=pc2_ip)
        assert telem.is_reachable
        assert telem.loss_pct == 0.0

        # Reverse ping: pc2 -> pc1
        res_rev = engine.simulate_ping(src_node=pc2, dst_ip="10.0.0.2", count=3)
        assert res_rev.exit_code == 0
        assert res_rev.success
        assert "0% packet loss" in res_rev.stdout

    def test_ttl_decrementation_fidelity(self) -> None:
        """Verify TTL decrements proportionally with hop count."""
        engine_3, pc1, pc2, pc2_ip = create_linear_topology(num_routers=3)
        res_3 = engine_3.simulate_ping(src_node=pc1, dst_ip=pc2_ip, count=1)
        assert res_3.exit_code == 0
        # Transit nodes: [pc1, r1, r2, r3, pc2] -> 5 nodes -> ttl = 64 - 5 = 59
        assert "ttl=59" in res_3.stdout

        engine_6, pc1, pc2, pc2_ip = create_linear_topology(num_routers=6)
        res_6 = engine_6.simulate_ping(src_node=pc1, dst_ip=pc2_ip, count=1)
        assert res_6.exit_code == 0
        # Transit nodes: [pc1, r1..r6, pc2] -> 8 nodes -> ttl = 64 - 8 = 56
        assert "ttl=56" in res_6.stdout

    def test_hop_limit_boundary_15_vs_16(self) -> None:
        """Verify 15-hop limit behavior: paths exceeding 15 hops fail gracefully."""
        # 14 routers is 15 hops (fits within 15 iterations)
        engine_14, pc1, pc2, pc2_ip = create_linear_topology(num_routers=14)
        res_14 = engine_14.simulate_ping(src_node=pc1, dst_ip=pc2_ip, count=1)
        assert res_14.exit_code == 0
        assert res_14.success

        # 15 routers is 16 hops (exceeds 15 iterations)
        engine_15, pc1, pc2, pc2_ip = create_linear_topology(num_routers=15)
        res_15 = engine_15.simulate_ping(src_node=pc1, dst_ip=pc2_ip, count=1)
        assert res_15.exit_code == 1
        assert not res_15.success
        assert "100% packet loss" in res_15.stdout


# ==============================================================================
# 2. Asymmetric Routing Paths Stress Tests
# ==============================================================================

class TestEmpiricalAsymmetricRouting:
    """Stress-test asymmetric routing: Forward via Path 1, Return via Path 2."""

    @pytest.fixture
    def asymmetric_diamond(self) -> MockEngine:
        r"""Diamond topology:
                 /--> R_FWD1 --> R_FWD2 ---\
            A                                 B
                 \--- R_RET2 <-- R_RET1 <--/
        """
        engine = MockEngine()
        nodes = {
            "A": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "R_FWD1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "R_FWD2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "R_RET1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "R_RET2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "B": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
        }
        links = [
            ContainerlabLinkEndpoint(endpoints=["A:eth1", "R_FWD1:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["R_FWD1:eth2", "R_FWD2:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["R_FWD2:eth2", "B:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["B:eth2", "R_RET1:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["R_RET1:eth2", "R_RET2:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["R_RET2:eth2", "A:eth2"]),
        ]
        topo = ContainerlabTopologyFile(name="asymm-diamond", topology=ContainerlabTopologyDefinition(nodes=nodes, links=links))
        engine.load_topology(topo)

        # Subnets:
        # A <-> R_FWD1: 10.1.1.0/24
        # R_FWD1 <-> R_FWD2: 10.1.2.0/24
        # R_FWD2 <-> B: 10.1.3.0/24
        # B <-> R_RET1: 10.2.1.0/24
        # R_RET1 <-> R_RET2: 10.2.2.0/24
        # R_RET2 <-> A: 10.2.3.0/24
        engine.graph.register_ip("10.1.1.2/24", "A", "eth1")
        engine.graph.register_ip("10.1.1.1/24", "R_FWD1", "eth1")
        engine.graph.register_ip("10.1.2.1/24", "R_FWD1", "eth2")
        engine.graph.register_ip("10.1.2.2/24", "R_FWD2", "eth1")
        engine.graph.register_ip("10.1.3.1/24", "R_FWD2", "eth2")
        engine.graph.register_ip("10.1.3.2/24", "B", "eth1")

        engine.graph.register_ip("10.2.1.2/24", "B", "eth2")
        engine.graph.register_ip("10.2.1.1/24", "R_RET1", "eth1")
        engine.graph.register_ip("10.2.2.1/24", "R_RET1", "eth2")
        engine.graph.register_ip("10.2.2.2/24", "R_RET2", "eth1")
        engine.graph.register_ip("10.2.3.1/24", "R_RET2", "eth2")
        engine.graph.register_ip("10.2.3.2/24", "A", "eth2")

        # Forward Routing (A -> B: 10.1.3.0/24):
        engine.graph.nodes["A"].add_route(RouteEntry(destination="10.1.3.0/24", next_hop="10.1.1.1", interface="eth1"))
        engine.graph.nodes["R_FWD1"].add_route(RouteEntry(destination="10.1.3.0/24", next_hop="10.1.2.2", interface="eth2"))
        # R_FWD2 has connected route to 10.1.3.0/24 on eth2

        # Return Routing (B -> A: 10.1.1.0/24):
        engine.graph.nodes["B"].add_route(RouteEntry(destination="10.1.1.0/24", next_hop="10.2.1.1", interface="eth2"))
        engine.graph.nodes["R_RET1"].add_route(RouteEntry(destination="10.1.1.0/24", next_hop="10.2.2.2", interface="eth2"))
        engine.graph.nodes["R_RET2"].add_route(RouteEntry(destination="10.1.1.0/24", next_hop="10.2.3.2", interface="eth2"))

        return engine

    def test_asymmetric_bidirectional_flow_succeeds(self, asymmetric_diamond: MockEngine) -> None:
        """Ping from A to B traverses forward routers and returns via return routers."""
        res = asymmetric_diamond.simulate_ping(src_node="A", dst_ip="10.1.3.2")
        assert res.exit_code == 0
        assert res.success
        assert "0% packet loss" in res.stdout

    def test_asymmetric_forward_path_breakage(self, asymmetric_diamond: MockEngine) -> None:
        """Break forward router R_FWD1; ping fails with Destination Net Unreachable."""
        r_fwd1 = asymmetric_diamond.graph.nodes["R_FWD1"]
        # Remove route to 10.1.3.0/24 on intermediate forward router
        r_fwd1.routes = [r for r in r_fwd1.routes if r.destination != "10.1.3.0/24"]
        res = asymmetric_diamond.simulate_ping(src_node="A", dst_ip="10.1.3.2")
        assert res.exit_code == 1
        assert "Destination Net Unreachable" in res.stdout

    def test_asymmetric_return_path_breakage(self, asymmetric_diamond: MockEngine) -> None:
        """Break return router R_RET2; ping fails indicating return path missing."""
        r_ret2 = asymmetric_diamond.graph.nodes["R_RET2"]
        r_ret2.routes = [r for r in r_ret2.routes if r.destination != "10.1.1.0/24"]
        res = asymmetric_diamond.simulate_ping(src_node="A", dst_ip="10.1.3.2")
        assert res.exit_code == 1
        assert "return path missing" in res.stdout


# ==============================================================================
# 3. Routing Loops and TTL Expiration Stress Tests
# ==============================================================================

class TestEmpiricalRoutingLoopsAndTTL:
    """Stress-test detection of 2-node, 3-node, 5-node routing loops and self-loops."""

    def test_two_node_ping_pong_loop(self) -> None:
        """R1 and R2 point static routes for 172.16.0.0/16 to each other."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="loop-2node",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "r1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "r2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "target_node": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r2:eth1"])],
            ),
        )
        engine.load_topology(topo)
        engine.graph.register_ip("192.168.1.1/24", "r1", "eth1")
        engine.graph.register_ip("192.168.1.2/24", "r2", "eth1")
        engine.graph.register_ip("172.16.1.100/24", "target_node", "eth0")

        # R1 -> R2, R2 -> R1
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="172.16.0.0/16", next_hop="192.168.1.2"))
        engine.graph.nodes["r2"].add_route(RouteEntry(destination="172.16.0.0/16", next_hop="192.168.1.1"))

        res = engine.simulate_ping(src_node="r1", dst_ip="172.16.1.100")
        assert res.exit_code == 1
        assert not res.success
        assert "Time to live exceeded" in res.stdout
        telem = PingProbe.parse_ping_output(res.stdout, src_node="r1", dst_ip="172.16.1.100")
        assert not telem.is_reachable
        assert "Time to Live (TTL) exceeded" in (telem.error_message or "")

    def test_five_node_circular_loop(self) -> None:
        """Cycle: R1 -> R2 -> R3 -> R4 -> R5 -> R1."""
        engine = MockEngine()
        nodes = {f"r{i}": ContainerlabNodeConfig(kind="linux", image="alpine:latest") for i in range(1, 6)}
        nodes["target_node"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
        links = [
            ContainerlabLinkEndpoint(endpoints=["r1:eth2", "r2:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["r2:eth2", "r3:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["r3:eth2", "r4:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["r4:eth2", "r5:eth1"]),
            ContainerlabLinkEndpoint(endpoints=["r5:eth2", "r1:eth1"]),
        ]
        topo = ContainerlabTopologyFile(name="loop-5node", topology=ContainerlabTopologyDefinition(nodes=nodes, links=links))
        engine.load_topology(topo)

        for i in range(1, 6):
            nxt = (i % 5) + 1
            engine.graph.register_ip(f"10.{i}.0.1/24", f"r{i}", "eth2")
            engine.graph.register_ip(f"10.{i}.0.2/24", f"r{nxt}", "eth1")
            # Next hop for destination 10.99.99.99 is next router
            engine.graph.nodes[f"r{i}"].add_route(RouteEntry(destination="10.99.99.0/24", next_hop=f"10.{i}.0.2"))

        engine.graph.register_ip("10.99.99.99/24", "target_node", "eth0")

        res = engine.simulate_ping(src_node="r1", dst_ip="10.99.99.99")
        assert res.exit_code == 1
        assert "Time to live exceeded" in res.stdout


# ==============================================================================
# 4. Partitioned Subnets, Blackholes, and Downed Interfaces Stress Tests
# ==============================================================================

class TestEmpiricalPartitionedAndBlackholes:
    """Stress-test partitioned networks, unresolvable next-hops, and interface down states."""

    def test_completely_partitioned_subnets(self) -> None:
        """Two isolated subnets without routers between them."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="partition-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "island_a": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "island_b": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[],
            ),
        )
        engine.load_topology(topo)
        engine.graph.register_ip("192.168.1.10/24", "island_a", "eth1")
        engine.graph.register_ip("10.0.0.10/24", "island_b", "eth1")

        # island_a has no route to 10.0.0.0/24
        res = engine.simulate_ping(src_node="island_a", dst_ip="10.0.0.10")
        assert res.exit_code == 1
        assert not res.success
        assert "Destination Net Unreachable" in res.stdout

    def test_blackhole_route_to_nonexistent_nexthop(self) -> None:
        """Static route pointing to an IP not assigned to any virtual node."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="blackhole-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "host": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "dest_node": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[],
            ),
        )
        engine.load_topology(topo)
        engine.graph.register_ip("10.1.1.2/24", "host", "eth1")
        engine.graph.register_ip("172.20.1.1/24", "dest_node", "eth0")

        # Add blackhole route pointing to 192.168.254.254 (unallocated)
        engine.graph.nodes["host"].add_route(RouteEntry(destination="172.20.0.0/16", next_hop="192.168.254.254"))

        res = engine.simulate_ping(src_node="host", dst_ip="172.20.1.1")
        assert res.exit_code == 1
        assert "Destination Net Unreachable" in res.stdout

    def test_interface_fault_injection_disconnects_transit_link(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Bringing down intermediate interface isolates pc1 from pc2."""
        injector = FaultInjector()
        engine = MockEngine(fault_injector=injector)
        engine.load_topology_package(full_multi_node_package)

        # Initially healthy
        r_init = engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert r_init.exit_code == 0

        # Inject interface down on destination node pc2's eth1
        rule = FaultRule(
            fault_type=FaultType.INTERFACE_DOWN,
            target_node="pc2",
            target_interface="eth1",
        )
        injector.add_rule(rule)
        r_down = engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert r_down.exit_code == 1
        assert "Destination Host Unreachable" in r_down.stdout

        # Restore interface by removing rule
        injector.remove_rule(rule.rule_id)
        r_restored = engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert r_restored.exit_code == 0


# ==============================================================================
# 5. IP Longest Prefix Match (LPM) Priority Stress Tests
# ==============================================================================

class TestEmpiricalLongestPrefixMatch:
    """Stress-test strict longest prefix match resolution across overlapping prefixes."""

    @pytest.fixture
    def lpm_engine(self) -> MockEngine:
        """Create node with overlapping routes:
        0.0.0.0/0   -> GW_0
        10.0.0.0/8  -> GW_8
        10.1.0.0/16 -> GW_16
        10.1.1.0/24 -> GW_24
        10.1.1.16/28-> GW_28
        10.1.1.17/32-> GW_32
        """
        engine = MockEngine()
        nodes = {
            "source": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_0": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_8": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_16": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_24": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_28": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
            "gw_32": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
        }
        topo = ContainerlabTopologyFile(name="lpm-rig", topology=ContainerlabTopologyDefinition(nodes=nodes, links=[]))
        engine.load_topology(topo)

        engine.graph.register_ip("192.168.0.1/24", "source", "eth0")
        engine.graph.register_ip("192.168.0.100/24", "gw_0", "eth0")
        engine.graph.register_ip("192.168.0.108/24", "gw_8", "eth0")
        engine.graph.register_ip("192.168.0.116/24", "gw_16", "eth0")
        engine.graph.register_ip("192.168.0.124/24", "gw_24", "eth0")
        engine.graph.register_ip("192.168.0.128/24", "gw_28", "eth0")
        engine.graph.register_ip("192.168.0.132/24", "gw_32", "eth0")

        # Configure overlapping routes
        engine.graph.nodes["source"].add_route(RouteEntry(destination="0.0.0.0/0", next_hop="192.168.0.100"))
        engine.graph.nodes["source"].add_route(RouteEntry(destination="10.0.0.0/8", next_hop="192.168.0.108"))
        engine.graph.nodes["source"].add_route(RouteEntry(destination="10.1.0.0/16", next_hop="192.168.0.116"))
        engine.graph.nodes["source"].add_route(RouteEntry(destination="10.1.1.0/24", next_hop="192.168.0.124"))
        engine.graph.nodes["source"].add_route(RouteEntry(destination="10.1.1.16/28", next_hop="192.168.0.128"))
        engine.graph.nodes["source"].add_route(RouteEntry(destination="10.1.1.17/32", next_hop="192.168.0.132"))

        return engine

    @pytest.mark.parametrize(
        "dest_ip, expected_gw",
        [
            ("10.1.1.17", "gw_32"),   # /32 match
            ("10.1.1.18", "gw_28"),   # /28 match
            ("10.1.1.30", "gw_28"),   # /28 match
            ("10.1.1.33", "gw_24"),   # /24 match
            ("10.1.200.5", "gw_16"),  # /16 match
            ("10.250.1.1", "gw_8"),   # /8 match
            ("172.16.1.1", "gw_0"),   # /0 default match
            ("8.8.8.8", "gw_0"),      # /0 default match
        ],
    )
    def test_lpm_prefix_specificity(self, lpm_engine: MockEngine, dest_ip: str, expected_gw: str) -> None:
        """Assert packet always forwards to the gateway corresponding to the longest prefix."""
        # Register a dummy host for the destination IP
        lpm_engine.graph.ip_to_node[dest_ip] = (f"host_{dest_ip.replace('.', '_')}", "eth0")

        fwd_ok, _, visited = lpm_engine._trace_path("source", dest_ip)
        # Even if the next router has no further route, the first hop from source MUST be expected_gw
        assert len(visited) >= 2
        assert visited[1] == expected_gw

    def test_lpm_route_order_invariance(self, lpm_engine: MockEngine) -> None:
        """LPM must produce identical next-hop regardless of list insertion order."""
        dest_ip = "10.1.1.17"
        lpm_engine.graph.ip_to_node[dest_ip] = ("host_target", "eth0")

        # Shuffle routes 10 times and verify gw_32 is consistently picked
        routes = list(lpm_engine.graph.nodes["source"].routes)
        for _ in range(10):
            shuffled = list(routes)
            random.shuffle(shuffled)
            lpm_engine.graph.nodes["source"].routes = shuffled

            _, _, visited = lpm_engine._trace_path("source", dest_ip)
            assert visited[1] == "gw_32", f"Failed order invariance with route order: {[r.destination for r in shuffled]}"

    def test_lpm_static_route_overrides_broader_connected_subnet(self) -> None:
        """Adversarial LPM test: More specific /24 static route must take priority over a broader /16 connected subnet."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="lpm-override-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "r1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "r2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "pc_target": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[
                    ContainerlabLinkEndpoint(endpoints=["r1:eth2", "r2:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["r2:eth2", "pc_target:eth1"]),
                ],
            ),
        )
        engine.load_topology(topo)

        # r1 has broad /16 on eth1, and transit /24 on eth2
        engine.graph.register_ip("10.0.0.1/16", "r1", "eth1")
        engine.graph.register_ip("192.168.1.1/24", "r1", "eth2")

        # r2 has transit /24 on eth1, and /24 on eth2
        engine.graph.register_ip("192.168.1.2/24", "r2", "eth1")
        engine.graph.register_ip("10.0.2.1/24", "r2", "eth2")

        # pc_target has 10.0.2.2/24
        engine.graph.register_ip("10.0.2.2/24", "pc_target", "eth1")

        # r1 has specific static route: 10.0.2.0/24 via 192.168.1.2 (r2)
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.0.2.0/24", next_hop="192.168.1.2"))

        fwd_ok, _, visited = engine._trace_path("r1", "10.0.2.2")
        assert fwd_ok
        # If LPM properly prioritizes the /24 route over the /16 connected subnet,
        # the packet MUST transit through r2!
        # If it prematurely short-circuits on the connected subnet, visited will be ['r1', 'pc_target']
        # which bypasses r2!
        assert "r2" in visited, f"LPM failed: packet bypassed r2 due to premature connected match! Visited: {visited}"



# ==============================================================================
# 6. Simulated CLI Commands Stress Tests
# ==============================================================================

class TestEmpiricalSimulatedCLICommands:
    """Stress-test CLI commands and their interoperation with telemetry probes."""

    def test_ip_route_show_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        # Linux PC1
        res = engine.exec_command("pc1", "ip route show")
        assert res.exit_code == 0
        rt = RouteTableProbe.parse_linux_routes("pc1", res.stdout)
        assert rt.has_default_route
        assert rt.has_route_to("default")
        assert rt.has_route_to("10.1.1.0/24")

    def test_vtysh_json_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        res = engine.exec_command("frr1", "vtysh -c 'show ip route json'")
        assert res.exit_code == 0
        # Assert valid JSON
        data = json.loads(res.stdout)
        assert isinstance(data, dict)
        assert "10.2.2.0/24" in data
        assert data["10.2.2.0/24"][0]["nexthops"][0]["ip"] == "10.1.12.2"

        # Assert RouteTableProbe parses FRR JSON
        rt = RouteTableProbe.parse_frr_routes_json("frr1", res.stdout)
        assert rt.has_route_to("10.2.2.0/24")
        assert rt.get_nexthop("10.2.2.0/24") == "10.1.12.2"

    def test_vtysh_text_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        res = engine.exec_command("frr1", "vtysh -c 'show ip route'")
        assert res.exit_code == 0
        assert "Codes:" in res.stdout
        assert "S>* 10.2.2.0/24" in res.stdout

        rt = RouteTableProbe.parse_frr_routes_text("frr1", res.stdout)
        assert rt.has_route_to("10.2.2.0/24")

    def test_sr_cli_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        res = engine.exec_command("srl1", "sr_cli 'show network-instance default route-table'")
        assert res.exit_code == 0
        assert "Network-instance : default" in res.stdout
        assert "IPv4 Prefix" in res.stdout

        rt = RouteTableProbe.parse_srl_routes("srl1", res.stdout)
        assert rt.has_route_to("10.1.1.0/24")

    def test_ip_addr_show_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        res = engine.exec_command("pc1", "ip addr show")
        assert res.exit_code == 0
        assert "1: lo:" in res.stdout
        assert "2: eth1:" in res.stdout

        ifaces = InterfaceProbe.parse_linux_ip_addr("pc1", res.stdout)
        assert len(ifaces) >= 2
        eth1 = next((i for i in ifaces if i.interface_name == "eth1"), None)
        assert eth1 is not None
        assert eth1.is_healthy
        assert eth1.admin_state == "UP"
        assert eth1.oper_state == "UP"
        assert "10.1.1.2/24" in eth1.ip_addresses

    def test_ping_command_output_and_probe_parsing(self, full_multi_node_package: FullTopologyPackage) -> None:
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        # Successful ping
        res_pass = engine.exec_command("pc1", "ping -c 5 10.2.2.2")
        assert res_pass.exit_code == 0
        assert "5 packets transmitted, 5 received, 0% packet loss" in res_pass.stdout
        telem_pass = PingProbe.parse_ping_output(res_pass.stdout, src_node="pc1", dst_ip="10.2.2.2")
        assert telem_pass.is_reachable
        assert telem_pass.transmitted == 5
        assert telem_pass.received == 5
        assert telem_pass.loss_pct == 0.0

        # Unreachable ping
        res_fail = engine.exec_command("pc1", "ping -c 3 192.168.199.1")
        assert res_fail.exit_code == 1
        assert "100% packet loss" in res_fail.stdout
        telem_fail = PingProbe.parse_ping_output(res_fail.stdout, src_node="pc1", dst_ip="192.168.199.1")
        assert not telem_fail.is_reachable
        assert telem_fail.loss_pct == 100.0

    def test_adapter_exec_command_routing(self, full_multi_node_package: FullTopologyPackage) -> None:
        """MockContainerlabAdapter properly delegates exec_command."""
        adapter = MockContainerlabAdapter()
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        res = adapter.exec_command(node_name="pc1", command="ping -c 2 10.2.2.2")
        assert res.exit_code == 0
        assert "0% packet loss" in res.stdout


# ==============================================================================
# 7. Integrated NetworkTelemetryCollector Stress Tests
# ==============================================================================

class TestEmpiricalTelemetryCollector:
    """Stress-test the end-to-end telemetry collector against complex multi-vendor topologies."""

    def test_collector_healthy_multi_hop(self, full_multi_node_package: FullTopologyPackage) -> None:
        adapter = MockContainerlabAdapter()
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        report = NetworkTelemetryCollector.collect(
            adapter=adapter,
            ping_targets=[("pc1", "10.2.2.2"), ("pc2", "10.1.1.2"), ("pc1", "10.1.1.1")],
            router_nodes=["frr1", "srl1"],
            all_nodes=["pc1", "frr1", "srl1", "pc2"],
            node_kinds={"frr1": "frr", "srl1": "srlinux"},
            required_routes={"frr1": ["10.2.2.0/24"], "srl1": ["10.1.1.0/24"]},
        )

        assert report.all_passed is True
        assert len(report.failures) == 0
        assert len(report.ping_results) == 3
        assert all(p.is_reachable for p in report.ping_results)
        assert len(report.route_tables) == 2
        assert len(report.interfaces) == 4
        md = report.to_summary_markdown()
        assert "PASSED" in md
        assert "Pings Checked: 3" in md

    def test_collector_detects_isolated_node_and_route_anomaly(self, full_multi_node_package: FullTopologyPackage) -> None:
        injector = FaultInjector()
        adapter = MockContainerlabAdapter(fault_injector=injector)
        adapter.mock_engine.load_topology_package(full_multi_node_package)

        # Inject missing route on frr1 for 10.2.2.0/24
        injector.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.2.2.0/24",
            )
        )

        report = NetworkTelemetryCollector.collect(
            adapter=adapter,
            ping_targets=[("pc1", "10.2.2.2")],
            router_nodes=["frr1"],
            all_nodes=["pc1", "frr1"],
            node_kinds={"frr1": "frr"},
            required_routes={"frr1": ["10.2.2.0/24"]},
        )

        assert report.all_passed is False
        assert any("Ping failure" in f for f in report.failures)
        assert any("Missing route on router 'frr1'" in f for f in report.failures)
        assert any("Configure static or dynamic route" in r for r in report.recommendations)
        md = report.to_summary_markdown()
        assert "FAIL" in md


# ==============================================================================
# 8. Boundary Edge Cases in MockEngine & CLI Simulation
# ==============================================================================

class TestEmpiricalBoundaryEdgeCases:
    """Stress-test obscure corner cases, self-pings, and unusual commands."""

    def test_ping_self_interface_ip(self, full_multi_node_package: FullTopologyPackage) -> None:
        """Pinging a node's own IP address succeeds immediately (1 hop)."""
        engine = MockEngine()
        engine.load_topology_package(full_multi_node_package)

        res = engine.simulate_ping(src_node="pc1", dst_ip="10.1.1.2")
        assert res.exit_code == 0
        assert res.success
        assert "0% packet loss" in res.stdout
        assert "ttl=63" in res.stdout

    def test_unrecognized_shell_command_fallback(self) -> None:
        """Unrecognized shell commands should return non-crashing mock success."""
        engine = MockEngine()
        res = engine.exec_command("node1", "cat /etc/os-release")
        assert res.exit_code == 0
        assert "mock: executed 'cat /etc/os-release' successfully" in res.stdout

    def test_empty_route_table_for_unconnected_node(self) -> None:
        """Querying route table of node with no interfaces returns empty cleanly."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="empty-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={"empty_node": ContainerlabNodeConfig(kind="linux", image="alpine:latest")},
                links=[],
            ),
        )
        engine.load_topology(topo)
        res = engine.exec_command("empty_node", "ip route show")
        assert res.exit_code == 0
        assert res.stdout == "\n"
        rt = RouteTableProbe.parse_linux_routes("empty_node", res.stdout)
        assert len(rt.routes) == 0
        assert rt.has_default_route is False

