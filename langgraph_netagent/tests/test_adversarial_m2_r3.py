"""Adversarial stress tests for Milestone M2 R3 verification.

Authored by challenger_net_m2_r3_1 to verify that all 8 previous defects
are genuinely resolved, robust against edge cases, and structurally sound.
"""

from typing import List
import pytest

from langgraph_netagent.models import (
    ContainerlabTopologyFile,
    ContainerlabTopologyDefinition,
    ContainerlabNodeConfig,
    ContainerlabLinkEndpoint,
    RouteEntry,
)
from langgraph_netagent.tools.fault_injector import (
    FaultInjector,
    FaultRule,
    FaultType,
    _matches_target_node,
)
from langgraph_netagent.tools.mock_engine import MockEngine
from langgraph_netagent.tools.probes import PingProbe, RouteTableProbe


class TestAdversarialLPMHierarchy:
    """Stress-test LPM candidate selection and hierarchy across connected and static routes."""

    @pytest.fixture
    def hierarchy_engine(self) -> MockEngine:
        """Build an engine with complex prefix hierarchy on r1."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="lpm-hierarchy-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "r1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "gw_default": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "gw_16": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "gw_24": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "gw_28": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "target_host": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[
                    ContainerlabLinkEndpoint(endpoints=["r1:eth0", "gw_default:eth0"]),
                    ContainerlabLinkEndpoint(endpoints=["r1:eth1", "gw_16:eth0"]),
                    ContainerlabLinkEndpoint(endpoints=["r1:eth2", "gw_24:eth0"]),
                    ContainerlabLinkEndpoint(endpoints=["r1:eth3", "gw_28:eth0"]),
                    ContainerlabLinkEndpoint(endpoints=["r1:eth4", "target_host:eth0"]),
                ],
            ),
        )
        engine.load_topology(topo)

        # Transit IPs on r1
        engine.graph.register_ip("192.168.0.1/24", "r1", "eth0")
        engine.graph.register_ip("192.168.0.2/24", "gw_default", "eth0")

        engine.graph.register_ip("192.168.1.1/24", "r1", "eth1")
        engine.graph.register_ip("192.168.1.2/24", "gw_16", "eth0")

        engine.graph.register_ip("192.168.2.1/24", "r1", "eth2")
        engine.graph.register_ip("192.168.2.2/24", "gw_24", "eth0")

        engine.graph.register_ip("192.168.3.1/24", "r1", "eth3")
        engine.graph.register_ip("192.168.3.2/24", "gw_28", "eth0")

        # Directly connected broad /16 on eth4
        engine.graph.register_ip("10.1.0.1/16", "r1", "eth4")
        engine.graph.register_ip("10.1.50.2/16", "target_host", "eth0")

        # Static routes with different prefix lengths
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="default", next_hop="192.168.0.2"))
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.1.0.0/16", next_hop="192.168.1.2"))
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.1.10.0/24", next_hop="192.168.2.2"))
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.1.10.16/28", next_hop="192.168.3.2"))

        return engine

    def test_lpm_tie_breaks_for_connected_subnet(self, hierarchy_engine: MockEngine) -> None:
        """When static route and connected subnet have identical /16 prefix, connected route wins (AD 0 vs AD 1)."""
        # Destination 10.1.50.2 matches connected 10.1.0.1/16 and static 10.1.0.0/16
        egress = hierarchy_engine._get_egress_interface("r1", "10.1.50.2")
        assert egress == "eth4", f"Expected connected eth4 on tie, got {egress}"

        ok, _, visited = hierarchy_engine._trace_path("r1", "10.1.50.2")
        assert ok is True
        assert visited == ["r1", "target_host"]

    def test_lpm_more_specific_static_overrides_connected(self, hierarchy_engine: MockEngine) -> None:
        """A /24 static route must override a /16 connected subnet."""
        # Destination 10.1.10.5 matches connected /16 and static /24
        egress = hierarchy_engine._get_egress_interface("r1", "10.1.10.5")
        assert egress == "eth2", f"Expected static /24 egress eth2, got {egress}"

        ok, _, visited = hierarchy_engine._trace_path("r1", "10.1.10.5")
        assert visited[1] == "gw_24"

    def test_lpm_most_specific_slash_28_overrides_slash_24_and_connected(
        self, hierarchy_engine: MockEngine
    ) -> None:
        """A /28 static route must override both /24 static and /16 connected."""
        # Destination 10.1.10.20 falls within 10.1.10.16/28
        egress = hierarchy_engine._get_egress_interface("r1", "10.1.10.20")
        assert egress == "eth3", f"Expected static /28 egress eth3, got {egress}"

        ok, _, visited = hierarchy_engine._trace_path("r1", "10.1.10.20")
        assert visited[1] == "gw_28"

    def test_lpm_unmatched_falls_back_to_default_gateway(self, hierarchy_engine: MockEngine) -> None:
        """Unmatched external IP falls back to default gateway (eth0)."""
        egress = hierarchy_engine._get_egress_interface("r1", "8.8.8.8")
        assert egress == "eth0", f"Expected default route egress eth0, got {egress}"


class TestAdversarialTransitInterfaceDown:
    """Stress-test transit interface down checking across multi-hop topologies."""

    @pytest.fixture
    def linear_chain(self) -> MockEngine:
        """Create 4-node chain: pc1 <-> r1 <-> r2 <-> r3 <-> pc2."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="linear-transit-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "pc1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "r1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "r2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "r3": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "pc2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[
                    ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "r1:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["r1:eth2", "r2:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["r2:eth2", "r3:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["r3:eth2", "pc2:eth1"]),
                ],
            ),
        )
        engine.load_topology(topo)

        engine.graph.register_ip("10.0.1.2/24", "pc1", "eth1")
        engine.graph.register_ip("10.0.1.1/24", "r1", "eth1")
        engine.graph.register_ip("10.0.12.1/24", "r1", "eth2")
        engine.graph.register_ip("10.0.12.2/24", "r2", "eth1")
        engine.graph.register_ip("10.0.23.1/24", "r2", "eth2")
        engine.graph.register_ip("10.0.23.2/24", "r3", "eth1")
        engine.graph.register_ip("10.0.2.1/24", "r3", "eth2")
        engine.graph.register_ip("10.0.2.2/24", "pc2", "eth1")

        # Forward routes
        engine.graph.nodes["pc1"].add_route(RouteEntry(destination="default", next_hop="10.0.1.1"))
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.0.2.0/24", next_hop="10.0.12.2"))
        engine.graph.nodes["r2"].add_route(RouteEntry(destination="10.0.2.0/24", next_hop="10.0.23.2"))
        engine.graph.nodes["r3"].add_route(RouteEntry(destination="10.0.2.0/24", next_hop=None, protocol="connected"))

        # Return routes
        engine.graph.nodes["pc2"].add_route(RouteEntry(destination="default", next_hop="10.0.2.1"))
        engine.graph.nodes["r3"].add_route(RouteEntry(destination="10.0.1.0/24", next_hop="10.0.23.1"))
        engine.graph.nodes["r2"].add_route(RouteEntry(destination="10.0.1.0/24", next_hop="10.0.12.1"))
        engine.graph.nodes["r1"].add_route(RouteEntry(destination="10.0.1.0/24", next_hop=None, protocol="connected"))

        return engine

    def test_healthy_chain_forwarding(self, linear_chain: MockEngine) -> None:
        """Verify baseline ping passes before faults."""
        res = linear_chain.simulate_ping("pc1", "10.0.2.2")
        assert res.exit_code == 0
        assert "0% packet loss" in res.stdout

    @pytest.mark.parametrize(
        ("node", "iface"),
        [
            ("r1", "eth2"),  # Transit hop 1 egress
            ("r2", "eth1"),  # Transit hop 1 ingress
            ("r2", "eth2"),  # Transit hop 2 egress
            ("r3", "eth1"),  # Transit hop 2 ingress
        ],
    )
    def test_each_transit_interface_failure_blocks_ping(
        self, linear_chain: MockEngine, node: str, iface: str
    ) -> None:
        """Downing any transit interface across multi-hop chain must fail ping."""
        linear_chain.fault_injector.clear_all()
        linear_chain.fault_injector.add_rule(
            FaultRule(fault_type=FaultType.INTERFACE_DOWN, target_node=node, target_interface=iface)
        )
        res = linear_chain.simulate_ping("pc1", "10.0.2.2")
        assert res.exit_code == 1
        assert "100% packet loss" in res.stdout


class TestAdversarialMultiHomedSourceIsolation:
    """Stress-test multi-homed source nodes with isolated interface failures."""

    @pytest.fixture
    def star_router(self) -> MockEngine:
        """Central router connecting 3 spoke hosts."""
        engine = MockEngine()
        topo = ContainerlabTopologyFile(
            name="star-lab",
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "hub": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "spoke1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "spoke2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    "spoke3": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                },
                links=[
                    ContainerlabLinkEndpoint(endpoints=["hub:eth1", "spoke1:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["hub:eth2", "spoke2:eth1"]),
                    ContainerlabLinkEndpoint(endpoints=["hub:eth3", "spoke3:eth1"]),
                ],
            ),
        )
        engine.load_topology(topo)

        engine.graph.register_ip("192.168.1.1/24", "hub", "eth1")
        engine.graph.register_ip("192.168.1.2/24", "spoke1", "eth1")

        engine.graph.register_ip("192.168.2.1/24", "hub", "eth2")
        engine.graph.register_ip("192.168.2.2/24", "spoke2", "eth1")

        engine.graph.register_ip("192.168.3.1/24", "hub", "eth3")
        engine.graph.register_ip("192.168.3.2/24", "spoke3", "eth1")

        engine.graph.nodes["spoke1"].add_route(RouteEntry(destination="default", next_hop="192.168.1.1"))
        engine.graph.nodes["spoke2"].add_route(RouteEntry(destination="default", next_hop="192.168.2.1"))
        engine.graph.nodes["spoke3"].add_route(RouteEntry(destination="default", next_hop="192.168.3.1"))

        return engine

    def test_single_interface_down_only_affects_that_branch(self, star_router: MockEngine) -> None:
        """Downing hub:eth2 must not affect pings between hub and spoke1 or spoke3."""
        star_router.fault_injector.add_rule(
            FaultRule(fault_type=FaultType.INTERFACE_DOWN, target_node="hub", target_interface="eth2")
        )

        # Spoke 1 is reachable
        assert star_router.simulate_ping("hub", "192.168.1.2").exit_code == 0
        # Spoke 3 is reachable
        assert star_router.simulate_ping("hub", "192.168.3.2").exit_code == 0
        # Spoke 2 is unreachable
        res2 = star_router.simulate_ping("hub", "192.168.2.2")
        assert res2.exit_code == 1
        assert "Network is unreachable" in res2.stdout


class TestAdversarialFaultInjectorScoping:
    """Stress-test target node scoping and base-name matching."""

    def test_missing_route_target_node_strictly_isolated(self) -> None:
        """MISSING_ROUTE on frr1 is not cleared by srl1 or pc1."""
        fi = FaultInjector()
        fi.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.50.0.0/24",
                cleared_on_remediation=True,
            )
        )

        # Redeploy unrelated configs containing the prefix
        fi.on_redeploy({
            "config/srl/srl.cfg": "set / static-route 10.50.0.0/24 next-hop 1.1.1.1",
            "config/pc1/setup.sh": "ip route add 10.50.0.0/24 via 1.1.1.1",
        })
        assert len(fi.get_active_rules()) == 1, "Fault on frr1 should not be cleared by srl or pc configs"

        # Redeploy frr config clears the fault
        fi.on_redeploy({"config/frr/frr.conf": "ip route 10.50.0.0/24 1.1.1.1"})
        assert len(fi.get_active_rules()) == 0, "Fault on frr1 should be cleared by frr.conf"

    def test_ping_drop_target_node_strictly_isolated(self) -> None:
        """PING_DROP on pc1 is not cleared by pc2 redeployment."""
        fi = FaultInjector()
        fi.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.2.2.2",
                cleared_on_remediation=True,
            )
        )

        # Redeploy pc2 config mentioning 10.2.2.2
        fi.on_redeploy({"config/pc2/setup.sh": "ip addr add 10.2.2.2/24 dev eth1"})
        assert len(fi.get_active_rules()) == 1, "PING_DROP on pc1 must not be cleared by pc2 config"

        # Redeploy pc1 config mentioning 10.2.2.2
        fi.on_redeploy({"config/pc1/setup.sh": "ping -c 1 10.2.2.2"})
        assert len(fi.get_active_rules()) == 0, "PING_DROP on pc1 should be cleared by pc1 config"


class TestAdversarialProbeParsers:
    """Stress-test telemetry probe parsers with unusual and multi-metric formats."""

    def test_ping_probe_submillisecond_and_integer_values(self) -> None:
        """Parse submillisecond BusyBox and integer metrics."""
        raw_submilli = """
--- 10.1.1.1 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.015/0.024/0.038 ms
"""
        res = PingProbe.parse_ping_output(raw_submilli, "pc1", "10.1.1.1")
        assert res.rtt_min_ms == 0.015
        assert res.rtt_avg_ms == 0.024
        assert res.rtt_max_ms == 0.038
        assert res.rtt_mdev_ms is None

    def test_srl_route_parser_all_special_nexthops(self) -> None:
        """SRL parser accepts blackhole, discard, unresolved, indirect, and direct."""
        raw_srl = """
-------------------------------------------------------------------
Network-instance : default
-------------------------------------------------------------------
IPv4 Prefix          Type         Next-hop           Interface   
-------------------------------------------------------------------
0.0.0.0/0            static       192.168.1.1        ethernet-1/1
10.0.1.0/24          local        direct             ethernet-1/2
10.0.2.0/24          static       blackhole          none        
10.0.3.0/24          static       discard            none        
10.0.4.0/24          static       unresolved         none        
10.0.5.0/24          static       indirect           none        
-------------------------------------------------------------------
"""
        rt = RouteTableProbe.parse_srl_routes("srl1", raw_srl)
        assert rt.has_default_route is True
        for pfx in ["0.0.0.0/0", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24", "10.0.5.0/24"]:
            assert rt.has_route_to(pfx), f"Route to {pfx} was dropped"
