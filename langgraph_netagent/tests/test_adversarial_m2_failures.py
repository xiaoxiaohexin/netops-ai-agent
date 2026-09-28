"""Empirical tests demonstrating confirmed failure modes and vulnerabilities in M2.

Each test is marked with @pytest.mark.xfail documenting the exact defect observed,
allowing verification without breaking baseline test suites.
"""

from pathlib import Path
import pytest

from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockEngine
from langgraph_netagent.tools.probes import PingProbe, RouteTableProbe


class TestEmpiricalDefectsM2:
    """Empirical proof of defects in FaultInjector, MockEngine, and Probes (now remediated)."""

    def test_defect_1_false_positive_clearing_from_unrelated_node(self) -> None:
        """A missing route on frr1 should NOT be cleared when srl1 config is deployed."""
        fi = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.MISSING_ROUTE,
            target_node="frr1",
            target_ip_or_prefix="10.2.2.0/24",
            cleared_on_remediation=True,
        )
        fi.add_rule(rule)

        # Deploy config for srl1 that happens to mention 10.2.2.0/24
        fi.on_redeploy({"config/srl/srl.cfg": "set / interface e1-2 10.2.2.0/24"})

        # Specification: Rule on frr1 should still be active
        assert len(fi.get_active_rules()) == 1

    def test_defect_2_ping_drop_cleared_by_other_node_config(self) -> None:
        """A ping drop rule on pc1 should NOT be cleared when pc2 config is deployed."""
        fi = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.PING_DROP,
            target_node="pc1",
            target_ip_or_prefix="10.2.2.2",
            cleared_on_remediation=True,
        )
        fi.add_rule(rule)

        # Deploy pc2 config containing 10.2.2.2
        fi.on_redeploy({"config/pc2/setup.sh": "ip addr add 10.2.2.2/24 dev eth1"})

        # Specification: Rule on pc1 must remain active
        assert len(fi.get_active_rules()) == 1

    def test_defect_3_interface_down_fails_to_clear_on_matching_redeploy(self) -> None:
        """INTERFACE_DOWN on frr1 should clear when frr1's frr.conf is deployed."""
        fi = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.INTERFACE_DOWN,
            target_node="frr1",
            target_interface="eth1",
            cleared_on_remediation=True,
        )
        fi.add_rule(rule)

        # Redeploy frr1's actual config path from containerlab (config/frr/frr.conf)
        fi.on_redeploy({"config/frr/frr.conf": "interface eth1\n ip address 10.1.1.1/24\n"})

        # Specification: Rule on frr1 should be cleared
        assert len(fi.get_active_rules()) == 0

    def test_defect_4_transit_interface_down_is_bypassed(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        """If transit interface frr1:eth2 is DOWN, routed ping from pc1 to pc2 must fail."""
        mock_engine.load_topology_package(full_multi_node_package)

        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.INTERFACE_DOWN,
                target_node="frr1",
                target_interface="eth2",
            )
        )

        res = mock_engine.simulate_ping("pc1", "10.2.2.2")
        # Specification: Ping must fail because link between frr1 and srl1 is down
        assert res.exit_code == 1
        assert "100% packet loss" in res.stdout

    def test_defect_5_multi_homed_source_node_blocked_on_unrelated_interface_down(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        """If frr1:eth2 is DOWN, pinging pc1 (10.1.1.2) over healthy eth1 should still work."""
        mock_engine.load_topology_package(full_multi_node_package)

        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.INTERFACE_DOWN,
                target_node="frr1",
                target_interface="eth2",
            )
        )

        res = mock_engine.simulate_ping("frr1", "10.1.1.2")
        # Specification: Ping from frr1 to pc1 via eth1 should succeed (eth1 is UP)
        assert res.exit_code == 0
        assert "0% packet loss" in res.stdout

    def test_defect_6_alpine_busybox_ping_rtt_not_parsed(self) -> None:
        """Alpine Linux BusyBox ping outputs round-trip min/avg/max = ... ms."""
        raw = """PING 10.2.2.2 (10.2.2.2): 56 data bytes
64 bytes from 10.2.2.2: seq=0 ttl=62 time=0.082 ms
64 bytes from 10.2.2.2: seq=1 ttl=62 time=0.075 ms

--- 10.2.2.2 ping statistics ---
2 packets transmitted, 2 packets received, 0% packet loss
round-trip min/avg/max = 0.075/0.078/0.082 ms
"""
        telemetry = PingProbe.parse_ping_output(raw_output=raw, src_node="pc1", dst_ip="10.2.2.2")
        # Specification: RTT avg should be parsed as 0.078 ms
        assert telemetry.rtt_avg_ms == 0.078

    def test_defect_7_srl_blackhole_routes_dropped(self) -> None:
        """SR Linux routes with next-hop 'blackhole' or 'discard' should be recorded in telemetry."""
        raw = """-------------------------------------------------------------------
Network-instance : default
-------------------------------------------------------------------
IPv4 Prefix          Type         Next-hop           Interface   
-------------------------------------------------------------------
10.5.5.0/24          static       blackhole          none        
-------------------------------------------------------------------
"""
        rt = RouteTableProbe.parse_srl_routes(node="srl1", raw_output=raw)
        # Specification: Route to 10.5.5.0/24 should be captured
        assert rt.has_route_to("10.5.5.0/24")
