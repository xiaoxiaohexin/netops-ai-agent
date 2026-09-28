"""Unit tests for FaultInjector and state-aware self-healing triggers."""

from pathlib import Path
import pytest

from langgraph_netagent.models.topology import DeviceConfigFile, FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine


class TestFaultInjector:
    """Test suite for fault injection rules and lifecycle management."""

    def test_rule_registration_and_removal(self) -> None:
        injector = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.PING_DROP,
            target_node="pc1",
            target_ip_or_prefix="10.2.2.2",
        )
        rule_id = injector.add_rule(rule)
        assert rule_id == rule.rule_id
        assert len(injector.get_active_rules()) == 1

        removed = injector.remove_rule(rule_id)
        assert removed is True
        assert len(injector.get_active_rules()) == 0

        # Remove non-existent returns False
        assert injector.remove_rule("non-existent-id") is False

    def test_deploy_failure_injection(
        self,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        from langgraph_netagent.tools.exporter import TopologyExporter

        exporter = TopologyExporter()
        exporter.export(package=full_multi_node_package, export_dir=tmp_path)
        topo_file = tmp_path / "multi-vendor-lab.clab.yml"

        injector = FaultInjector()
        injector.add_rule(
            FaultRule(
                fault_type=FaultType.DEPLOY_FAILURE,
                error_message="Simulated Docker daemon failure during container instantiation",
            )
        )
        adapter = MockContainerlabAdapter(fault_injector=injector)

        # Deploy should fail
        res = adapter.deploy(topo_file=topo_file)
        assert not res.success
        assert "Simulated Docker daemon failure" in res.error_message

        # Clear fault and deploy again -> should succeed
        injector.clear_all()
        res_retry = adapter.deploy(topo_file=topo_file)
        assert res_retry.success

    def test_ping_drop_targeting_specific_node_and_destination(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Baseline: pc1 -> pc2 is healthy
        res_before = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert res_before.success

        # Inject PING_DROP from pc1 to 10.2.2.2
        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.PING_DROP,
                target_node="pc1",
                target_ip_or_prefix="10.2.2.2",
            )
        )

        # pc1 -> 10.2.2.2 must fail
        res_dropped = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2")
        assert not res_dropped.success
        assert "100% packet loss" in res_dropped.stdout

        # pc1 -> 10.1.1.1 (gateway) must still pass!
        res_gateway = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.1.1.1")
        assert res_gateway.success

    def test_intermittent_loss_injection(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.INTERMITTENT_LOSS,
                target_node="pc1",
                target_ip_or_prefix="10.2.2.2",
                loss_pct=33.3,
            )
        )

        res = mock_engine.simulate_ping(src_node="pc1", dst_ip="10.2.2.2", count=3)
        assert "33.3% packet loss" in res.stdout
        assert "2 received" in res.stdout

    def test_missing_route_suppression_and_ping_impact(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Inject missing route on frr1 for 10.2.2.0/24
        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.MISSING_ROUTE,
                target_node="frr1",
                target_ip_or_prefix="10.2.2.0/24",
            )
        )

        # Route table on frr1 must NOT display 10.2.2.0/24
        rt_res = mock_engine.simulate_ip_route("frr1", "ip route show")
        assert "10.2.2.0/24" not in rt_res.stdout

        # Ping across frr1 to pc2 must fail
        ping_res = mock_engine.simulate_ping("pc1", "10.2.2.2")
        assert not ping_res.success
        assert "Destination Net Unreachable" in ping_res.stdout

    def test_interface_down_injection(
        self,
        mock_engine: MockEngine,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        mock_engine.load_topology_package(full_multi_node_package)

        # Inject eth1 DOWN on pc1
        mock_engine.fault_injector.add_rule(
            FaultRule(
                fault_type=FaultType.INTERFACE_DOWN,
                target_node="pc1",
                target_interface="eth1",
            )
        )

        # Interface status shows DOWN
        iface_res = mock_engine.simulate_ip_addr("pc1", "ip addr show")
        assert "eth1:" in iface_res.stdout
        assert "state DOWN" in iface_res.stdout

        # Outbound ping fails
        ping_res = mock_engine.simulate_ping("pc1", "10.2.2.2")
        assert not ping_res.success
        assert "Network is unreachable" in ping_res.stdout

    def test_active_until_retry_auto_clearing(self) -> None:
        injector = FaultInjector()
        rule = FaultRule(
            fault_type=FaultType.PING_DROP,
            target_node="pc1",
            active_until_retry=2,
        )
        injector.add_rule(rule)

        # Retry 1: still active
        expired_1 = injector.on_retry(1)
        assert len(expired_1) == 0
        assert len(injector.get_active_rules()) == 1

        # Retry 2: reaches threshold -> auto-cleared
        expired_2 = injector.on_retry(2)
        assert len(expired_2) == 1
        assert len(injector.get_active_rules()) == 0

    def test_state_aware_remediation_auto_clears_on_redeploy(
        self,
        tmp_path: Path,
        full_multi_node_package: FullTopologyPackage,
    ) -> None:
        """Verify that repairing the configuration file and calling deploy() auto-clears faults."""
        from langgraph_netagent.tools.exporter import TopologyExporter

        # Ensure initial frr.conf lacks the route to 10.2.2.0/24
        for cfg in full_multi_node_package.configs:
            if cfg.node_name == "frr1":
                cfg.content = cfg.content.replace("ip route 10.2.2.0/24 10.1.12.2", "! no route initially")

        exporter = TopologyExporter()
        exporter.export(package=full_multi_node_package, export_dir=tmp_path)
        topo_file = tmp_path / "multi-vendor-lab.clab.yml"

        fault_injector = FaultInjector()
        # Inject missing route fault on frr1
        rule = FaultRule(
            fault_type=FaultType.MISSING_ROUTE,
            target_node="frr1",
            target_ip_or_prefix="10.2.2.0/24",
            cleared_on_remediation=True,
        )
        fault_injector.add_rule(rule)

        adapter = MockContainerlabAdapter(fault_injector=fault_injector)
        adapter.deploy(topo_file=topo_file)

        # Route is currently suppressed
        assert len(fault_injector.get_active_rules()) == 1
        ping_before = adapter.exec_command("pc1", "ping -c 2 10.2.2.2")
        assert not ping_before.success

        # Now simulate remediation: patch frr.conf on disk
        frr_conf_path = tmp_path / "config" / "frr" / "frr.conf"
        patched_content = frr_conf_path.read_text(encoding="utf-8") + "\nip route 10.2.2.0/24 10.1.12.2\n"
        frr_conf_path.write_text(patched_content, encoding="utf-8")

        # Redeploy topology
        redeploy_res = adapter.deploy(topo_file=topo_file)
        assert redeploy_res.success

        # FaultRule should have been automatically cleared!
        assert len(fault_injector.get_active_rules()) == 0

        # Verification ping should now pass!
        ping_after = adapter.exec_command("pc1", "ping -c 2 10.2.2.2")
        assert ping_after.success
        assert "0% packet loss" in ping_after.stdout
