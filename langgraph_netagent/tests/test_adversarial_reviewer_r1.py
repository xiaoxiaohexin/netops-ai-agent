"""Adversarial Reviewer Round 1 Test Suite for NetOps Agent.

Probes and verifies:
1. Module-level `ipaddress` usage in `telemetry_extraction_node` for missing-route isolation.
2. Ingestion and parsing of `initial_alerts` into 5-tuple attributes in `telemetry_extraction_node`.
3. AAL command evasion prevention (ordering of flags, short aliases, shutdown variants, swapped dd args, fork bombs, and chained commands).
4. AAL read-only mode enforcement against shorthand iproute2 and file modification tools.
5. CLI output parser robustness (veth @if suffixes, VLAN dot interfaces, BGP/OSPF/Kernel protocol mapping).
6. InventoryPool extraction resilience with unnumbered/link-only interfaces.
7. Multi-vendor syslog parsing (IPTables, Cisco IOS ACL, Juniper Junos, BGP) and IP validation.
8. Shadow sandbox error boundaries (non-existent nodes and live Docker container clone handling).
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter, CommandResult
from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.workflow.operational_edges import route_after_telemetry
from langgraph_netagent.workflow.operational_graph import (
    build_operational_graph,
    run_operational_workflow,
)
from langgraph_netagent.workflow.operational_nodes import create_operational_nodes
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


# ===========================================================================
# 1. AAL Security & Evasion Resistance Tests
# ===========================================================================

class TestAALAdversarialEvasion:
    """Probe AAL against evasion attacks, flag variations, and chained commands."""

    @pytest.fixture
    def aal(self):
        return AgentAccessLayer(MockContainerlabAdapter(), raise_on_security_violation=False)

    @pytest.fixture
    def strict_aal(self):
        return AgentAccessLayer(MockContainerlabAdapter(), raise_on_security_violation=True)

    @pytest.mark.parametrize(
        "evasive_cmd",
        [
            "rm -fr /",
            "rm -r -f /",
            "rm -f -r /",
            "rm --recursive --force /",
            "rm -rf/etc/frr",
            "rm -r /etc/frr",
            "ip link del dev eth1",
            "ip l del eth1",
            "ip link delete dev eth1",
            "ip a flush dev eth1",
            "ip addr flush dev eth1",
            "shutdown",
            "shutdown now",
            "telinit 0",
            "telinit 6",
            "systemctl isolate poweroff.target",
            "dd of=/dev/sda if=/dev/zero",
            "bomb() { bomb | bomb & }; bomb",
            ":(){ :|:& };:",
        ],
    )
    def test_evasive_destructive_commands_blocked(self, aal: AgentAccessLayer, evasive_cmd: str):
        tool_call = AALToolCall(tool_name="cli_exec", node_name="frr1", command=evasive_cmd)
        resp = aal.execute(tool_call)
        assert resp.is_blocked is True
        assert resp.success is False
        assert "SECURITY POLICY VIOLATION" in (resp.error_message or "")

    @pytest.mark.parametrize(
        "chained_cmd",
        [
            "vtysh -c 'show running-config' ; rm -fr /",
            "vtysh -c 'show ip route' && reboot",
            "ip addr show || shutdown",
            "echo 1\nrm -rf /",
            "cat /etc/frr/frr.conf | rm -r -f /etc",
        ],
    )
    def test_chained_payload_injection_blocked(self, aal: AgentAccessLayer, chained_cmd: str):
        tool_call = AALToolCall(tool_name="cli_exec", node_name="frr1", command=chained_cmd)
        resp = aal.execute(tool_call)
        assert resp.is_blocked is True
        assert resp.success is False

    @pytest.mark.parametrize(
        "mutating_evasion_cmd",
        [
            "ip r add 10.2.2.0/24 via 10.1.12.2",
            "ip r del 10.2.2.0/24 via 10.1.12.2",
            "ip a add 10.1.1.5/24 dev eth1",
            "ip a del 10.1.1.5/24 dev eth1",
            "ip l set dev eth1 down",
            "echo 'hostname r1' >> /etc/frr/frr.conf",
            "mv /tmp/x /etc/frr/frr.conf",
            "rm /etc/frr/frr.conf",
            "touch /etc/frr/frr.conf",
            "tee /etc/frr/frr.conf",
        ],
    )
    def test_mutating_evasion_blocked_in_read_only(self, aal: AgentAccessLayer, mutating_evasion_cmd: str):
        tool_call = AALToolCall(
            tool_name="read_config",
            node_name="frr1",
            command=mutating_evasion_cmd,
            read_only=True,
        )
        resp = aal.execute(tool_call)
        assert resp.is_blocked is True
        assert "READ-ONLY CONSTRAINT VIOLATION" in (resp.error_message or "")

    def test_chained_command_in_read_only(self, aal: AgentAccessLayer):
        tool_call = AALToolCall(
            tool_name="read_config",
            node_name="frr1",
            command="ip route show ; ip r add 10.2.2.0/24 via 10.1.12.2",
            read_only=True,
        )
        resp = aal.execute(tool_call)
        assert resp.is_blocked is True
        assert "READ-ONLY CONSTRAINT VIOLATION" in (resp.error_message or "")


# ===========================================================================
# 2. CLI Output Parsing Robustness Tests
# ===========================================================================

class TestAALParserRobustness:
    """Verify CLI parser handles veth interfaces, VLAN dot notation, and multi-protocol routing."""

    def test_parse_veth_and_vlan_interfaces(self):
        raw = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "42: eth1@if41: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state up\n"
            "    link/ether 00:16:3e:aa:bb:cc\n"
            "    inet 10.1.1.2/24 scope global eth1\n"
            "43: eth1.100@eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    link/ether 00:16:3e:aa:bb:cd\n"
            "    inet 10.1.100.1/24 scope global eth1.100\n"
        )
        parsed = AgentAccessLayer.normalize_cli_output("ip addr show", raw)
        assert parsed["type"] == "interface_inventory"
        assert parsed["count"] == 3
        iface_names = [i["name"] for i in parsed["interfaces"]]
        assert "eth1" in iface_names
        assert "eth1.100" in iface_names

        eth1 = [i for i in parsed["interfaces"] if i["name"] == "eth1"][0]
        assert eth1["state"] == "UP"
        assert "10.1.1.2/24" in eth1["ips"]

    def test_parse_multi_protocol_and_vlan_routes(self):
        raw = (
            "Codes: K - kernel, C - connected, S - static, B - BGP, O - OSPF\n"
            "K>* 0.0.0.0/0 [0/0] via 172.20.20.1, eth0, src 172.20.20.3\n"
            "C>* 10.1.1.0/24 is directly connected, eth1\n"
            "S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2\n"
            "B>* 192.168.1.0/24 [20/0] via 10.1.12.2, eth2.100, weight 1\n"
            "O>* 10.3.3.0/24 [110/20] via 10.1.12.2, eth2\n"
            "10.4.0.0/16 via 10.1.12.2 dev eth2.200\n"
        )
        parsed = AgentAccessLayer.normalize_cli_output("vtysh -c 'show ip route'", raw)
        assert parsed["type"] == "route_inventory"
        assert parsed["count"] == 6

        # Protocol mapping
        proto_by_dest = {r["destination"]: r["protocol"] for r in parsed["routes"]}
        assert proto_by_dest["0.0.0.0/0"] == "kernel"
        assert proto_by_dest["10.1.1.0/24"] == "connected"
        assert proto_by_dest["10.2.2.0/24"] == "static"
        assert proto_by_dest["192.168.1.0/24"] == "bgp"
        assert proto_by_dest["10.3.3.0/24"] == "ospf"
        assert proto_by_dest["10.4.0.0/16"] == "static"

        # VLAN interface preservation without truncation
        bgp_r = [r for r in parsed["routes"] if r["destination"] == "192.168.1.0/24"][0]
        assert bgp_r["interface"] == "eth2.100"

        vlan_static = [r for r in parsed["routes"] if r["destination"] == "10.4.0.0/16"][0]
        assert vlan_static["interface"] == "eth2.200"


# ===========================================================================
# 3. Multi-Vendor Syslog & Inventory Pool Extraction Tests
# ===========================================================================

class TestSyslogAndInventoryRobustness:
    """Verify syslog parser across vendor formats and clean inventory pool extraction."""

    def test_iptables_syslog_parsing(self):
        line = "IPTables-Dropped: IN=eth1 OUT=eth2 SRC=10.1.1.2 DST=10.2.2.2 PROTO=TCP SPT=45678 DPT=80"
        ft = FiveTuple.from_syslog(line)
        assert ft is not None
        assert ft.source_ip == "10.1.1.2"
        assert ft.destination_ip == "10.2.2.2"
        assert ft.protocol == "TCP"
        assert ft.source_port == 45678
        assert ft.destination_port == 80
        assert ft.alert_type == "PACKET_DROP"

    def test_cisco_acl_syslog_parsing(self):
        line = "%SEC-6-IPACCESSLOGP: list 101 denied tcp 10.1.1.2(12345) -> 10.2.2.2(80), 1 packet"
        ft = FiveTuple.from_syslog(line)
        assert ft is not None
        assert ft.source_ip == "10.1.1.2"
        assert ft.destination_ip == "10.2.2.2"
        assert ft.protocol == "TCP"
        assert ft.source_port == 12345
        assert ft.destination_port == 80
        assert ft.alert_type == "ACL_DENIED"

    def test_juniper_junos_syslog_parsing(self):
        line = "RT_FLOW: session created 10.1.1.2/12345->10.2.2.2/80 proto=TCP"
        ft = FiveTuple.from_syslog(line)
        assert ft is not None
        assert ft.source_ip == "10.1.1.2"
        assert ft.destination_ip == "10.2.2.2"
        assert ft.source_port == 12345
        assert ft.destination_port == 80

    def test_invalid_ip_rejected(self):
        line = "DROP 999.999.999.999:1234 -> 10.2.2.2:80"
        ft = FiveTuple.from_syslog(line)
        assert ft is None

    def test_inventory_extraction_with_unnumbered_interface(self):
        """Unnumbered/link-only interface must not bleed IP addresses into wrong interfaces."""
        baseline = {
            "nodes": {
                "frr1": {
                    "ip_addr": (
                        "1: lo: <LOOPBACK> mtu 65536\n"
                        "    inet 127.0.0.1/8 scope host lo\n"
                        "2: eth0: <BROADCAST> mtu 1500\n"
                        "    link/ether 00:16:3e:00:00:01\n"
                        "3: eth1: <BROADCAST> mtu 1500\n"
                        "    link/ether 00:16:3e:00:00:02\n"
                        "    inet 10.1.1.1/24 scope global eth1\n"
                    ),
                    "route_table": "C>* 10.1.1.0/24 is directly connected, eth1",
                }
            }
        }
        pool = InventoryPool.from_baseline(baseline)
        assert "eth0" in pool.interfaces["frr1"]
        assert "eth1" in pool.interfaces["frr1"]
        # 10.1.1.1 must belong to frr1 and be mapped cleanly
        assert pool.ip_to_node.get("10.1.1.1") == "frr1"
        assert "10.1.1.0/24" in pool.subnets


# ===========================================================================
# 4. State Machine Discrepancy & Initial Alert Integration Tests
# ===========================================================================

class TestDiscrepancyAndInitialAlertsIntegration:
    """Verify telemetry_extraction properly isolates single-exit discrepancies with ipaddress and parses initial_alerts."""

    def test_initial_alerts_parsed_in_telemetry_node(self):
        """Initial alerts passed to the state are extracted into failure_5tuples."""
        adapter = MockContainerlabAdapter()
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
        )

        state = create_operational_initial_state(
            initial_alerts=[
                "DROP 10.1.1.2:54321 -> 10.2.2.2:80 proto=TCP",
                "%SEC-6-IPACCESSLOGP: list 101 denied tcp 10.1.1.2(12345) -> 10.2.2.2(80)",
            ]
        )
        state["topology_path"] = ["pc1", "frr1", "pc2"]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "pc2": "linux"}
        state["baseline"] = {
            "nodes": {
                "pc1": {"ip_addr": "2: eth1: inet 10.1.1.2/24"},
                "pc2": {"ip_addr": "2: eth1: inet 10.2.2.2/24"},
                "frr1": {"ip_addr": "2: eth1: inet 10.1.1.1/24"},
            }
        }
        state["inventory_pool"] = {
            "subnets": ["10.1.1.0/24", "10.2.2.0/24"],
            "ip_to_node": {"10.1.1.2": "pc1", "10.2.2.2": "pc2"},
        }

        result = nodes["telemetry_extraction"](state)
        # failure_5tuples must contain the parsed initial alerts
        assert len(result["failure_5tuples"]) >= 2
        protos = [ft["protocol"] for ft in result["failure_5tuples"]]
        assert "TCP" in protos

        # Edge routing must not route to end_healthy when alerts are present
        updated_state = dict(state)
        updated_state.update(result)
        decision = route_after_telemetry(updated_state)
        assert decision == "diagnostic_stage1"

    def test_single_exit_discrepancy_with_ipaddress(self):
        """Verify router missing-route discrepancy is accurately identified with ipaddress logic."""
        adapter = MockContainerlabAdapter()
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
        )

        state = create_operational_initial_state()
        state["topology_path"] = ["pc1", "frr1", "pc2"]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "pc2": "linux"}
        state["baseline"] = {
            "nodes": {
                "pc1": {"ip_addr": "2: eth1: inet 10.1.1.2/24"},
                "pc2": {"ip_addr": "2: eth1: inet 10.2.2.2/24"},
                "frr1": {"ip_addr": "2: eth1: inet 10.1.1.1/24"},
            }
        }
        state["inventory_pool"] = {
            "subnets": ["10.1.1.0/24", "10.2.2.0/24"],
            "ip_to_node": {"10.1.1.2": "pc1", "10.2.2.2": "pc2"},
        }

        # Mock adapter returning route table missing 10.2.2.0/24
        def mock_exec(node_name, command, timeout=15):
            if "route" in command:
                return CommandResult(
                    command=command,
                    exit_code=0,
                    stdout="C>* 10.1.1.0/24 is directly connected, eth1",
                    node=node_name,
                )
            if "ping" in command:
                return CommandResult(command=command, exit_code=1, stdout="100% packet loss", node=node_name)
            return CommandResult(command=command, exit_code=0, stdout="", node=node_name)

        adapter.exec_command = mock_exec

        result = nodes["telemetry_extraction"](state)
        discrepancies = result.get("discrepancies", [])
        assert len(discrepancies) >= 1
        missing_route_disc = [d for d in discrepancies if d["discrepancy_type"] == "missing_route"]
        assert len(missing_route_disc) >= 1
        assert missing_route_disc[0]["node"] == "frr1"
        assert missing_route_disc[0]["target_destination"] == "10.2.2.0/24"


# ===========================================================================
# 5. Shadow Sandbox Error Boundary Tests
# ===========================================================================

class TestShadowSandboxBoundaries:
    """Verify error handling in shadow sandbox when target node or live environment is missing."""

    def test_nonexistent_target_node_returns_clean_error(self):
        adapter = MockContainerlabAdapter()
        aal = AgentAccessLayer(adapter)
        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="nonexistent_router",
            patch_commands=["vtysh -c 'conf t'"],
            adapter=adapter,
            aal=aal,
        )
        assert res.all_passed is False
        assert "not found in virtual network topology" in (res.error_message or "")

    def test_live_clab_adapter_error_boundary(self):
        """When Docker daemon is unavailable, LiveContainerlabAdapter cloning catches error cleanly."""
        adapter = LiveContainerlabAdapter()
        aal = AgentAccessLayer(adapter)

        # Mock runner failing on docker commit
        adapter.runner.run = MagicMock(return_value=CommandResult(
            command="docker commit",
            exit_code=1,
            stderr="Cannot connect to the Docker daemon",
        ))

        res = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=["vtysh -c 'conf t'"],
            adapter=adapter,
            aal=aal,
        )
        assert res.all_passed is False
        assert "Live sandbox container cloning failed" in (res.error_message or "")
