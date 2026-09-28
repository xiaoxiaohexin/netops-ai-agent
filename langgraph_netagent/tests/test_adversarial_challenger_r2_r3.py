"""Empirical Adversarial Challenge Suite (R2 & R3) for NetOps AI Agent.

Authored by Challenger Agent (teamwork_preview_challenger).
Empirically stress-tests and challenges:
1. Malformed, corrupt, or truncated 'tc -s qdisc show' outputs (missing fields, unexpected units, 64-bit counters).
2. Ambiguous anomalies: simultaneous missing route AND buffer overlimits (priority and multi-anomaly handling).
3. 5-tuple extraction edge cases: IPv6 addresses, non-standard protocols, missing port numbers, multi-homed routers.
4. AAL injection stress: command chaining evasion payloads (; rm -rf /, && reboot, | sh) within remediation templates.
5. Shadow sandbox isolation: hermetic execution, zero state pollution of parent environment, guaranteed teardown.
"""

import copy
import ipaddress
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.remediation import RemediationPlan
from langgraph_netagent.models.telemetry import (
    InterfaceStatsTelemetry,
    InterfaceTelemetry,
    NetworkHealthReport,
    PingTelemetry,
    QdiscTelemetry,
    RouteTableTelemetry,
)
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, MockEngine, VirtualNode
from langgraph_netagent.tools.probes import QdiscProbe
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def deployed_mock_adapter():
    """Provides a MockContainerlabAdapter initialized with the netagent-lab topology."""
    adapter = MockContainerlabAdapter()
    for candidate in [
        Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
        Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
    ]:
        if candidate.exists():
            adapter.deploy(candidate)
            break
    return adapter


@pytest.fixture
def aal_instance(deployed_mock_adapter):
    return AgentAccessLayer(lab_adapter=deployed_mock_adapter)


# ==============================================================================
# 1. Malformed, Corrupt, or Truncated Qdisc Telemetry Parsing
# ==============================================================================

class TestMalformedQdiscTelemetry:
    """Stress-test QdiscProbe.parse_tc_output against hostile and corrupted outputs."""

    def test_empty_or_whitespace_tc_output(self):
        """Empty, whitespace-only, or comment-only outputs must return an empty list without raising."""
        assert QdiscProbe.parse_tc_output(node="gw1", raw_output="") == []
        assert QdiscProbe.parse_tc_output(node="gw1", raw_output="   \n\t  \n  ") == []
        assert QdiscProbe.parse_tc_output(node="gw1", raw_output="No qdisc configured on interface\n") == []

    def test_truncated_qdisc_headers(self):
        """Header with missing handle, missing dev, or truncated lines must not crash."""
        # Bare qdisc keyword
        assert QdiscProbe.parse_tc_output(node="gw1", raw_output="qdisc") == []

        # Qdisc type without handle
        assert QdiscProbe.parse_tc_output(node="gw1", raw_output="qdisc tbf") == []

        # Qdisc type and handle but missing dev - should use fallback_interface
        raw_no_dev = (
            "qdisc fq_codel 8001: root refcnt 2 limit 10240p flows 1024 quantum 1514\n"
            " Sent 1000 bytes 10 pkt (dropped 0, overlimits 0 requeues 0)\n"
            " backlog 0b 0p requeues 0"
        )
        res = QdiscProbe.parse_tc_output(node="gw1", raw_output=raw_no_dev, fallback_interface="eth-fallback")
        assert len(res) == 1
        assert res[0].interface == "eth-fallback"
        assert res[0].qdisc_type == "fq_codel"
        assert res[0].handle == "8001:"
        assert res[0].bytes_sent == 1000

    def test_missing_and_corrupted_counter_fields(self):
        """Garbage, non-numeric tokens, and partial counter lines must default cleanly to 0."""
        corrupt_raw = (
            "qdisc tbf 10: dev eth1 root rate 10Mbit burst 10Kb lat 50ms\n"
            " Sent NOTANUMBER bytes UNKNOWN pkt (dropped GARBAGE, overlimits NULL requeues NONE)\n"
            " backlog CORRUPT 10p"
        )
        res = QdiscProbe.parse_tc_output(node="gw1", raw_output=corrupt_raw)
        assert len(res) == 1
        q = res[0]
        assert q.bytes_sent == 0
        assert q.packets_sent == 0
        assert q.dropped == 0
        assert q.overlimits == 0
        assert q.requeues == 0
        assert q.backlog_bytes == 0

    def test_unexpected_units_and_casing_in_backlog(self):
        """Upper/lower case units and variations in backlog format should parse safely."""
        raw_upper = (
            "qdisc pfifo_fast 0: dev eth2 root refcnt 2 bands 3 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1\n"
            " Sent 52428800 bytes 45000 pkt (dropped 320, overlimits 150 requeues 5)\n"
            " backlog 65536B 50P requeues 5"
        )
        res = QdiscProbe.parse_tc_output(node="r1", raw_output=raw_upper)
        assert len(res) == 1
        q = res[0]
        assert q.dropped == 320
        assert q.overlimits == 150
        assert q.backlog_bytes == 65536
        assert q.backlog_packets == 50

    def test_huge_64bit_counter_values(self):
        """Ensure huge 64-bit integer values (e.g. 2^64-1, 2^63-1) parse and validate in QdiscTelemetry."""
        huge_bytes = 18446744073709551615
        huge_pkts = 9223372036854775807
        huge_dropped = 4294967295
        huge_overlimits = 10000000000

        raw_huge = (
            f"qdisc tbf 1: dev eth1 root\n"
            f" Sent {huge_bytes} bytes {huge_pkts} pkt (dropped {huge_dropped}, overlimits {huge_overlimits} requeues 0)\n"
            f" backlog {huge_bytes}b {huge_pkts}p requeues 0"
        )
        res = QdiscProbe.parse_tc_output(node="edge-gw", raw_output=raw_huge)
        assert len(res) == 1
        q = res[0]
        assert q.bytes_sent == huge_bytes
        assert q.packets_sent == huge_pkts
        assert q.dropped == huge_dropped
        assert q.overlimits == huge_overlimits
        assert q.backlog_bytes == huge_bytes
        assert q.backlog_packets == huge_pkts

        # Pydantic serialization round-trip verification
        dump = q.model_dump()
        restored = QdiscTelemetry.model_validate(dump)
        assert restored.bytes_sent == huge_bytes

    def test_mixed_corrupt_and_valid_qdiscs(self):
        """When multiple qdisc blocks are present with interspersed corrupt blocks, valid ones are preserved."""
        composite_raw = (
            "qdisc tbf 1: dev eth1 root\n"
            " Sent 100 bytes 1 pkt (dropped 0, overlimits 0 requeues 0)\n"
            " backlog 0b 0p\n"
            "qdisc corrupt_garbage_no_structure\n"
            "qdisc netem 2: dev eth2 root\n"
            " Sent 5000 bytes 50 pkt (dropped 12, overlimits 4 requeues 1)\n"
            " backlog 100b 2p\n"
        )
        res = QdiscProbe.parse_tc_output(node="gw1", raw_output=composite_raw)
        assert len(res) == 2
        assert res[0].interface == "eth1"
        assert res[0].dropped == 0
        assert res[1].interface == "eth2"
        assert res[1].dropped == 12
        assert res[1].overlimits == 4


# ==============================================================================
# 2. Ambiguous Anomalies: Simultaneous Missing Route AND Buffer Overlimits
# ==============================================================================

class TestAmbiguousAnomaliesAndPriority:
    """Challenge anomaly classification and diagnosis when multiple anomalies coexist."""

    def test_simultaneous_missing_route_and_overlimit_priority(self):
        """Buffer overlimit must take classification priority over missing route to protect gateway."""
        discrepancies = [
            NetworkDiscrepancy(
                node="frr1",
                discrepancy_type="missing_route",
                target_destination="10.2.2.0/24",
                description="Missing static route to 10.2.2.0/24",
                suspect_nodes=["frr1"],
            ),
            NetworkDiscrepancy(
                node="dc-egress",
                discrepancy_type="buffer_overlimit",
                affected_interface="eth2",
                description="Buffer overlimit on dc-egress:eth2: 850 dropped, 400 overlimits",
                suspect_nodes=["dc-egress"],
            ),
        ]
        ft_overload = FiveTuple.from_traffic_overload(
            src_ip="192.168.100.2",
            dst_ip="203.0.113.10",
            protocol="TCP",
            dst_port=80,
            overlimits=400,
            dropped=850,
        )

        classification = classify_anomaly(
            report=None,
            discrepancies=discrepancies,
            failure_5tuples=[ft_overload],
        )

        # Overload must take precedence because buffer drops disrupt active forwarding
        assert classification.category == "external_overload"
        assert classification.bottleneck_node == "dc-egress"
        assert classification.bottleneck_interface == "eth2"
        assert classification.offending_source_ip == "192.168.100.2"
        assert classification.confidence >= 0.90

    def test_dual_anomaly_context_retention_in_stage1(self, deployed_mock_adapter):
        """Stage 1 context enrichment must retain BOTH the overload and missing route discrepancies."""
        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=deployed_mock_adapter,
        )

        state = create_operational_initial_state()
        state["topology_path"] = ["pc1", "frr1", "dc-egress", "pc2"]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "dc-egress": "linux", "pc2": "linux"}
        state["suspect_devices"] = ["dc-egress", "frr1"]
        state["discrepancies"] = [
            {"node": "frr1", "discrepancy_type": "missing_route", "target_destination": "10.2.2.0/24"},
            {"node": "dc-egress", "discrepancy_type": "buffer_overlimit", "affected_interface": "eth2"},
        ]
        state["failure_5tuples"] = [
            FiveTuple.from_traffic_overload(
                src_ip="192.168.100.2",
                dst_ip="203.0.113.10",
                protocol="TCP",
                overlimits=500,
                dropped=1000,
            ).model_dump(),
            FiveTuple.from_ping_failure(src_ip="10.1.1.2", dst_ip="10.2.2.2").model_dump(),
        ]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "bottleneck_node": "dc-egress",
            "bottleneck_interface": "eth2",
            "offending_source_ip": "192.168.100.2",
            "victim_destination_ip": "203.0.113.10",
        }

        s1_out = nodes["diagnostic_stage1"](state)
        enriched = s1_out["enriched_context"]

        # Verify neither anomaly was dropped from enriched context
        assert len(enriched["discrepancies_summary"]) == 2
        assert len(enriched["failure_summary"]) == 2
        assert enriched["is_overload"] is True
        assert enriched["bottleneck_node"] == "dc-egress"

    def test_dual_anomaly_stage2_targeting_overload_first(self, deployed_mock_adapter):
        """Stage 2 must formulate iptables drop rule for overload without tripping circuit breaker."""
        mock_llm = MagicMock()
        mock_llm.generate_structured.return_value = None  # Force deterministic fallback

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=deployed_mock_adapter,
        )

        state = create_operational_initial_state()
        state["node_kinds"] = {"dc-egress": "linux", "frr1": "frr"}
        state["suspect_devices"] = ["dc-egress", "frr1"]
        state["discrepancies"] = [
            {"node": "frr1", "discrepancy_type": "missing_route", "target_destination": "10.2.2.0/24"},
            {"node": "dc-egress", "discrepancy_type": "buffer_overlimit", "affected_interface": "eth2"},
        ]
        state["failure_5tuples"] = [
            FiveTuple.from_traffic_overload(
                src_ip="192.168.100.2",
                dst_ip="203.0.113.10",
                protocol="TCP",
                dst_port=80,
                overlimits=500,
                dropped=1000,
            ).model_dump()
        ]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "bottleneck_node": "dc-egress",
            "bottleneck_interface": "eth2",
            "offending_source_ip": "192.168.100.2",
            "victim_destination_ip": "203.0.113.10",
        }
        state["rag_keywords"] = ["buffer", "overlimits", "iptables", "overload"]
        state["retry_count"] = 0
        state["max_retries"] = 3

        s2_out = nodes["diagnostic_stage2"](state)

        assert s2_out["circuit_breaker_tripped"] is False
        assert s2_out["status"] == "stage2_plan_generated"
        plan = s2_out["remediation_plan"]
        assert plan["target_entity"] == "dc-egress"
        assert any("iptables" in cmd and "192.168.100.2" in cmd for cmd in plan["exec_commands"])
        assert s2_out["current_step_tag"] == "diag_iter_1"


# ==============================================================================
# 3. 5-Tuple Extraction Edge Cases
# ==============================================================================

class TestFiveTupleExtractionEdgeCases:
    """Stress-test 5-tuple extraction on IPv6, non-standard protocols, missing ports, and multi-homing."""

    def test_ipv6_syslog_extraction(self):
        """Verify IPv6 addresses in netfilter, bracketed formats, and link-local logs."""
        # Standard iptables IPv6 log
        log_v6 = (
            "kernel: [1234.56] IN=eth1 OUT=eth2 "
            "SRC=2001:0db8:85a3:0000:0000:8a2e:0370:7334 DST=2001:0db8:85a3:0000:0000:8a2e:0370:7335 "
            "PROTO=TCP SPT=443 DPT=51234"
        )
        ft = FiveTuple.from_syslog(log_v6)
        assert ft is not None
        assert ft.source_ip == "2001:db8:85a3::8a2e:370:7334"
        assert ft.destination_ip == "2001:db8:85a3::8a2e:370:7335"
        assert ft.protocol == "TCP"
        assert ft.source_port == 443
        assert ft.destination_port == 51234

        # Bracketed IPv6 Juniper style
        log_bracketed = "PFE_FW_SYSLOG: [2001:db8::1]:8080 -> [2001:db8::2]:9090 proto=TCP"
        ft_br = FiveTuple.from_syslog(log_bracketed)
        assert ft_br is not None
        assert ft_br.source_ip == "2001:db8::1"
        assert ft_br.destination_ip == "2001:db8::2"
        assert ft_br.source_port == 8080
        assert ft_br.destination_port == 9090

    def test_non_standard_protocols_and_numbers(self):
        """Verify GRE, ESP, SCTP, and ICMP without ports parse safely."""
        # GRE Protocol
        log_gre = "netfilter: SRC=198.51.100.1 DST=203.0.113.1 PROTO=GRE"
        ft_gre = FiveTuple.from_syslog(log_gre)
        assert ft_gre is not None
        assert ft_gre.protocol == "GRE"
        assert ft_gre.source_port == 0
        assert ft_gre.destination_port == 0

        # ESP (IPsec)
        log_esp = "firewall: SRC=198.51.100.2 DST=203.0.113.2 PROTO=ESP"
        ft_esp = FiveTuple.from_syslog(log_esp)
        assert ft_esp is not None
        assert ft_esp.protocol == "ESP"

        # SCTP with ports
        log_sctp = "kernel: SRC=10.1.1.1 DST=10.2.2.2 PROTO=SCTP SPT=3868 DPT=3868"
        ft_sctp = FiveTuple.from_syslog(log_sctp)
        assert ft_sctp is not None
        assert ft_sctp.protocol == "SCTP"
        assert ft_sctp.destination_port == 3868

    def test_missing_ports_and_icmp_drop(self):
        """Ping failures and layer-3 only alerts must have ports default to 0 without error."""
        ft = FiveTuple.from_ping_failure(src_ip="10.1.1.10", dst_ip="10.2.2.20")
        assert ft.source_port == 0
        assert ft.destination_port == 0
        assert ft.protocol == "ICMP"
        assert ft.alert_type == "PACKET_DROP"

    def test_multihomed_router_inventory_mapping(self):
        """Routers with multiple interfaces and IPs must extract cleanly into InventoryPool."""
        ip_addr_raw = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 10.0.1.1/24 scope global eth1\n"
            "3: eth2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 10.0.2.1/24 scope global eth2\n"
            "4: eth3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 10.0.3.1/24 scope global eth3\n"
            "5: eth4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"
            "    inet 192.168.10.1/24 scope global eth4\n"
        )
        baseline = {
            "nodes": {
                "multihomed-r1": {
                    "kind": "linux",
                    "ip_addr": ip_addr_raw,
                }
            }
        }
        pool = InventoryPool.from_baseline(baseline)
        assert len(pool.subnets) == 4
        assert "10.0.1.0/24" in pool.subnets
        assert "10.0.2.0/24" in pool.subnets
        assert "10.0.3.0/24" in pool.subnets
        assert "192.168.10.0/24" in pool.subnets
        assert pool.ip_to_node.get("10.0.1.1") == "multihomed-r1"
        assert pool.ip_to_node.get("192.168.10.1") == "multihomed-r1"


# ==============================================================================
# 4. AAL Injection Stress & Command Chaining Evasion Resistance
# ==============================================================================

class TestAALInjectionEvasionStress:
    """Verify that command chaining and evasive payloads are strictly rejected by AAL."""

    EVASION_PAYLOADS = [
        # Semicolon chaining
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; rm -rf /",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; reboot",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; poweroff",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; shutdown -h now",
        # && Chaining
        "iptables -I FORWARD -s 192.168.100.2 -j DROP && rm -rf /etc",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP && reboot",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP && ip addr flush dev eth1",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP && ip link delete eth1",
        # Pipe to shell interpreters
        "iptables -I FORWARD -s 192.168.100.2 -j DROP | sh",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP | /bin/bash",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP | sudo sh",
        "echo rm -rf / | sh",
        # || Chaining
        "iptables -I FORWARD -s 192.168.100.2 -j DROP || reboot",
        # Newline injection
        "iptables -I FORWARD -s 192.168.100.2 -j DROP\nrm -rf /root",
        # Fork bomb
        "iptables -I FORWARD -j DROP && :(){ :|:& };:",
        # Disk formatting / dd overwrite
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; mkfs.ext4 /dev/sda1",
        "iptables -I FORWARD -s 192.168.100.2 -j DROP ; dd if=/dev/zero of=/dev/sda",
    ]

    @pytest.mark.parametrize("payload", EVASION_PAYLOADS)
    def test_evasion_payloads_blocked_in_validate_command_safety(self, aal_instance, payload):
        """Every evasion payload must be recognized as unsafe by validate_command_safety."""
        is_safe, error_reason = aal_instance.validate_command_safety(payload, read_only=False)
        assert is_safe is False, f"Payload bypassed safety validation: '{payload}'"
        assert "SECURITY POLICY VIOLATION" in (error_reason or "")

    @pytest.mark.parametrize("payload", EVASION_PAYLOADS)
    def test_evasion_payloads_blocked_in_aal_execute(self, aal_instance, payload):
        """AAL.execute must return is_blocked=True with exit_code=126 without running adapter."""
        tool_call = AALToolCall(
            tool_name="remediation_exec",
            node_name="dc-egress",
            command=payload,
            read_only=False,
            step_tag="adversarial_test",
        )
        resp = aal_instance.execute(tool_call)
        assert resp.is_blocked is True
        assert resp.exit_code == 126
        assert resp.success is False
        assert "SECURITY POLICY VIOLATION" in (resp.error_message or "")

    def test_read_only_mode_blocks_mutating_command_chains(self, aal_instance):
        """Chained read-only commands that attempt mutation via && or ; must be blocked."""
        mutating_chains = [
            "ip route show ; ip route add 10.99.0.0/24 via 10.1.1.1",
            "ip addr show && iptables -I FORWARD -j DROP",
            "cat /etc/frr/frr.conf ; sed -i 's/foo/bar/' /etc/frr/frr.conf",
            "vtysh -c 'show ip route' ; touch /tmp/pwned",
        ]
        for cmd in mutating_chains:
            is_safe, error_reason = aal_instance.validate_command_safety(cmd, read_only=True)
            assert is_safe is False, f"Mutating chain allowed in read-only mode: '{cmd}'"
            assert "READ-ONLY CONSTRAINT VIOLATION" in (error_reason or "")


# ==============================================================================
# 5. Shadow Sandbox Isolation & Hermetic State Verification
# ==============================================================================

class TestShadowSandboxIsolation:
    """Empirically prove shadow sandbox leaves parent state 100% unpolluted."""

    def test_sandbox_mutations_do_not_leak_to_original_node(self, deployed_mock_adapter, aal_instance):
        """Mutations inside shadow sandbox must NOT modify the live node in VirtualNetworkGraph."""
        target = "frr1"
        v_graph = deployed_mock_adapter.mock_engine.graph
        orig_node = v_graph.nodes[target]

        initial_routes_count = len(orig_node.routes)
        initial_interfaces_count = len(orig_node.interfaces)
        initial_node_keys = set(v_graph.nodes.keys())

        # Test patch command inside sandbox: adds a new route
        patch_cmd = "vtysh -c 'configure terminal' -c 'ip route 172.30.0.0/24 10.1.12.2'"
        result: ShadowSandboxResult = ShadowSandboxManager.run_sandbox_validation(
            target_node=target,
            patch_commands=[patch_cmd],
            adapter=deployed_mock_adapter,
            aal=aal_instance,
            step_tag="sandbox_isolation_test",
        )

        assert result.all_passed is True

        # Verify parent/original node was NOT mutated
        current_orig_node = v_graph.nodes[target]
        assert len(current_orig_node.routes) == initial_routes_count, "Original node routes were mutated by sandbox!"
        assert len(current_orig_node.interfaces) == initial_interfaces_count

        # Verify sandbox replica was completely torn down
        final_node_keys = set(v_graph.nodes.keys())
        assert initial_node_keys == final_node_keys
        assert not any(k.startswith("sandbox_") for k in final_node_keys)

    def test_sandbox_teardown_on_failing_patch(self, deployed_mock_adapter, aal_instance):
        """Even when a command fails or violates policy, teardown must clean up the replica."""
        v_graph = deployed_mock_adapter.mock_engine.graph
        initial_node_keys = set(v_graph.nodes.keys())

        # Use a command that violates AAL security policy to guarantee failure
        failing_patch = ["iptables -I FORWARD -s 192.168.100.2 -j DROP ; rm -rf /"]
        result = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=failing_patch,
            adapter=deployed_mock_adapter,
            aal=aal_instance,
        )

        assert result.all_passed is False
        assert "SECURITY POLICY VIOLATION" in (result.error_message or "")
        final_node_keys = set(v_graph.nodes.keys())
        assert initial_node_keys == final_node_keys, "Replica node leaked after failing sandbox command!"

    def test_consecutive_sandbox_runs_are_independent(self, deployed_mock_adapter, aal_instance):
        """Multiple consecutive sandbox runs must each have unique IDs and zero crosstalk."""
        v_graph = deployed_mock_adapter.mock_engine.graph
        initial_keys = set(v_graph.nodes.keys())

        seen_sandbox_ids = set()
        for i in range(5):
            res = ShadowSandboxManager.run_sandbox_validation(
                target_node="frr1",
                patch_commands=["vtysh -c 'show ip route'"],
                adapter=deployed_mock_adapter,
                aal=aal_instance,
                step_tag=f"run_{i}",
            )
            assert res.all_passed is True
            assert res.sandbox_id not in seen_sandbox_ids
            seen_sandbox_ids.add(res.sandbox_id)

        assert set(v_graph.nodes.keys()) == initial_keys
