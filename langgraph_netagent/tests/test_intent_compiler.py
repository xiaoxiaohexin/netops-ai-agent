"""Comprehensive Unit and Integration Tests for Canonical Intent Compiler (Day-3).

Tests:
1. Canonical Intent models, enums, aliases, and Pydantic validation.
2. Bidirectional compilation (forward and exact inverse rollback) across:
   - Linux netfilter / iptables
   - Cisco IOS / IOS-XE extended ACLs & QoS
   - Huawei VRP (5-tier ACL/Classifier/Behavior/Policy hierarchy)
   - Linux FRRouting (vtysh)
3. Reverse topological ordering of rollback steps (e.g. unbinding interfaces before ACL deletion).
4. Composite remediation plan compilation and global reverse rollback sequencing.
5. AAL security policy gating against destructive commands (reboots, table flushes, rm -rf).
"""

import pytest
from pydantic import ValidationError

from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CanonicalRemediationIntent,
    CompilationResult,
    CompiledRemediationResult,
    IntentAction,
    IntentActionType,
    PlatformType,
    RollbackStep,
    TargetPlatform,
)
from langgraph_netagent.tools.aal import AALSecurityError
from langgraph_netagent.tools.intent_compiler import (
    CanonicalIntentCompiler,
    compile_canonical_intent,
    compile_remediation_plan,
)


# =============================================================================
# 1. Canonical Intent Data Model & Enum Tests
# =============================================================================

class TestCanonicalIntentModels:
    """Validate CanonicalIntent data contracts, enums, and aliases."""

    def test_canonical_intent_creation_valid(self):
        intent = CanonicalIntent(
            intent_id="intent-001",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="192.168.100.5",
            destination_ip="10.0.0.1",
            protocol="tcp",
            source_port=54321,
            destination_port=80,
            interface="eth1",
        )
        assert intent.intent_id == "intent-001"
        assert intent.action == IntentAction.DROP_TRAFFIC
        assert intent.target_platform == TargetPlatform.LINUX_IPTABLES
        assert intent.source_port == 54321
        assert intent.destination_port == 80
        assert intent.interface == "eth1"

    def test_canonical_intent_aliases(self):
        # target_interface alias, prefix alias, rate_mbps alias
        intent = CanonicalIntent(
            action="drop_traffic",
            target_node="r1",
            target_platform="cisco",
            target_interface="GigabitEthernet0/1",
            prefix="10.1.0.0/16",
            rate_mbps=50.0,
        )
        assert intent.action == IntentAction.DROP_TRAFFIC
        assert intent.target_platform == TargetPlatform.CISCO_ACL
        assert intent.interface == "GigabitEthernet0/1"
        assert intent.network_prefix == "10.1.0.0/16"
        assert intent.rate_limit_kbps == 50000

    def test_intent_action_enums_and_normalization(self):
        assert IntentAction("DROP_TRAFFIC") == IntentAction.DROP_TRAFFIC
        assert IntentAction("drop-traffic") == IntentAction.DROP_TRAFFIC
        assert IntentAction("rate_limit") == IntentAction.RATE_LIMIT
        assert IntentAction("restore-route") == IntentAction.RESTORE_ROUTE
        assert IntentActionType == IntentAction

    def test_target_platform_enums_and_normalization(self):
        assert TargetPlatform("linux_iptables") == TargetPlatform.LINUX_IPTABLES
        assert TargetPlatform("cisco_acl") == TargetPlatform.CISCO_ACL
        assert TargetPlatform("cisco") == TargetPlatform.CISCO_ACL
        assert TargetPlatform("cisco_ios") == TargetPlatform.CISCO_ACL
        assert TargetPlatform("huawei") == TargetPlatform.HUAWEI_VRP
        assert TargetPlatform("frr") == TargetPlatform.LINUX_FRR
        assert PlatformType == TargetPlatform

    def test_rollback_step_legacy_compatibility(self):
        # Primary M2 constructor
        step1 = RollbackStep(
            step_number=1,
            command="iptables -D FORWARD -j DROP",
            description="Delete drop rule",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            timeout_sec=15.0,
        )
        assert step1.step_number == 1
        assert step1.step_order == 1
        assert step1.command == "iptables -D FORWARD -j DROP"
        assert step1.payload == "iptables -D FORWARD -j DROP"

        # Legacy remediation constructor
        step2 = RollbackStep(
            step_order=2,
            action="EXEC_COMMAND",
            target_node="dc-egress",
            payload="ip link set dev eth1 up",
        )
        assert step2.step_number == 2
        assert step2.step_order == 2
        assert step2.command == "ip link set dev eth1 up"
        assert step2.payload == "ip link set dev eth1 up"

    def test_compilation_result_to_remediation_plan(self):
        res = CompilationResult(
            intent_id="int-123",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            forward_commands=["iptables -I FORWARD -j DROP"],
            rollback_commands=["iptables -D FORWARD -j DROP"],
            rollback_steps=[RollbackStep(step_number=1, command="iptables -D FORWARD -j DROP")],
            target_node="node-1",
        )
        plan = res.to_remediation_plan()
        assert plan.plan_id == "plan-int-123"
        assert plan.target_entity == "node-1"
        assert plan.exec_commands == ["iptables -I FORWARD -j DROP"]
        assert len(plan.rollback_steps) == 1


# =============================================================================
# 2. Linux Netfilter / iptables Compilation Tests
# =============================================================================

class TestLinuxIptablesCompilation:
    """Test suite for Linux iptables intent compilation and exact rollback."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler()

    def test_drop_traffic_full_5tuple_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            protocol="tcp",
            source_port=12345,
            destination_port=80,
            interface="eth1",
        )
        res = compiler.compile(intent)
        assert res.is_safe is True
        assert len(res.forward_commands) == 1
        assert len(res.rollback_commands) == 1

        fwd = res.forward_commands[0]
        rb = res.rollback_commands[0]

        assert fwd == "iptables -I FORWARD -s 192.168.1.100 -d 10.0.0.1 -p tcp --sport 12345 --dport 80 -i eth1 -j DROP"
        assert rb == "iptables -D FORWARD -s 192.168.1.100 -d 10.0.0.1 -p tcp --sport 12345 --dport 80 -i eth1 -j DROP"

        # Verify rollback step model
        assert len(res.rollback_steps) == 1
        assert res.rollback_steps[0].command == rb
        assert res.rollback_steps[0].step_number == 1

    def test_drop_traffic_wildcard_no_sport(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-drop-2",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="192.168.100.2",
            destination_ip="10.0.0.5",
            protocol="udp",
            destination_port=53,
        )
        res = compiler.compile(intent)
        fwd = res.forward_commands[0]
        rb = res.rollback_commands[0]

        # No --sport flag generated when source_port is None / 0
        assert "--sport" not in fwd
        assert "--dport 53" in fwd
        assert fwd == "iptables -I FORWARD -s 192.168.100.2 -d 10.0.0.5 -p udp --dport 53 -j DROP"
        assert rb == "iptables -D FORWARD -s 192.168.100.2 -d 10.0.0.5 -p udp --dport 53 -j DROP"

    def test_rate_limit_iptables_limit(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-rate-1",
            action=IntentAction.RATE_LIMIT,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="192.168.1.50",
            protocol="tcp",
            destination_port=443,
            rate_limit_kbps=500,
        )
        res = compiler.compile(intent)
        assert len(res.forward_commands) == 2
        assert len(res.rollback_commands) == 2

        # Forward: accept up to rate limit, then drop excess
        assert "-m limit --limit 500/s -j ACCEPT" in res.forward_commands[0]
        assert "-j DROP" in res.forward_commands[1]

        # Rollback: deleted in reverse order
        assert "-j DROP" in res.rollback_commands[0]
        assert "-m limit --limit 500/s -j ACCEPT" in res.rollback_commands[1]

    def test_rate_limit_tc_interface(self, compiler):
        intent = CanonicalIntent(
            intent_id="tc-rate-1",
            action=IntentAction.RATE_LIMIT,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            interface="eth1",
            rate_limit_kbps=10000,
            extra_params={"method": "tc"},
        )
        res = compiler.compile(intent)
        assert len(res.forward_commands) == 2
        assert res.forward_commands[0] == "tc qdisc add dev eth1 root handle 1: htb default 10"
        assert res.forward_commands[1] == "tc class add dev eth1 parent 1: classid 1:10 htb rate 10000kbit"

        assert len(res.rollback_commands) == 1
        assert res.rollback_commands[0] == "tc qdisc del dev eth1 root"

    def test_restore_route_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-route-1",
            action=IntentAction.RESTORE_ROUTE,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            network_prefix="10.20.0.0/16",
            next_hop="192.168.1.1",
            interface="eth1",
        )
        res = compiler.compile(intent)
        assert res.forward_commands == ["ip route add 10.20.0.0/16 via 192.168.1.1 dev eth1"]
        assert res.rollback_commands == ["ip route del 10.20.0.0/16 via 192.168.1.1 dev eth1"]

    def test_clear_filter_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-clear-1",
            action=IntentAction.CLEAR_FILTER,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="192.168.1.100",
            protocol="tcp",
            destination_port=80,
        )
        res = compiler.compile(intent)
        assert res.forward_commands == ["iptables -D FORWARD -s 192.168.1.100 -p tcp --dport 80 -j DROP"]
        assert res.rollback_commands == ["iptables -I FORWARD -s 192.168.1.100 -p tcp --dport 80 -j DROP"]

    def test_reset_interface_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="ipt-reset-1",
            action=IntentAction.RESET_INTERFACE,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            interface="eth2",
        )
        res = compiler.compile(intent)
        assert res.forward_commands == [
            "ip link set dev eth2 down",
            "ip link set dev eth2 up",
        ]
        assert res.rollback_commands == [
            "ip link set dev eth2 up",
        ]


# =============================================================================
# 3. Cisco ACL Compilation Tests
# =============================================================================

class TestCiscoAclCompilation:
    """Test suite for Cisco IOS / IOS-XE ACL compilation, wildcard masks, and reverse unbinding."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler()

    def test_cisco_drop_traffic_subnet_wildcard_calculation(self, compiler):
        # 10.1.1.0/24 subnet -> wildcard mask 0.0.0.255
        # Single IP 192.168.1.5 -> host 192.168.1.5
        intent = CanonicalIntent(
            intent_id="cisco-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="cisco-r1",
            target_platform=TargetPlatform.CISCO_ACL,
            source_ip="10.1.1.0/24",
            destination_ip="192.168.1.5",
            protocol="tcp",
            destination_port=80,
            interface="GigabitEthernet0/1",
            extra_params={"acl_name": "NETOPS_PROTECT"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is True
        fwd = res.forward_commands
        rb = res.rollback_commands

        # Forward creates ACL then attaches to interface
        assert fwd == [
            "ip access-list extended NETOPS_PROTECT",
            "10 deny tcp 10.1.1.0 0.0.0.255 host 192.168.1.5 eq 80",
            "20 permit ip any any",
            "interface GigabitEthernet0/1",
            "ip access-group NETOPS_PROTECT in",
        ]

        # Rollback unbinds interface BEFORE deleting ACL (Reverse Topological Ordering)
        assert rb == [
            "interface GigabitEthernet0/1",
            "no ip access-group NETOPS_PROTECT in",
            "no ip access-list extended NETOPS_PROTECT",
        ]

        # Verify rollback steps
        assert len(res.rollback_steps) == 3
        assert res.rollback_steps[0].command == "interface GigabitEthernet0/1"
        assert res.rollback_steps[1].command == "no ip access-group NETOPS_PROTECT in"
        assert res.rollback_steps[2].command == "no ip access-list extended NETOPS_PROTECT"

    def test_cisco_drop_traffic_no_interface(self, compiler):
        intent = CanonicalIntent(
            intent_id="cisco-drop-2",
            action=IntentAction.DROP_TRAFFIC,
            target_node="cisco-r1",
            target_platform=TargetPlatform.CISCO_ACL,
            source_ip="172.16.0.0/16",
            extra_params={"acl_name": "FILTER_16"},
        )
        res = compiler.compile(intent)
        assert res.forward_commands == [
            "ip access-list extended FILTER_16",
            "10 deny tcp 172.16.0.0 0.0.255.255 any",
            "20 permit ip any any",
        ]
        assert res.rollback_commands == [
            "no ip access-list extended FILTER_16",
        ]

    def test_cisco_rate_limit_qos(self, compiler):
        intent = CanonicalIntent(
            intent_id="cisco-qos-1",
            action=IntentAction.RATE_LIMIT,
            target_node="cisco-r1",
            target_platform=TargetPlatform.CISCO_ACL,
            interface="GigabitEthernet0/2",
            rate_limit_kbps=5000,
            extra_params={"policy_name": "POLICE_5M"},
        )
        res = compiler.compile(intent)
        fwd = res.forward_commands
        rb = res.rollback_commands

        assert fwd == [
            "policy-map POLICE_5M",
            "class class-default",
            "police 5000000",
            "interface GigabitEthernet0/2",
            "service-policy input POLICE_5M",
        ]
        # Reverse unbinding
        assert rb == [
            "interface GigabitEthernet0/2",
            "no service-policy input POLICE_5M",
            "no policy-map POLICE_5M",
        ]

    def test_cisco_restore_route(self, compiler):
        intent = CanonicalIntent(
            intent_id="cisco-rt-1",
            action=IntentAction.RESTORE_ROUTE,
            target_node="cisco-r1",
            target_platform=TargetPlatform.CISCO_ACL,
            network_prefix="10.2.0.0/16",
            next_hop="192.168.10.1",
        )
        res = compiler.compile(intent)
        assert res.forward_commands == ["ip route 10.2.0.0 255.255.0.0 192.168.10.1"]
        assert res.rollback_commands == ["no ip route 10.2.0.0 255.255.0.0 192.168.10.1"]


# =============================================================================
# 4. Huawei VRP Compilation Tests
# =============================================================================

class TestHuaweiVrpCompilation:
    """Test suite for Huawei VRP 5-tier ACL/Policy hierarchy and reverse unbinding."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler()

    def test_huawei_drop_traffic_5tier_hierarchy_and_rollback(self, compiler):
        intent = CanonicalIntent(
            intent_id="hw-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="huawei-ne40",
            target_platform=TargetPlatform.HUAWEI_VRP,
            source_ip="192.168.10.0/24",
            destination_ip="10.5.5.5",
            protocol="tcp",
            destination_port=8080,
            interface="GigabitEthernet0/0/1",
            extra_params={
                "acl_number": 3999,
                "classifier_name": "tc_netops_sec",
                "behavior_name": "tb_netops_sec",
                "policy_name": "tp_netops_sec",
                "rule_number": 10,
            },
        )
        res = compiler.compile(intent)
        assert res.is_safe is True
        fwd = res.forward_commands
        rb = res.rollback_commands

        # Check 5-tier hierarchy construction
        assert fwd == [
            "acl number 3999",
            "rule 10 deny tcp source 192.168.10.0 0.0.0.255 destination 10.5.5.5 0 destination-port eq 8080",
            "traffic classifier tc_netops_sec",
            "if-match acl 3999",
            "traffic behavior tb_netops_sec",
            "deny",
            "traffic policy tp_netops_sec",
            "classifier tc_netops_sec behavior tb_netops_sec",
            "interface GigabitEthernet0/0/1",
            "traffic-policy tp_netops_sec inbound",
        ]

        # Check exact reverse topological rollback order:
        # interface -> policy -> behavior -> classifier -> acl
        assert rb == [
            "interface GigabitEthernet0/0/1",
            "undo traffic-policy tp_netops_sec inbound",
            "undo traffic policy tp_netops_sec",
            "undo traffic behavior tb_netops_sec",
            "undo traffic classifier tc_netops_sec",
            "undo acl number 3999",
        ]

        assert len(res.rollback_steps) == 6
        assert res.rollback_steps[0].command == "interface GigabitEthernet0/0/1"
        assert res.rollback_steps[5].command == "undo acl number 3999"

    def test_huawei_rate_limit(self, compiler):
        intent = CanonicalIntent(
            intent_id="hw-rate-1",
            action=IntentAction.RATE_LIMIT,
            target_node="huawei-ne40",
            target_platform=TargetPlatform.HUAWEI_VRP,
            interface="GigabitEthernet0/0/2",
            rate_limit_kbps=8000,
            extra_params={
                "classifier_name": "tc_rate",
                "behavior_name": "tb_rate",
                "policy_name": "tp_rate",
            },
        )
        res = compiler.compile(intent)
        fwd = res.forward_commands
        rb = res.rollback_commands

        assert "car cir 8000" in fwd[3]
        assert rb == [
            "interface GigabitEthernet0/0/2",
            "undo traffic-policy tp_rate inbound",
            "undo traffic policy tp_rate",
            "undo traffic behavior tb_rate",
            "undo traffic classifier tc_rate",
        ]

    def test_huawei_restore_route(self, compiler):
        intent = CanonicalIntent(
            intent_id="hw-rt-1",
            action=IntentAction.RESTORE_ROUTE,
            target_node="huawei-ne40",
            target_platform=TargetPlatform.HUAWEI_VRP,
            network_prefix="10.100.0.0/16",
            next_hop="192.168.0.254",
        )
        res = compiler.compile(intent)
        assert res.forward_commands == ["ip route-static 10.100.0.0 255.255.0.0 192.168.0.254"]
        assert res.rollback_commands == ["undo ip route-static 10.100.0.0 255.255.0.0 192.168.0.254"]


# =============================================================================
# 5. Linux FRRouting (vtysh) Compilation Tests
# =============================================================================

class TestLinuxFrrCompilation:
    """Test suite for Linux FRRouting vtysh syntax compilation and rollback."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler()

    def test_frr_drop_traffic_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="frr-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="frr-spine1",
            target_platform=TargetPlatform.LINUX_FRR,
            source_ip="192.168.5.10",
            extra_params={"acl_name": "NETOPS_BLACKHOLE"},
        )
        res = compiler.compile(intent)
        assert res.forward_commands == [
            "vtysh -c 'configure terminal' -c 'access-list NETOPS_BLACKHOLE deny 192.168.5.10/32'"
        ]
        assert res.rollback_commands == [
            "vtysh -c 'configure terminal' -c 'no access-list NETOPS_BLACKHOLE deny 192.168.5.10/32'"
        ]

    def test_frr_restore_route_compilation(self, compiler):
        intent = CanonicalIntent(
            intent_id="frr-route-1",
            action=IntentAction.RESTORE_ROUTE,
            target_node="frr-spine1",
            target_platform=TargetPlatform.LINUX_FRR,
            network_prefix="10.20.0.0/24",
            next_hop="10.1.1.2",
        )
        res = compiler.compile(intent)
        assert res.forward_commands == [
            "vtysh -c 'configure terminal' -c 'ip route 10.20.0.0/24 10.1.1.2'"
        ]
        assert res.rollback_commands == [
            "vtysh -c 'configure terminal' -c 'no ip route 10.20.0.0/24 10.1.1.2'"
        ]

    def test_frr_rate_limit_flowspec(self, compiler):
        intent = CanonicalIntent(
            intent_id="frr-flowspec-1",
            action=IntentAction.RATE_LIMIT,
            target_node="frr-spine1",
            target_platform=TargetPlatform.LINUX_FRR,
            rate_limit_kbps=25000,
        )
        res = compiler.compile(intent)
        assert res.forward_commands == [
            "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'match-action RATE_LIMIT' -c 'rate 25000'"
        ]
        assert res.rollback_commands == [
            "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'no match-action RATE_LIMIT'"
        ]


# =============================================================================
# 6. Composite Plan Compilation & Global Reverse Topological Ordering Tests
# =============================================================================

class TestCompositePlanCompilation:
    """Test compiling multi-intent remediation plans with global rollback inversion."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler()

    def test_composite_plan_reverse_topological_rollback(self, compiler):
        # Plan has 2 intents:
        # 1. DROP_TRAFFIC on Cisco
        # 2. RESTORE_ROUTE on Cisco
        intent1 = CanonicalIntent(
            intent_id="p1-drop",
            action=IntentAction.DROP_TRAFFIC,
            target_node="edge-cisco",
            target_platform=TargetPlatform.CISCO_ACL,
            source_ip="10.99.1.1",
            interface="GigabitEthernet0/1",
            extra_params={"acl_name": "P1_ACL"},
        )
        intent2 = CanonicalIntent(
            intent_id="p2-route",
            action=IntentAction.RESTORE_ROUTE,
            target_node="edge-cisco",
            target_platform=TargetPlatform.CISCO_ACL,
            network_prefix="192.168.200.0/24",
            next_hop="10.0.0.254",
        )

        composite = compiler.compile_composite_plan([intent1, intent2])
        assert composite.is_safe is True
        assert len(composite.forward_commands) == 6  # 5 from intent1 + 1 from intent2
        assert len(composite.rollback_commands) == 4  # 1 from intent2 + 3 from intent1

        # Intent 2 forward executes AFTER Intent 1 forward
        assert composite.forward_commands[-1] == "ip route 192.168.200.0 255.255.255.0 10.0.0.254"

        # Rollback of Intent 2 MUST execute FIRST in composite rollback!
        assert composite.rollback_commands[0] == "no ip route 192.168.200.0 255.255.255.0 10.0.0.254"

        # Followed by unbinding Intent 1's ACL from interface
        assert composite.rollback_commands[1] == "interface GigabitEthernet0/1"
        assert composite.rollback_commands[2] == "no ip access-group P1_ACL in"
        assert composite.rollback_commands[3] == "no ip access-list extended P1_ACL"

        # Check sequential step indexing
        assert [s.step_number for s in composite.rollback_steps] == [1, 2, 3, 4]

    def test_compile_plan_list_helper(self, compiler):
        intents = [
            CanonicalIntent(
                intent_id="it-1",
                action=IntentAction.DROP_TRAFFIC,
                target_node="n1",
                target_platform=TargetPlatform.LINUX_IPTABLES,
                source_ip="1.1.1.1",
            ),
            CanonicalIntent(
                intent_id="it-2",
                action=IntentAction.DROP_TRAFFIC,
                target_node="n2",
                target_platform=TargetPlatform.LINUX_FRR,
                source_ip="2.2.2.2",
            ),
        ]
        results = compile_remediation_plan(intents)
        assert len(results) == 2
        assert results[0].intent_id == "it-1"
        assert results[1].intent_id == "it-2"


# =============================================================================
# 7. AAL Safety Whitelist Gating Tests
# =============================================================================

class TestAALSecurityGateIntegration:
    """Test that destructive commands are strictly rejected by the intent compiler."""

    @pytest.fixture
    def compiler(self):
        return CanonicalIntentCompiler(strict_safety=True)

    @pytest.mark.parametrize(
        "destructive_cmd",
        [
            "reboot",
            "poweroff",
            "shutdown",
            "init 0",
            "iptables -F",
            "iptables --flush",
            "nft flush ruleset",
            "rm -rf /root",
            "ip link delete eth0",
            ":(){ :|:& };:",
        ],
    )
    def test_direct_safety_validator_rejects_destructive_commands(self, compiler, destructive_cmd):
        is_safe, reason = compiler.validate_safety(destructive_cmd)
        assert is_safe is False
        assert "SECURITY POLICY VIOLATION" in (reason or "")

    def test_table_flush_in_intent_blocked(self, compiler):
        # Simulate intent generating an unsafe command via extra_params or override
        intent = CanonicalIntent(
            intent_id="unsafe-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="10.0.0.1",
            extra_params={"chain": "FORWARD ; iptables -F"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is False
        assert "SECURITY POLICY VIOLATION" in (res.validation_error or "")

    def test_reboot_in_intent_blocked(self, compiler):
        intent = CanonicalIntent(
            intent_id="unsafe-2",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="10.0.0.1",
            extra_params={"chain": "FORWARD && reboot"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is False
        assert "Node reboot" in (res.validation_error or "")

    def test_raise_on_unsafe_flag(self, compiler):
        intent = CanonicalIntent(
            intent_id="unsafe-3",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="10.0.0.1",
            extra_params={"chain": "FORWARD ; rm -rf /etc"},
        )
        with pytest.raises(AALSecurityError) as exc:
            compiler.compile(intent, raise_on_unsafe=True)
        assert "SECURITY POLICY VIOLATION" in str(exc.value)
