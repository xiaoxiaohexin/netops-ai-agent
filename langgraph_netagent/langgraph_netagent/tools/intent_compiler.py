"""Canonical Intent Compiler and Mathematical Inverse Rollback Generator (Day-3).

Translates abstract declarative network remediation intents (CanonicalIntent)
into concrete, platform-specific command sequences across:
1. Linux netfilter / iptables
2. Cisco IOS / IOS-XE extended ACLs & QoS
3. Huawei VRP (ACL, Traffic Classifier, Behavior, Policy)
4. Linux FRRouting (vtysh)

Generates mathematically exact inverse rollback compensation commands in
reverse topological order (e.g. unbinding interfaces before deleting ACLs).
Integrates directly with AAL security policy validation to reject destructive
commands (reboots, table flushes, fork bombs).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CompilationResult,
    IntentAction,
    RollbackStep,
    TargetPlatform,
)
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer


class CanonicalIntentCompiler:
    """Multi-platform canonical intent compiler and exact rollback generator."""

    def __init__(
        self,
        validator: Optional[Any] = None,
        strict_safety: bool = True,
    ):
        """Initialize the compiler.

        Args:
            validator: Optional custom validator or AgentAccessLayer instance.
            strict_safety: If True, validate all compiled commands against AAL safety policies.
        """
        self.validator = validator
        self.strict_safety = strict_safety

    # -------------------------------------------------------------------------
    # Public Compilation API
    # -------------------------------------------------------------------------

    def compile(
        self,
        intent: CanonicalIntent,
        raise_on_unsafe: bool = False,
    ) -> CompilationResult:
        """Compile a single CanonicalIntent into forward and rollback commands.

        Args:
            intent: The abstract canonical remediation intent.
            raise_on_unsafe: If True, raise AALSecurityError immediately on safety violation.

        Returns:
            CompilationResult with forward_commands, rollback_commands, rollback_steps,
            and safety status.
        """
        platform = intent.target_platform
        if platform == TargetPlatform.LINUX_IPTABLES:
            forward_cmds, rollback_cmds = self._compile_linux_iptables(intent)
        elif platform == TargetPlatform.CISCO_ACL:
            forward_cmds, rollback_cmds = self._compile_cisco_acl(intent)
        elif platform == TargetPlatform.HUAWEI_VRP:
            forward_cmds, rollback_cmds = self._compile_huawei_vrp(intent)
        elif platform == TargetPlatform.LINUX_FRR:
            forward_cmds, rollback_cmds = self._compile_linux_frr(intent)
        else:
            raise ValueError(f"Unsupported target platform: '{platform}'")

        # Generate structured rollback steps in reverse topological order
        rollback_steps = self.build_rollback_steps(rollback_cmds, platform, intent)

        # Validate command safety via AAL policies
        is_safe = True
        validation_error: Optional[str] = None

        if self.strict_safety:
            for cmd in forward_cmds + rollback_cmds:
                cmd_safe, error_reason = self.validate_safety(cmd)
                if not cmd_safe:
                    is_safe = False
                    validation_error = error_reason
                    if raise_on_unsafe:
                        raise AALSecurityError(error_reason)
                    break

        return CompilationResult(
            intent_id=intent.intent_id,
            target_platform=platform,
            forward_commands=forward_cmds,
            rollback_commands=rollback_cmds,
            rollback_steps=rollback_steps,
            is_safe=is_safe,
            validation_error=validation_error,
            target_node=intent.target_node,
            extra_metadata={
                "action": intent.action.value,
                "command_count": len(forward_cmds),
                "rollback_count": len(rollback_cmds),
                "description": intent.description,
            },
        )

    def compile_plan(
        self,
        intents: List[CanonicalIntent],
        raise_on_unsafe: bool = False,
    ) -> List[CompilationResult]:
        """Compile a list of CanonicalIntents into ordered compilation results.

        Rollback steps across the composite plan maintain reverse topological
        order: the last executed intent is rolled back first.

        Args:
            intents: List of CanonicalIntents forming a remediation plan.
            raise_on_unsafe: If True, raise on any safety violation.

        Returns:
            List of CompilationResult objects.
        """
        results: List[CompilationResult] = []
        for intent in intents:
            result = self.compile(intent, raise_on_unsafe=raise_on_unsafe)
            results.append(result)
        return results

    def compile_composite_plan(
        self,
        intents: List[CanonicalIntent],
        plan_id: Optional[str] = None,
        raise_on_unsafe: bool = False,
    ) -> CompilationResult:
        """Compile multiple intents into a single aggregated CompilationResult.

        Forward commands execute in sequential order [Intent1, Intent2, ...].
        Rollback commands execute in global reverse topological order [IntentN_rb, ..., Intent1_rb].
        """
        if not intents:
            raise ValueError("Cannot compile empty intent list")

        target_platform = intents[0].target_platform
        pid = plan_id or f"composite-{intents[0].intent_id}"
        all_forward: List[str] = []
        composite_rollback: List[str] = []
        is_safe = True
        validation_error: Optional[str] = None

        # Gather forward commands in order
        compiled_list = self.compile_plan(intents, raise_on_unsafe=raise_on_unsafe)
        for res in compiled_list:
            all_forward.extend(res.forward_commands)
            if not res.is_safe:
                is_safe = False
                validation_error = res.validation_error

        # Gather rollback commands in reverse order across intents
        for res in reversed(compiled_list):
            composite_rollback.extend(res.rollback_commands)

        # Build composite rollback steps with sequential indexing
        composite_steps: List[RollbackStep] = []
        for idx, cmd in enumerate(composite_rollback, start=1):
            composite_steps.append(
                RollbackStep(
                    step_number=idx,
                    command=cmd,
                    description=f"Composite rollback step {idx}",
                    target_platform=target_platform,
                    timeout_sec=30.0,
                )
            )

        return CompilationResult(
            intent_id=pid,
            target_platform=target_platform,
            forward_commands=all_forward,
            rollback_commands=composite_rollback,
            rollback_steps=composite_steps,
            is_safe=is_safe,
            validation_error=validation_error,
            target_node=intents[0].target_node,
            extra_metadata={
                "intent_count": len(intents),
                "is_composite": True,
            },
        )

    # -------------------------------------------------------------------------
    # Safety Validation & Rollback Helpers
    # -------------------------------------------------------------------------

    def validate_safety(self, command: str) -> Tuple[bool, Optional[str]]:
        """Validate command against AAL safety policies and destructive patterns."""
        cmd_clean = command.strip()
        # If custom validator provided
        if self.validator is not None:
            if hasattr(self.validator, "validate_command_safety"):
                return self.validator.validate_command_safety(cmd_clean, read_only=False)

        # Fallback to AgentAccessLayer BLOCKED_PATTERNS
        subcmds = AgentAccessLayer.split_chained_commands(cmd_clean)
        check_list = [cmd_clean] + subcmds if len(subcmds) > 1 else [cmd_clean]

        for sub in check_list:
            for pattern, reason in AgentAccessLayer.BLOCKED_PATTERNS:
                if pattern.search(sub):
                    return False, f"SECURITY POLICY VIOLATION: {reason} (command: '{command}')"

        return True, None

    def build_rollback_steps(
        self,
        rollback_commands: List[str],
        platform: TargetPlatform,
        intent: CanonicalIntent,
    ) -> List[RollbackStep]:
        """Construct structured RollbackStep models with sequential indices."""
        steps: List[RollbackStep] = []
        for idx, cmd in enumerate(rollback_commands, start=1):
            steps.append(
                RollbackStep(
                    step_number=idx,
                    command=cmd,
                    description=f"Rollback {intent.action.value} step {idx} on {intent.target_node or 'node'}",
                    target_platform=platform,
                    timeout_sec=30.0,
                    target_node=intent.target_node,
                )
            )
        return steps

    # -------------------------------------------------------------------------
    # Platform 1: Linux Netfilter / iptables
    # -------------------------------------------------------------------------

    def _compile_linux_iptables(
        self,
        intent: CanonicalIntent,
    ) -> Tuple[List[str], List[str]]:
        """Compile intent to Linux iptables CLI syntax."""
        action = intent.action
        chain = intent.extra_params.get("chain", "FORWARD")
        table = intent.extra_params.get("table", "")
        table_flag = f"-t {table} " if table else ""

        if action == IntentAction.DROP_TRAFFIC:
            # Build match predicate
            match_parts = []
            if intent.source_ip and intent.source_ip.lower() not in ("any", "0.0.0.0/0"):
                match_parts.append(f"-s {intent.source_ip}")
            if intent.destination_ip and intent.destination_ip.lower() not in ("any", "0.0.0.0/0"):
                match_parts.append(f"-d {intent.destination_ip}")
            if intent.protocol:
                match_parts.append(f"-p {intent.protocol.lower()}")
            if intent.source_port and intent.source_port > 0:
                match_parts.append(f"--sport {intent.source_port}")
            if intent.destination_port and intent.destination_port > 0:
                match_parts.append(f"--dport {intent.destination_port}")
            if intent.interface:
                match_parts.append(f"-i {intent.interface}")

            match_clause = " ".join(match_parts)
            if match_clause:
                match_clause = " " + match_clause

            fwd = f"iptables {table_flag}-I {chain}{match_clause} -j DROP".strip()
            rb = f"iptables {table_flag}-D {chain}{match_clause} -j DROP".strip()
            return [fwd], [rb]

        elif action == IntentAction.RATE_LIMIT:
            rate = intent.rate_limit_kbps or 1000
            # If explicit tc method or interface rate limiting
            if intent.interface and intent.extra_params.get("method") == "tc":
                iface = intent.interface
                fwd = [
                    f"tc qdisc add dev {iface} root handle 1: htb default 10",
                    f"tc class add dev {iface} parent 1: classid 1:10 htb rate {rate}kbit",
                ]
                rb = [f"tc qdisc del dev {iface} root"]
                return fwd, rb
            else:
                # iptables limit module
                match_parts = []
                if intent.source_ip and intent.source_ip.lower() not in ("any", "0.0.0.0/0"):
                    match_parts.append(f"-s {intent.source_ip}")
                if intent.destination_ip and intent.destination_ip.lower() not in ("any", "0.0.0.0/0"):
                    match_parts.append(f"-d {intent.destination_ip}")
                if intent.protocol:
                    match_parts.append(f"-p {intent.protocol.lower()}")
                if intent.destination_port and intent.destination_port > 0:
                    match_parts.append(f"--dport {intent.destination_port}")
                if intent.interface:
                    match_parts.append(f"-i {intent.interface}")

                match_clause = " ".join(match_parts)
                if match_clause:
                    match_clause = " " + match_clause

                fwd = [
                    f"iptables {table_flag}-I {chain}{match_clause} -m limit --limit {rate}/s -j ACCEPT".strip(),
                    f"iptables {table_flag}-I {chain}{match_clause} -j DROP".strip(),
                ]
                # Rollback in reverse topological order
                rb = [
                    f"iptables {table_flag}-D {chain}{match_clause} -j DROP".strip(),
                    f"iptables {table_flag}-D {chain}{match_clause} -m limit --limit {rate}/s -j ACCEPT".strip(),
                ]
                return fwd, rb

        elif action in (IntentAction.RESTORE_ROUTE, IntentAction.REDIRECT_FLOW):
            prefix = intent.network_prefix or intent.destination_ip or "0.0.0.0/0"
            next_hop = intent.next_hop
            dev_clause = f" dev {intent.interface}" if intent.interface else ""

            if not next_hop:
                raise ValueError("next_hop is required for route operations")

            verb = "replace" if action == IntentAction.REDIRECT_FLOW else "add"
            fwd = [f"ip route {verb} {prefix} via {next_hop}{dev_clause}".strip()]

            # Rollback: if old route was provided, restore it, else delete
            old_nh = intent.extra_params.get("old_next_hop")
            if old_nh:
                rb = [f"ip route replace {prefix} via {old_nh}{dev_clause}".strip()]
            else:
                rb = [f"ip route del {prefix} via {next_hop}{dev_clause}".strip()]
            return fwd, rb

        elif action == IntentAction.CLEAR_FILTER:
            # Reverse of DROP_TRAFFIC
            match_parts = []
            if intent.source_ip and intent.source_ip.lower() not in ("any", "0.0.0.0/0"):
                match_parts.append(f"-s {intent.source_ip}")
            if intent.destination_ip and intent.destination_ip.lower() not in ("any", "0.0.0.0/0"):
                match_parts.append(f"-d {intent.destination_ip}")
            if intent.protocol:
                match_parts.append(f"-p {intent.protocol.lower()}")
            if intent.destination_port and intent.destination_port > 0:
                match_parts.append(f"--dport {intent.destination_port}")
            if intent.interface:
                match_parts.append(f"-i {intent.interface}")

            match_clause = " ".join(match_parts)
            if match_clause:
                match_clause = " " + match_clause

            fwd = [f"iptables {table_flag}-D {chain}{match_clause} -j DROP".strip()]
            rb = [f"iptables {table_flag}-I {chain}{match_clause} -j DROP".strip()]
            return fwd, rb

        elif action == IntentAction.RESET_INTERFACE:
            iface = intent.interface or "eth1"
            fwd = [
                f"ip link set dev {iface} down",
                f"ip link set dev {iface} up",
            ]
            rb = [f"ip link set dev {iface} up"]
            return fwd, rb

        raise NotImplementedError(f"Action '{action}' not implemented for Linux iptables")

    # -------------------------------------------------------------------------
    # Platform 2: Cisco IOS / IOS-XE ACL & Route
    # -------------------------------------------------------------------------

    def _compile_cisco_acl(
        self,
        intent: CanonicalIntent,
    ) -> Tuple[List[str], List[str]]:
        """Compile intent to Cisco IOS / IOS-XE CLI syntax."""
        action = intent.action

        if action == IntentAction.DROP_TRAFFIC:
            acl_name = intent.extra_params.get("acl_name", f"NETOPS_{intent.intent_id[:8].upper()}")
            proto = intent.protocol.lower() if intent.protocol else "ip"
            src_clause = self._cisco_ip_clause(intent.source_ip)
            dst_clause = self._cisco_ip_clause(intent.destination_ip)

            sport_clause = f" eq {intent.source_port}" if intent.source_port and intent.source_port > 0 else ""
            dport_clause = f" eq {intent.destination_port}" if intent.destination_port and intent.destination_port > 0 else ""

            rule_deny = f"10 deny {proto} {src_clause}{sport_clause} {dst_clause}{dport_clause}".strip()
            rule_permit = "20 permit ip any any"

            fwd = [
                f"ip access-list extended {acl_name}",
                rule_deny,
                rule_permit,
            ]
            if intent.interface:
                iface = intent.interface
                direction = intent.extra_params.get("direction", "in")
                fwd.extend([
                    f"interface {iface}",
                    f"ip access-group {acl_name} {direction}",
                ])
                # Rollback in reverse topological order: unbind interface before deleting ACL
                rb = [
                    f"interface {iface}",
                    f"no ip access-group {acl_name} {direction}",
                    f"no ip access-list extended {acl_name}",
                ]
            else:
                rb = [f"no ip access-list extended {acl_name}"]

            return fwd, rb

        elif action == IntentAction.RATE_LIMIT:
            policy_name = intent.extra_params.get("policy_name", f"NETOPS_QOS_{intent.intent_id[:8].upper()}")
            rate_bps = (intent.rate_limit_kbps or 1000) * 1000
            iface = intent.interface or "GigabitEthernet0/1"

            fwd = [
                f"policy-map {policy_name}",
                "class class-default",
                f"police {rate_bps}",
                f"interface {iface}",
                f"service-policy input {policy_name}",
            ]
            # Rollback: unbind policy from interface then destroy policy-map
            rb = [
                f"interface {iface}",
                f"no service-policy input {policy_name}",
                f"no policy-map {policy_name}",
            ]
            return fwd, rb

        elif action in (IntentAction.RESTORE_ROUTE, IntentAction.REDIRECT_FLOW):
            prefix_str = intent.network_prefix or intent.destination_ip
            if not prefix_str or not intent.next_hop:
                raise ValueError("network_prefix and next_hop are required for Cisco routing intent")

            net_addr, netmask, _ = self.parse_network(prefix_str)
            fwd = [f"ip route {net_addr} {netmask} {intent.next_hop}"]
            rb = [f"no ip route {net_addr} {netmask} {intent.next_hop}"]
            return fwd, rb

        elif action == IntentAction.CLEAR_FILTER:
            acl_name = intent.extra_params.get("acl_name", f"NETOPS_{intent.intent_id[:8].upper()}")
            if intent.interface:
                iface = intent.interface
                direction = intent.extra_params.get("direction", "in")
                fwd = [
                    f"interface {iface}",
                    f"no ip access-group {acl_name} {direction}",
                    f"no ip access-list extended {acl_name}",
                ]
                rb = [
                    f"ip access-list extended {acl_name}",
                    "20 permit ip any any",
                    f"interface {iface}",
                    f"ip access-group {acl_name} {direction}",
                ]
            else:
                fwd = [f"no ip access-list extended {acl_name}"]
                rb = [f"ip access-list extended {acl_name}", "20 permit ip any any"]
            return fwd, rb

        elif action == IntentAction.RESET_INTERFACE:
            iface = intent.interface or "GigabitEthernet0/1"
            fwd = [
                f"interface {iface}",
                "shutdown",
                "no shutdown",
            ]
            rb = [
                f"interface {iface}",
                "no shutdown",
            ]
            return fwd, rb

        raise NotImplementedError(f"Action '{action}' not implemented for Cisco ACL")

    # -------------------------------------------------------------------------
    # Platform 3: Huawei VRP (ACL, Traffic Policy, Route)
    # -------------------------------------------------------------------------

    def _compile_huawei_vrp(
        self,
        intent: CanonicalIntent,
    ) -> Tuple[List[str], List[str]]:
        """Compile intent to Huawei VRP CLI syntax."""
        action = intent.action

        if action == IntentAction.DROP_TRAFFIC:
            acl_num = intent.extra_params.get("acl_number", 3999)
            tc_name = intent.extra_params.get("classifier_name", f"tc_netops_{intent.intent_id[:8].lower()}")
            tb_name = intent.extra_params.get("behavior_name", f"tb_netops_{intent.intent_id[:8].lower()}")
            tp_name = intent.extra_params.get("policy_name", f"tp_netops_{intent.intent_id[:8].lower()}")
            rule_num = intent.extra_params.get("rule_number", 5)
            proto = intent.protocol.lower() if intent.protocol else "ip"

            src_clause = self._huawei_ip_clause(intent.source_ip, is_source=True)
            dst_clause = self._huawei_ip_clause(intent.destination_ip, is_source=False)
            sport_clause = f" source-port eq {intent.source_port}" if intent.source_port and intent.source_port > 0 else ""
            dport_clause = f" destination-port eq {intent.destination_port}" if intent.destination_port and intent.destination_port > 0 else ""

            rule_line = f"rule {rule_num} deny {proto}{src_clause}{sport_clause}{dst_clause}{dport_clause}".strip()

            fwd = [
                f"acl number {acl_num}",
                rule_line,
                f"traffic classifier {tc_name}",
                f"if-match acl {acl_num}",
                f"traffic behavior {tb_name}",
                "deny",
                f"traffic policy {tp_name}",
                f"classifier {tc_name} behavior {tb_name}",
            ]

            if intent.interface:
                iface = intent.interface
                direction = intent.extra_params.get("direction", "inbound")
                fwd.extend([
                    f"interface {iface}",
                    f"traffic-policy {tp_name} {direction}",
                ])
                # Rollback in reverse topological order:
                # 1. unbind interface policy
                # 2. undo traffic policy
                # 3. undo traffic behavior
                # 4. undo traffic classifier
                # 5. undo acl
                rb = [
                    f"interface {iface}",
                    f"undo traffic-policy {tp_name} {direction}",
                    f"undo traffic policy {tp_name}",
                    f"undo traffic behavior {tb_name}",
                    f"undo traffic classifier {tc_name}",
                    f"undo acl number {acl_num}",
                ]
            else:
                rb = [
                    f"undo traffic policy {tp_name}",
                    f"undo traffic behavior {tb_name}",
                    f"undo traffic classifier {tc_name}",
                    f"undo acl number {acl_num}",
                ]

            return fwd, rb

        elif action == IntentAction.RATE_LIMIT:
            rate = intent.rate_limit_kbps or 1000
            tc_name = intent.extra_params.get("classifier_name", f"tc_netops_{intent.intent_id[:8].lower()}")
            tb_name = intent.extra_params.get("behavior_name", f"tb_netops_{intent.intent_id[:8].lower()}")
            tp_name = intent.extra_params.get("policy_name", f"tp_netops_{intent.intent_id[:8].lower()}")
            iface = intent.interface or "GigabitEthernet0/0/1"

            fwd = [
                f"traffic classifier {tc_name}",
                "if-match any",
                f"traffic behavior {tb_name}",
                f"car cir {rate}",
                f"traffic policy {tp_name}",
                f"classifier {tc_name} behavior {tb_name}",
                f"interface {iface}",
                f"traffic-policy {tp_name} inbound",
            ]
            rb = [
                f"interface {iface}",
                f"undo traffic-policy {tp_name} inbound",
                f"undo traffic policy {tp_name}",
                f"undo traffic behavior {tb_name}",
                f"undo traffic classifier {tc_name}",
            ]
            return fwd, rb

        elif action in (IntentAction.RESTORE_ROUTE, IntentAction.REDIRECT_FLOW):
            prefix_str = intent.network_prefix or intent.destination_ip
            if not prefix_str or not intent.next_hop:
                raise ValueError("network_prefix and next_hop are required for Huawei routing intent")

            net_addr, netmask, _ = self.parse_network(prefix_str)
            fwd = [f"ip route-static {net_addr} {netmask} {intent.next_hop}"]
            rb = [f"undo ip route-static {net_addr} {netmask} {intent.next_hop}"]
            return fwd, rb

        elif action == IntentAction.CLEAR_FILTER:
            acl_num = intent.extra_params.get("acl_number", 3999)
            tc_name = intent.extra_params.get("classifier_name", f"tc_netops_{intent.intent_id[:8].lower()}")
            tb_name = intent.extra_params.get("behavior_name", f"tb_netops_{intent.intent_id[:8].lower()}")
            tp_name = intent.extra_params.get("policy_name", f"tp_netops_{intent.intent_id[:8].lower()}")

            if intent.interface:
                iface = intent.interface
                direction = intent.extra_params.get("direction", "inbound")
                fwd = [
                    f"interface {iface}",
                    f"undo traffic-policy {tp_name} {direction}",
                    f"undo traffic policy {tp_name}",
                    f"undo traffic behavior {tb_name}",
                    f"undo traffic classifier {tc_name}",
                    f"undo acl number {acl_num}",
                ]
                rb = [
                    f"acl number {acl_num}",
                    f"traffic classifier {tc_name}",
                    f"if-match acl {acl_num}",
                    f"traffic behavior {tb_name}",
                    "deny",
                    f"traffic policy {tp_name}",
                    f"classifier {tc_name} behavior {tb_name}",
                    f"interface {iface}",
                    f"traffic-policy {tp_name} {direction}",
                ]
            else:
                fwd = [
                    f"undo traffic policy {tp_name}",
                    f"undo traffic behavior {tb_name}",
                    f"undo traffic classifier {tc_name}",
                    f"undo acl number {acl_num}",
                ]
                rb = [
                    f"acl number {acl_num}",
                    f"traffic classifier {tc_name}",
                    f"traffic behavior {tb_name}",
                    f"traffic policy {tp_name}",
                ]
            return fwd, rb

        elif action == IntentAction.RESET_INTERFACE:
            iface = intent.interface or "GigabitEthernet0/0/1"
            fwd = [
                f"interface {iface}",
                "shutdown",
                "undo shutdown",
            ]
            rb = [
                f"interface {iface}",
                "undo shutdown",
            ]
            return fwd, rb

        raise NotImplementedError(f"Action '{action}' not implemented for Huawei VRP")

    # -------------------------------------------------------------------------
    # Platform 4: Linux FRRouting (vtysh)
    # -------------------------------------------------------------------------

    def _compile_linux_frr(
        self,
        intent: CanonicalIntent,
    ) -> Tuple[List[str], List[str]]:
        """Compile intent to Linux FRRouting vtysh syntax."""
        action = intent.action

        if action == IntentAction.DROP_TRAFFIC:
            acl_name = intent.extra_params.get("acl_name", f"NETOPS_{intent.intent_id[:8].upper()}")
            src_cidr = self._frr_cidr_clause(intent.source_ip)
            fwd = [f"vtysh -c 'configure terminal' -c 'access-list {acl_name} deny {src_cidr}'"]
            rb = [f"vtysh -c 'configure terminal' -c 'no access-list {acl_name} deny {src_cidr}'"]
            return fwd, rb

        elif action == IntentAction.RATE_LIMIT:
            rate = intent.rate_limit_kbps or 1000
            fwd = [
                f"vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'match-action RATE_LIMIT' -c 'rate {rate}'"
            ]
            rb = [
                "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' -c 'no match-action RATE_LIMIT'"
            ]
            return fwd, rb

        elif action in (IntentAction.RESTORE_ROUTE, IntentAction.REDIRECT_FLOW):
            prefix = intent.network_prefix or intent.destination_ip
            if not prefix or not intent.next_hop:
                raise ValueError("network_prefix and next_hop are required for FRR routing intent")

            fwd = [f"vtysh -c 'configure terminal' -c 'ip route {prefix} {intent.next_hop}'"]
            rb = [f"vtysh -c 'configure terminal' -c 'no ip route {prefix} {intent.next_hop}'"]
            return fwd, rb

        elif action == IntentAction.CLEAR_FILTER:
            acl_name = intent.extra_params.get("acl_name", f"NETOPS_{intent.intent_id[:8].upper()}")
            src_cidr = self._frr_cidr_clause(intent.source_ip)
            fwd = [f"vtysh -c 'configure terminal' -c 'no access-list {acl_name} deny {src_cidr}'"]
            rb = [f"vtysh -c 'configure terminal' -c 'access-list {acl_name} deny {src_cidr}'"]
            return fwd, rb

        elif action == IntentAction.RESET_INTERFACE:
            iface = intent.interface or "eth1"
            fwd = [
                f"vtysh -c 'configure terminal' -c 'interface {iface}' -c 'shutdown' -c 'no shutdown'"
            ]
            rb = [
                f"vtysh -c 'configure terminal' -c 'interface {iface}' -c 'no shutdown'"
            ]
            return fwd, rb

        raise NotImplementedError(f"Action '{action}' not implemented for Linux FRR")

    # -------------------------------------------------------------------------
    # IP & Subnet Wildcard Utilities
    # -------------------------------------------------------------------------

    @staticmethod
    def parse_network(ip_str: str) -> Tuple[str, str, str]:
        """Parse an IP or CIDR into (network_address, netmask, wildcard_mask)."""
        clean = ip_str.strip()
        try:
            if "/" in clean:
                net = ipaddress.ip_network(clean, strict=False)
            else:
                # Default host mask
                net = ipaddress.ip_network(f"{clean}/32", strict=False)
            net_addr = str(net.network_address)
            netmask = str(net.netmask)
            wildcard = str(net.hostmask)
            return net_addr, netmask, wildcard
        except ValueError as exc:
            raise ValueError(f"Invalid IP address or CIDR: '{ip_str}'") from exc

    def _cisco_ip_clause(self, ip_str: Optional[str]) -> str:
        """Format an IP string into Cisco ACL source/destination format."""
        if not ip_str or ip_str.lower() in ("any", "0.0.0.0/0"):
            return "any"
        net_addr, _, wildcard = self.parse_network(ip_str)
        if wildcard == "0.0.0.0":
            return f"host {net_addr}"
        return f"{net_addr} {wildcard}"

    def _huawei_ip_clause(self, ip_str: Optional[str], is_source: bool = True) -> str:
        """Format an IP string into Huawei VRP rule clause format."""
        prefix = " source" if is_source else " destination"
        if not ip_str or ip_str.lower() in ("any", "0.0.0.0/0"):
            return ""
        net_addr, _, wildcard = self.parse_network(ip_str)
        if wildcard == "0.0.0.0":
            return f"{prefix} {net_addr} 0"
        return f"{prefix} {net_addr} {wildcard}"

    def _frr_cidr_clause(self, ip_str: Optional[str]) -> str:
        """Format an IP string into FRR CIDR syntax."""
        if not ip_str or ip_str.lower() in ("any", "0.0.0.0/0"):
            return "any"
        if "/" in ip_str:
            return ip_str.strip()
        return f"{ip_str.strip()}/32"


# =============================================================================
# Functional Convenience Helpers
# =============================================================================

def compile_canonical_intent(
    intent: CanonicalIntent,
    validator: Optional[Any] = None,
    raise_on_unsafe: bool = False,
) -> CompilationResult:
    """Convenience functional wrapper around CanonicalIntentCompiler.compile."""
    compiler = CanonicalIntentCompiler(validator=validator)
    return compiler.compile(intent, raise_on_unsafe=raise_on_unsafe)


def compile_remediation_plan(
    intents: List[CanonicalIntent],
    validator: Optional[Any] = None,
    raise_on_unsafe: bool = False,
) -> List[CompilationResult]:
    """Convenience functional wrapper around CanonicalIntentCompiler.compile_plan."""
    compiler = CanonicalIntentCompiler(validator=validator)
    return compiler.compile_plan(intents, raise_on_unsafe=raise_on_unsafe)
