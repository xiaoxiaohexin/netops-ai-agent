"""Programmable Fault Injection System for Hermetic Testing and Self-Healing Loops."""

from __future__ import annotations
from enum import Enum
import uuid
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FaultType(str, Enum):
    """Types of faults that can be injected into the virtual lab."""
    PING_DROP = "ping_drop"             # Drop ping packets between specified src and dst
    INTERMITTENT_LOSS = "loss"          # Induce a specific percentage of packet loss
    MISSING_ROUTE = "missing_route"     # Suppress a route from node's routing table / FIB
    INTERFACE_DOWN = "interface_down"   # Set interface operational state to DOWN
    DEPLOY_FAILURE = "deploy_failure"   # Trigger failure on lab deploy()
    BUFFER_OVERLIMIT = "buffer_overlimit"  # Simulate queue buffer overflow / rate limit overlimits
    TRAFFIC_OVERLOAD = "traffic_overload"  # Simulate high-volume external traffic overload


class FaultRule(BaseModel):
    """Definition of an injected fault rule."""
    model_config = ConfigDict(populate_by_name=True)

    rule_id: str = Field(default_factory=lambda: f"fault-{uuid.uuid4().hex[:8]}")
    fault_type: FaultType = Field(..., description="Type of fault")
    target_node: Optional[str] = Field(default=None, description="Target node identifier")
    target_ip_or_prefix: Optional[str] = Field(default=None, description="Destination IP or CIDR prefix")
    target_interface: Optional[str] = Field(default=None, description="Interface name")
    loss_pct: float = Field(default=100.0, ge=0.0, le=100.0, description="Packet loss percentage for PING_DROP/LOSS")
    overlimits: int = Field(default=15000, description="Simulated overlimits count for buffer overlimit")
    dropped: int = Field(default=5000, description="Simulated dropped packets count for buffer overlimit")
    source_ip: Optional[str] = Field(default=None, description="Offending source IP or subnet for overload")
    dest_port: Optional[int] = Field(default=None, description="Target destination port for overload")
    active_until_retry: Optional[int] = Field(default=None, description="Auto-clear when retry counter reaches this count")
    cleared_on_remediation: bool = Field(default=True, description="True if repairing the configuration file clears this fault")
    error_message: Optional[str] = Field(default=None, description="Custom error message or stderr string")


def _matches_target_node(cfg_key: str, target_node: Optional[str]) -> bool:
    """Check if configuration key/path corresponds to the target node."""
    if not target_node:
        return True
    target_node = target_node.strip()
    norm_key = cfg_key.replace("\\", "/").strip().strip("/")
    parts = norm_key.split("/")

    # Exact node name match
    if target_node == norm_key or target_node in parts:
        return True

    # Base name matching (e.g. frr1 matches config/frr/frr.conf, srl1 matches config/srl/srl.cfg)
    base_name = target_node.rstrip("0123456789")
    if base_name and base_name != target_node:
        if base_name == norm_key or base_name in parts:
            return True
        # Check filename stem, e.g. frr.conf or srl.cfg
        filename = parts[-1]
        file_stem = filename.split(".")[0]
        if file_stem == target_node or file_stem == base_name:
            return True

    return False


class FaultInjector:
    """Manages active fault injection rules for the mock network engine."""

    def __init__(self, initial_rules: Optional[List[FaultRule]] = None):
        self._rules: Dict[str, FaultRule] = {}
        if initial_rules:
            for r in initial_rules:
                self.add_rule(r)

    def add_rule(self, rule: FaultRule) -> str:
        """Register a new fault rule."""
        self._rules[rule.rule_id] = rule
        return rule.rule_id

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a fault rule by its rule_id."""
        return self._rules.pop(rule_id, None) is not None

    def clear_all(self) -> None:
        """Clear all active fault rules."""
        self._rules.clear()

    def get_active_rules(self) -> List[FaultRule]:
        """Return a copy of all currently active fault rules."""
        return list(self._rules.values())

    def should_fail_deploy(self, lab_name: Optional[str] = None) -> Optional[FaultRule]:
        """Check if deployment should fail due to an active fault rule."""
        for rule in self._rules.values():
            if rule.fault_type == FaultType.DEPLOY_FAILURE:
                if rule.target_node is None or rule.target_node == lab_name:
                    return rule
        return None

    def should_drop_ping(self, src_node: str, dst_ip: str) -> Optional[FaultRule]:
        """Check if ping between src_node and dst_ip should be dropped or degraded."""
        for rule in self._rules.values():
            if rule.fault_type in (FaultType.PING_DROP, FaultType.INTERMITTENT_LOSS):
                # Check target_node match if specified
                if rule.target_node and rule.target_node != src_node:
                    continue
                # Check target_ip match if specified
                if rule.target_ip_or_prefix:
                    # Match exact IP or prefix substring
                    target = rule.target_ip_or_prefix.split("/")[0]
                    if target != dst_ip and not dst_ip.startswith(target):
                        continue
                return rule
        return None

    def should_suppress_route(self, node: str, prefix: str) -> Optional[FaultRule]:
        """Check if a route prefix on a given node should be hidden/suppressed."""
        for rule in self._rules.values():
            if rule.fault_type == FaultType.MISSING_ROUTE:
                if rule.target_node and rule.target_node != node:
                    continue
                if rule.target_ip_or_prefix:
                    pfx_clean = rule.target_ip_or_prefix.strip()
                    if pfx_clean != prefix.strip() and not prefix.startswith(pfx_clean):
                        continue
                return rule
        return None

    def is_interface_down(self, node: str, interface_name: str) -> Optional[FaultRule]:
        """Check if an interface on a given node is forced into a DOWN state."""
        for rule in self._rules.values():
            if rule.fault_type == FaultType.INTERFACE_DOWN:
                if rule.target_node and rule.target_node != node:
                    continue
                if rule.target_interface and rule.target_interface != interface_name:
                    continue
                return rule
        return None

    def get_buffer_overlimit(self, node: str, interface: Optional[str] = None) -> Optional[FaultRule]:
        """Check if a buffer overlimit or traffic overload fault is active for the given node/interface."""
        for rule in self._rules.values():
            if rule.fault_type in (FaultType.BUFFER_OVERLIMIT, FaultType.TRAFFIC_OVERLOAD):
                if rule.target_node and rule.target_node != node:
                    continue
                if interface and rule.target_interface and rule.target_interface != interface:
                    continue
                return rule
        return None

    def on_retry(self, retry_count: int) -> List[str]:
        """Expire rules whose active_until_retry threshold has been reached."""
        expired = []
        for rule_id, rule in list(self._rules.items()):
            if rule.active_until_retry is not None and retry_count >= rule.active_until_retry:
                expired.append(rule_id)
                del self._rules[rule_id]
        return expired

    def on_redeploy(self, updated_configs: Dict[str, str]) -> List[FaultRule]:
        """Inspect redeployed configuration file contents and auto-clear resolved faults.
        
        Args:
            updated_configs: Dict mapping relative file path or node name to file content string.
            
        Returns:
            List of FaultRules that were cleared.
        """
        cleared: List[FaultRule] = []
        for rule_id, rule in list(self._rules.items()):
            if not rule.cleared_on_remediation:
                continue

            # When rule.target_node is set, ONLY inspect configs matching that node
            matching_configs = {}
            for cfg_key, content in updated_configs.items():
                if _matches_target_node(cfg_key, rule.target_node):
                    matching_configs[cfg_key] = content

            if rule.target_node and not matching_configs:
                continue

            configs_to_check = matching_configs if rule.target_node else updated_configs

            # Check if this rule is a missing route that is now present in the config
            if rule.fault_type == FaultType.MISSING_ROUTE:
                target_pfx = rule.target_ip_or_prefix
                if not target_pfx:
                    cleared.append(rule)
                    del self._rules[rule_id]
                    continue

                found = False
                for cfg_key, content in configs_to_check.items():
                    if target_pfx in content or target_pfx.split("/")[0] in content:
                        found = True
                        break

                if found:
                    cleared.append(rule)
                    del self._rules[rule_id]

            elif rule.fault_type == FaultType.INTERFACE_DOWN:
                # If interface configuration is touched / updated
                if not rule.target_interface:
                    cleared.append(rule)
                    del self._rules[rule_id]
                    continue

                found = False
                for cfg_key, content in configs_to_check.items():
                    if rule.target_interface in content:
                        found = True
                        break

                if found:
                    cleared.append(rule)
                    del self._rules[rule_id]

            elif rule.fault_type == FaultType.PING_DROP:
                # If target IP/prefix was associated with a missing route that is now in configs
                if not rule.target_ip_or_prefix:
                    cleared.append(rule)
                    del self._rules[rule_id]
                    continue

                found = False
                for cfg_key, content in configs_to_check.items():
                    if rule.target_ip_or_prefix in content or rule.target_ip_or_prefix.split("/")[0] in content:
                        found = True
                        break

                if found:
                    cleared.append(rule)
                    del self._rules[rule_id]

        return cleared

    def on_remediation(
        self,
        command: Optional[str] = None,
        node: Optional[str] = None,
        configs: Optional[Dict[str, str]] = None,
    ) -> List[FaultRule]:
        """Inspect candidate remediation action (e.g. iptables drop command or redeployed configs) and clear resolved faults.
        
        If an iptables rule dropping the offending IP/port is applied, clear the buffer overlimit fault.
        """
        cleared: List[FaultRule] = []

        if configs:
            cleared.extend(self.on_redeploy(configs))

        if command:
            cmd_clean = command.strip()
            # Check for iptables DROP or REJECT rule
            if "iptables" in cmd_clean and ("DROP" in cmd_clean or "REJECT" in cmd_clean):
                for rule_id, rule in list(self._rules.items()):
                    if not rule.cleared_on_remediation:
                        continue
                    if rule.fault_type in (FaultType.BUFFER_OVERLIMIT, FaultType.TRAFFIC_OVERLOAD):
                        # Node match check
                        if rule.target_node and node and rule.target_node != node:
                            continue

                        # Offending source IP, prefix, or port matching
                        matched = False
                        if rule.source_ip:
                            src = rule.source_ip.split("/")[0]
                            if src in cmd_clean:
                                matched = True
                        elif rule.target_ip_or_prefix:
                            pfx = rule.target_ip_or_prefix.split("/")[0]
                            if pfx in cmd_clean:
                                matched = True
                        elif rule.dest_port:
                            if f"--dport {rule.dest_port}" in cmd_clean or str(rule.dest_port) in cmd_clean:
                                matched = True
                        else:
                            matched = True

                        if matched:
                            cleared.append(rule)
                            del self._rules[rule_id]

        return cleared

