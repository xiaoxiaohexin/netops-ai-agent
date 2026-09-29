"""Network Intent Pydantic Data Contracts.

Defines the structured representation of user requirements parsed from natural language,
as well as the Canonical Intent taxonomy, rollback steps, and compilation result contracts
for Milestone 2 (Canonical Intent Compiler & Rollback Generator).
"""

from __future__ import annotations
from enum import Enum
import ipaddress
import re
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# =============================================================================
# Day-1 Greenfield Intent Models (Preserved for backwards compatibility)
# =============================================================================

class ProtocolType(str, Enum):
    """Routing and network protocols supported."""
    STATIC = "static"
    OSPF = "ospf"
    BGP = "bgp"
    ISIS = "isis"
    RIP = "rip"
    NONE = "none"

    @classmethod
    def _missing_(cls, value: object) -> Optional[ProtocolType]:
        if isinstance(value, str):
            clean = value.strip().lower()
            for member in cls:
                if member.value == clean:
                    return member
        return None


class QoSLevel(str, Enum):
    """Quality of Service policy classifications."""
    STANDARD = "standard"
    HIGH_PRIORITY = "high_priority"
    LOW_LATENCY = "low_latency"
    BEST_EFFORT = "best_effort"


class IsolationMode(str, Enum):
    """Network segmentation and isolation mechanisms."""
    NONE = "none"
    VLAN = "vlan"
    VRF = "vrf"
    NAMESPACE = "namespace"


class NodeIntent(BaseModel):
    """Specification of an intended node in the network."""
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(..., description="Unique alphanumeric identifier of the node (e.g. pc1, frr1, srl1)")
    role: str = Field(..., description="Functional role (e.g. 'host', 'router', 'switch', 'leaf', 'spine')")
    device_kind: Optional[str] = Field(default=None, description="Preferred platform kind ('linux', 'frr', 'nokia_srlinux')")
    subnets: List[str] = Field(default_factory=list, description="Subnets directly attached to this node (e.g. ['10.1.1.0/24'])")
    asn: Optional[int] = Field(default=None, description="Autonomous System Number if BGP is used")
    extra_attributes: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary vendor-specific requirements")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Node name cannot be empty")
        return clean


class LinkIntent(BaseModel):
    """Specification of an intended physical or logical link between two nodes."""
    model_config = ConfigDict(populate_by_name=True)

    source_node: str = Field(..., min_length=1, description="Identifier of the source node")
    target_node: str = Field(..., min_length=1, description="Identifier of the target node")
    subnet: Optional[str] = Field(default=None, description="Point-to-point subnet for this link (e.g. '10.1.12.0/24')")
    bandwidth_mbps: Optional[int] = Field(default=None, ge=0, description="Bandwidth constraint in Mbps")
    latency_ms: Optional[float] = Field(default=None, ge=0, description="Maximum latency constraint in ms")

    @field_validator("source_node", "target_node")
    @classmethod
    def validate_node_identifiers(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean:
            raise ValueError("Node identifier cannot be empty or whitespace")
        return clean


class NetworkIntent(BaseModel):
    """Root network intent model capturing complete user specifications."""
    model_config = ConfigDict(populate_by_name=True)

    intent_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8], description="Unique intent tracking ID")
    raw_intent: str = Field(..., description="The original natural language input from the user")
    summary: str = Field(..., description="Distilled one-sentence technical summary of the network intent")
    nodes: List[NodeIntent] = Field(..., description="List of nodes required by this intent")
    links: List[LinkIntent] = Field(default_factory=list, description="List of interconnection links")
    protocols: List[ProtocolType] = Field(default_factory=lambda: [ProtocolType.STATIC], description="Routing protocols enabled")
    qos: QoSLevel = Field(default=QoSLevel.STANDARD, description="QoS profile")
    isolation: IsolationMode = Field(default=IsolationMode.NONE, description="Network isolation mechanism")
    source_endpoints: List[str] = Field(default_factory=list, description="Nodes acting as client/source hosts")
    target_endpoints: List[str] = Field(default_factory=list, description="Nodes acting as destination/server hosts")
    verification_targets: List[str] = Field(default_factory=list, description="End-to-end connectivity verification targets")
    constraints: Dict[str, Any] = Field(default_factory=dict, description="Additional policy constraints")

    @field_validator("protocols", mode="before")
    @classmethod
    def coerce_protocols(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = [v]
        if isinstance(v, (list, tuple, set)):
            return [item.strip().lower() if isinstance(item, str) else item for item in v]
        return v


# =============================================================================
# Milestone 2: Canonical Remediation Intent Taxonomy & Compilation Contracts
# =============================================================================

class IntentAction(str, Enum):
    """Abstract declarative remediation actions."""
    DROP_TRAFFIC = "DROP_TRAFFIC"
    RATE_LIMIT = "RATE_LIMIT"
    REDIRECT_FLOW = "REDIRECT_FLOW"
    RESTORE_ROUTE = "RESTORE_ROUTE"
    CLEAR_FILTER = "CLEAR_FILTER"
    RESET_INTERFACE = "RESET_INTERFACE"

    @classmethod
    def _missing_(cls, value: object) -> Optional[IntentAction]:
        if isinstance(value, str):
            norm = value.strip().upper().replace("-", "_")
            for member in cls:
                if member.value == norm or member.name == norm:
                    return member
        return None


# Alias for spec alignment
IntentActionType = IntentAction


class TargetPlatform(str, Enum):
    """Target execution platform / network OS."""
    LINUX_IPTABLES = "linux_iptables"
    CISCO_ACL = "cisco_acl"
    HUAWEI_VRP = "huawei_vrp"
    LINUX_FRR = "linux_frr"

    @classmethod
    def _missing_(cls, value: object) -> Optional[TargetPlatform]:
        if isinstance(value, str):
            norm = value.strip().lower().replace("-", "_")
            # Exact value match
            for member in cls:
                if member.value == norm or member.name.lower() == norm:
                    return member
            # Fuzzy / common aliases
            if norm in ("iptables", "linux", "linux_tc", "netfilter"):
                return cls.LINUX_IPTABLES
            if norm in ("cisco", "cisco_ios", "cisco_ios_xe", "ios"):
                return cls.CISCO_ACL
            if norm in ("huawei", "vrp", "huawei_vrf"):
                return cls.HUAWEI_VRP
            if norm in ("frr", "frrouting", "vtysh"):
                return cls.LINUX_FRR
        return None


# Alias for spec alignment
PlatformType = TargetPlatform


class RollbackStep(BaseModel):
    """Explicit step required to safely reverse remediation in reverse topological order."""
    model_config = ConfigDict(populate_by_name=True)

    step_number: int = Field(default=1, description="Sequential execution index (1, 2, 3...)")
    command: str = Field(default="", description="Command to execute for rollback")
    description: str = Field(default="", description="Explanation of the rollback action")
    target_platform: Optional[TargetPlatform] = Field(default=None, description="Target platform")
    timeout_sec: float = Field(default=30.0, description="Execution timeout in seconds")

    # Compatibility fields for legacy RollbackStep in remediation
    step_order: Optional[int] = Field(default=None, description="Legacy alias for step_number")
    action: Optional[str] = Field(default="EXEC_COMMAND", description="Legacy action type")
    target_node: Optional[str] = Field(default="", description="Node or container where rollback is executed")
    payload: Optional[str] = Field(default=None, description="Command string or content to restore")

    @model_validator(mode="before")
    @classmethod
    def sync_legacy_fields(cls, data: Any) -> Any:
        if hasattr(data, "__dict__"):
            data = data.__dict__
        if isinstance(data, dict):
            # Sync step_number / step_order
            if "step_order" in data and "step_number" not in data:
                data["step_number"] = data["step_order"]
            elif "step_number" in data and "step_order" not in data:
                data["step_order"] = data["step_number"]
            elif "step_number" not in data and "step_order" not in data:
                data["step_number"] = 1
                data["step_order"] = 1

            # Sync command / payload
            if "payload" in data and not data.get("command"):
                data["command"] = data["payload"]
            elif "command" in data and not data.get("payload"):
                data["payload"] = data["command"]

            # Defaults
            if "action" not in data or data["action"] is None:
                data["action"] = "EXEC_COMMAND"
            if "target_node" not in data or data["target_node"] is None:
                data["target_node"] = ""
            if "description" not in data or data["description"] is None:
                data["description"] = ""
        return data

    @model_validator(mode="after")
    def ensure_synced_after(self) -> RollbackStep:
        if self.step_order is None and self.step_number is not None:
            self.step_order = self.step_number
        elif self.step_number is None and self.step_order is not None:
            self.step_number = self.step_order

        if self.payload is None and self.command:
            self.payload = self.command
        elif not self.command and self.payload:
            self.command = self.payload
        return self


class CanonicalIntent(BaseModel):
    """Abstract declarative remediation intent specification.
    
    Decoupled from underlying vendor syntax.
    """
    model_config = ConfigDict(populate_by_name=True)

    intent_id: str = Field(default_factory=lambda: f"intent-{uuid.uuid4().hex[:8]}", description="Unique intent identifier")
    action: IntentAction = Field(..., description="Abstract remediation action primitive")
    target_node: str = Field(..., description="Target node/container identifier")
    target_platform: TargetPlatform = Field(..., description="Target network OS / platform")
    source_ip: Optional[str] = Field(default=None, description="Source IP address or CIDR subnet")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address or CIDR subnet")
    protocol: Optional[str] = Field(default="tcp", description="L4 protocol (tcp, udp, icmp, ip)")
    source_port: Optional[int] = Field(default=None, description="Source L4 port number")
    destination_port: Optional[int] = Field(default=None, description="Destination L4 port number")
    rate_limit_kbps: Optional[int] = Field(default=None, description="Rate limit in kbps")
    interface: Optional[str] = Field(default=None, description="Target interface (e.g. eth1, GigabitEthernet0/1)")
    next_hop: Optional[str] = Field(default=None, description="Next hop IP address for route operations")
    network_prefix: Optional[str] = Field(default=None, description="Destination CIDR prefix for route operations")
    extra_params: Dict[str, Any] = Field(default_factory=dict, description="Platform-specific or policy parameters")
    description: Optional[str] = Field(default="", description="Human-readable rationale for this intent")

    @model_validator(mode="before")
    @classmethod
    def harmonize_intent_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Interface alias
            if "target_interface" in data and not data.get("interface"):
                data["interface"] = data["target_interface"]
            # Network prefix alias
            if "prefix" in data and not data.get("network_prefix"):
                data["network_prefix"] = data["prefix"]
            # Rate limit alias (Mbps to kbps)
            if "rate_mbps" in data and not data.get("rate_limit_kbps"):
                mbps = data["rate_mbps"]
                if mbps is not None:
                    data["rate_limit_kbps"] = int(float(mbps) * 1000)
            if "rate_limit" in data and not data.get("rate_limit_kbps"):
                val = data["rate_limit"]
                if val is not None:
                    data["rate_limit_kbps"] = int(val)
        return data


# Alias for survey spec alignment
CanonicalRemediationIntent = CanonicalIntent


class CompilationResult(BaseModel):
    """Result of compiling a CanonicalIntent into forward and rollback commands."""
    model_config = ConfigDict(populate_by_name=True)

    intent_id: str = Field(..., description="Associated intent ID")
    target_platform: TargetPlatform = Field(..., description="Target execution platform")
    forward_commands: List[str] = Field(default_factory=list, description="Ordered forward execution commands")
    rollback_commands: List[str] = Field(default_factory=list, description="Ordered rollback commands in reverse topological order")
    rollback_steps: List[RollbackStep] = Field(default_factory=list, description="Structured rollback steps")
    is_safe: bool = Field(default=True, description="Whether all commands passed AAL safety validation")
    validation_error: Optional[str] = Field(default=None, description="Safety or syntax validation error if is_safe is False")
    target_node: Optional[str] = Field(default=None, description="Target node for execution")
    extra_metadata: Dict[str, Any] = Field(default_factory=dict, description="Compilation metadata and statistics")

    def to_remediation_plan(self, target_entity: Optional[str] = None) -> Any:
        """Helper to convert compilation result to RemediationPlan."""
        from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
        target = target_entity or self.target_node or "network_node"
        return RemediationPlan(
            plan_id=f"plan-{self.intent_id}",
            action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
            target_entity=target,
            exec_commands=self.forward_commands,
            rollback_steps=self.rollback_steps,
            expected_outcome=f"Canonical intent {self.intent_id} executed on {self.target_platform.value}",
        )


# Alias for survey spec alignment
CompiledRemediationResult = CompilationResult
