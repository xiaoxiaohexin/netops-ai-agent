"""Network Intent Pydantic Data Contracts.

Defines the structured representation of user requirements parsed from natural language.
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field, field_validator


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
