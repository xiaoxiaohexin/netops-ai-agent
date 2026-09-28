"""Containerlab Topology and Node Configuration Contracts.

Defines schemas compatible with Containerlab YAML definitions and device configs.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator
import yaml


class ContainerlabMgmtConfig(BaseModel):
    """Management network configuration in Containerlab."""
    model_config = ConfigDict(populate_by_name=True)

    network: str = Field(default="clab", description="Docker network name for management")
    ipv4_subnet: Optional[str] = Field(default="172.100.100.0/24", alias="ipv4-subnet", description="Management IPv4 subnet CIDR")
    ipv6_subnet: Optional[str] = Field(default=None, alias="ipv6-subnet", description="Management IPv6 subnet CIDR")


class ContainerlabNodeConfig(BaseModel):
    """Node configuration entry in Containerlab topology."""
    model_config = ConfigDict(populate_by_name=True)

    kind: str = Field(..., description="Node kind ('linux', 'nokia_srlinux', 'cisco_xrv', etc.)")
    image: str = Field(..., description="Container image ('alpine:latest', 'frrouting/frr:latest', etc.)")
    binds: List[str] = Field(default_factory=list, description="Host-to-container volume mount mappings")
    exec: List[str] = Field(default_factory=list, description="Post-boot execution commands")
    sysctls: Dict[str, Union[int, str]] = Field(default_factory=dict, description="Kernel sysctl parameters")
    startup_config: Optional[str] = Field(default=None, alias="startup-config", description="Path to startup configuration file")
    env: Dict[str, str] = Field(default_factory=dict, description="Environment variables")
    labels: Dict[str, str] = Field(default_factory=dict, description="Custom metadata labels")


class ContainerlabLinkEndpoint(BaseModel):
    """Inter-node link endpoint pair in Containerlab."""
    model_config = ConfigDict(populate_by_name=True)

    endpoints: List[str] = Field(..., description="List of two endpoints in 'node:interface' format")

    @field_validator("endpoints")
    @classmethod
    def validate_endpoints_pair(cls, v: List[str]) -> List[str]:
        if len(v) != 2:
            raise ValueError(f"Link must connect exactly 2 endpoints, got {len(v)}: {v}")
        endpoint_pattern = re.compile(r"^[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\.\-]+$")
        for ep in v:
            if not endpoint_pattern.match(ep):
                raise ValueError(f"Endpoint '{ep}' does not match required format '<node>:<interface>' (e.g. 'pc1:eth1')")
        return v


class ContainerlabTopologyDefinition(BaseModel):
    """Inner topology dictionary holding nodes and links."""
    model_config = ConfigDict(populate_by_name=True)

    nodes: Dict[str, ContainerlabNodeConfig] = Field(..., description="Dictionary of node definitions keyed by node name")
    links: List[ContainerlabLinkEndpoint] = Field(default_factory=list, description="List of link endpoint connections")


class ContainerlabTopologyFile(BaseModel):
    """Complete root Containerlab topology YAML file schema."""
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(..., min_length=1, description="Lab topology name identifier")
    mgmt: Optional[ContainerlabMgmtConfig] = Field(default=None, description="Management network settings")
    topology: ContainerlabTopologyDefinition = Field(..., description="Topology nodes and links")

    @field_validator("name")
    @classmethod
    def validate_topology_name(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Topology name cannot be empty or whitespace")
        return clean

    def to_yaml(self) -> str:
        """Serialize topology object to clean Containerlab-compliant YAML string."""
        dumped_dict = self.model_dump(by_alias=True, exclude_none=True)
        return yaml.safe_dump(dumped_dict, sort_keys=False, default_flow_style=False)

    @classmethod
    def from_yaml(cls, yaml_content: str) -> ContainerlabTopologyFile:
        """Parse and validate topology object from YAML string."""
        raw_dict = yaml.safe_load(yaml_content)
        if not isinstance(raw_dict, dict):
            raise ValueError("YAML content must resolve to a dictionary")
        return cls.model_validate(raw_dict)


class DeviceConfigFile(BaseModel):
    """A generated device configuration file to be written to disk."""
    model_config = ConfigDict(populate_by_name=True)

    node_name: str = Field(..., description="Node that consumes this config file")
    file_path: str = Field(..., description="Relative destination path (e.g. 'config/frr/frr.conf')")
    content: str = Field(..., description="Raw text content of the configuration file")
    permissions: str = Field(
        default="0644",
        pattern=r"^[0-7]{3,4}$",
        description="File permissions in octal (e.g. '0755' for setup.sh)",
    )
    description: Optional[str] = Field(default=None, description="Purpose of this configuration file")

    @field_validator("permissions", mode="before")
    @classmethod
    def strip_permissions(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.strip()
        return v


class IPAllocation(BaseModel):
    """Detailed IP allocation record for verification and telemetry."""
    model_config = ConfigDict(populate_by_name=True)

    node_name: str = Field(..., description="Node name")
    interface_name: str = Field(..., description="Interface name (e.g. eth1)")
    ipv4_address: str = Field(..., description="Assigned IPv4 address with prefix (e.g. '10.1.1.2/24')")
    gateway_ipv4: Optional[str] = Field(default=None, description="Default gateway IPv4 if applicable")
    peer_node: Optional[str] = Field(default=None, description="Connected peer node name")
    peer_interface: Optional[str] = Field(default=None, description="Connected peer interface name")

    @field_validator("ipv4_address")
    @classmethod
    def validate_ipv4_address(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("ipv4_address cannot be empty")
        try:
            ipaddress.IPv4Interface(clean)
        except Exception as exc:
            raise ValueError(f"Invalid IPv4 address or CIDR notation '{v}': {exc}") from exc
        return clean

    @field_validator("gateway_ipv4")
    @classmethod
    def validate_gateway_ipv4(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            return None
        try:
            ipaddress.IPv4Address(clean)
        except Exception as exc:
            raise ValueError(f"Invalid gateway IPv4 address '{v}': {exc}") from exc
        return clean


class FullTopologyPackage(BaseModel):
    """Bundled topology package ready for pre-flight validation and disk export."""
    model_config = ConfigDict(populate_by_name=True)

    topology: ContainerlabTopologyFile = Field(..., description="Containerlab topology structure")
    configs: List[DeviceConfigFile] = Field(default_factory=list, description="Startup config files for all nodes")
    ip_allocations: List[IPAllocation] = Field(default_factory=list, description="Interface IP allocation map")
