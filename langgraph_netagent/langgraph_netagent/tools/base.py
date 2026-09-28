"""Abstract Base Classes and Data Contracts for Containerlab Adapters."""

from __future__ import annotations
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class CommandResult(BaseModel):
    """Result of executing a command inside a network node container."""
    model_config = ConfigDict(populate_by_name=True)

    command: str = Field(..., description="Executed command string")
    exit_code: int = Field(..., description="Process exit code (0 for success)")
    stdout: str = Field(default="", description="Captured standard output")
    stderr: str = Field(default="", description="Captured standard error")
    node: Optional[str] = Field(default=None, description="Target container node name")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Execution duration in seconds")

    @property
    def success(self) -> bool:
        """True if command executed with returncode 0."""
        return self.exit_code == 0


class DeploymentResult(BaseModel):
    """Result of a Containerlab deployment operation."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool = Field(..., description="True if deployment succeeded")
    lab_name: str = Field(..., description="Name of the deployed lab topology")
    topo_file: str = Field(..., description="Path to the topology YAML file")
    nodes_deployed: List[str] = Field(default_factory=list, description="Names of deployed container nodes")
    raw_output: str = Field(default="", description="CLI deployment log output")
    error_message: Optional[str] = Field(default=None, description="Error explanation if deployment failed")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Deployment elapsed time in seconds")


class DestructionResult(BaseModel):
    """Result of a Containerlab destruction/cleanup operation."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool = Field(..., description="True if lab was destroyed cleanly")
    lab_name: str = Field(..., description="Name of the destroyed lab topology")
    raw_output: str = Field(default="", description="CLI destroy log output")
    error_message: Optional[str] = Field(default=None, description="Error explanation if destroy failed")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Destroy elapsed time in seconds")


class LabNodeState(BaseModel):
    """Observed runtime state of a single node in a deployed lab."""
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(..., description="Node name in topology")
    container_id: str = Field(default="", description="Container ID or Docker name")
    image: str = Field(default="", description="Container image")
    kind: str = Field(default="", description="Containerlab node kind (e.g. linux, nokia_srlinux)")
    state: str = Field(default="running", description="Container status: running, exited, etc.")
    ipv4_address: Optional[str] = Field(default=None, description="Management IPv4 address")
    ipv6_address: Optional[str] = Field(default=None, description="Management IPv6 address")


class LabInspectionResult(BaseModel):
    """Result of inspecting a deployed Containerlab topology."""
    model_config = ConfigDict(populate_by_name=True)

    success: bool = Field(..., description="True if inspect completed successfully")
    lab_name: str = Field(..., description="Name of inspected lab")
    nodes: List[LabNodeState] = Field(default_factory=list, description="States of all detected nodes")
    raw_output: str = Field(default="", description="Raw inspect output from clab CLI")
    error_message: Optional[str] = Field(default=None, description="Error explanation if inspect failed")


class BaseNetworkLabAdapter(ABC):
    """Abstract interface defining operations for Containerlab environments.
    
    Both LiveContainerlabAdapter (executing against real Docker/WSL/clab) and
    MockContainerlabAdapter (in-memory virtual simulation) implement this contract.
    """

    @abstractmethod
    def deploy(
        self,
        topo_file: Union[str, Path],
        reconfigure: bool = True,
    ) -> DeploymentResult:
        """Deploy a Containerlab topology file.
        
        Args:
            topo_file: Path to the .clab.yml file.
            reconfigure: If True, apply --reconfigure flag.
            
        Returns:
            DeploymentResult with success status and deployed node list.
        """
        raise NotImplementedError

    @abstractmethod
    def destroy(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
        cleanup: bool = True,
    ) -> DestructionResult:
        """Destroy a running Containerlab topology.
        
        Args:
            topo_file: Optional path to the topology file.
            lab_name: Optional lab name if topo_file not provided.
            cleanup: If True, remove lab directory and network artifacts.
            
        Returns:
            DestructionResult with success status.
        """
        raise NotImplementedError

    @abstractmethod
    def inspect(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
    ) -> LabInspectionResult:
        """Inspect the current runtime state of containers in the lab.
        
        Args:
            topo_file: Optional path to the topology file.
            lab_name: Optional lab name.
            
        Returns:
            LabInspectionResult containing container states.
        """
        raise NotImplementedError

    @abstractmethod
    def exec_command(
        self,
        node_name: str,
        command: str,
        timeout: int = 15,
    ) -> CommandResult:
        """Execute a command inside a specific container node.
        
        Args:
            node_name: Target node identifier (e.g. 'pc1', 'frr1').
            command: Command string to execute (e.g. 'ping -c 3 10.2.2.2').
            timeout: Maximum execution timeout in seconds.
            
        Returns:
            CommandResult with exit code, stdout, and stderr.
        """
        raise NotImplementedError

    @abstractmethod
    def is_live_ready(self) -> bool:
        """Check whether the underlying environment is capable of live Containerlab execution.
        
        Returns:
            True if live Docker/clab environment is functional, False otherwise.
        """
        raise NotImplementedError

    def get_topology_summary(self) -> str:
        """Return a structured human-readable and LLM-friendly summary of the current network topology."""
        return ""
