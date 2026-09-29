"""Self-Healing Remediation Plan Contracts."""

from __future__ import annotations
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field
from langgraph_netagent.models.diagnostic import SeverityLevel


class RemediationActionType(str, Enum):
    """Categorized remediation operations."""
    PATCH_CONFIG_FILE = "patch_config_file"
    EXEC_RUNTIME_COMMAND = "exec_runtime_command"
    RELOAD_DAEMON = "reload_daemon"
    RESTART_CONTAINER = "restart_container"
    MODIFY_TOPOLOGY = "modify_topology"
    RECREATE_LINK = "recreate_link"


class ConfigurationPatch(BaseModel):
    """Specification of a patch applied to a node's configuration file."""
    model_config = ConfigDict(populate_by_name=True)

    file_path: str = Field(..., description="Target file path (e.g. 'config/frr/frr.conf')")
    patch_type: str = Field(default="FULL_REPLACE", description="Patch method: 'FULL_REPLACE', 'LINE_INSERT', or 'DIFF'")
    new_content: str = Field(..., description="New configuration content or patch body")
    backup_content: Optional[str] = Field(default=None, description="Original content for rollback")


from langgraph_netagent.models.intent import RollbackStep


class RemediationPlan(BaseModel):
    """Actionable remediation plan produced by the Fault Fixer node."""
    model_config = ConfigDict(populate_by_name=True)

    plan_id: str = Field(default_factory=lambda: f"fix-{uuid.uuid4().hex[:6]}", description="Unique plan ID")
    action_type: RemediationActionType = Field(..., description="Primary remediation action type")
    target_entity: str = Field(..., description="Primary node or component being remediated (e.g. 'frr1')")
    configuration_patch: Optional[ConfigurationPatch] = Field(default=None, description="Config file patch if applicable")
    exec_commands: List[str] = Field(default_factory=list, description="Immediate runtime commands (e.g. vtysh or ip route)")
    rollback_steps: List[RollbackStep] = Field(default_factory=list, description="Ordered rollback operations")
    expected_outcome: str = Field(..., description="Expected observable network state after remediation")
    estimated_risk: SeverityLevel = Field(default=SeverityLevel.LOW, description="Risk assessment of applying the plan")
    requires_human_approval: bool = Field(default=False, description="Flag indicating if human-in-the-loop approval is needed")
