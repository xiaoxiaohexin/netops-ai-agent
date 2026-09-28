"""Telemetry Diagnostic Report Contracts."""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class ErrorCategory(str, Enum):
    """Classification of root-cause network and system failure domains."""
    ROUTING_MISCONFIG = "routing_misconfig"
    INTERFACE_DOWN = "interface_down"
    IP_SUBNET_MISMATCH = "ip_subnet_mismatch"
    GATEWAY_UNREACHABLE = "gateway_unreachable"
    CONTAINER_CRASH = "container_crash"
    CONFIG_SYNTAX_ERROR = "config_syntax_error"
    FIREWALL_FILTER_DROP = "firewall_filter_drop"
    ARP_RESOLUTION_FAIL = "arp_resolution_fail"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    """Incident severity classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DiagnosticReport(BaseModel):
    """Structured report produced by the Diagnostic Node after probe failure."""
    model_config = ConfigDict(populate_by_name=True)

    report_id: str = Field(default_factory=lambda: f"diag-{uuid.uuid4().hex[:6]}", description="Diagnostic report ID")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat(), description="UTC timestamp")
    telemetry_trigger: str = Field(..., description="Probe result that triggered diagnosis (e.g. 'Ping 10.2.2.2 100% loss')")
    root_cause: str = Field(..., description="Root technical cause of the failure")
    affected_nodes: List[str] = Field(..., description="List of nodes contributing to or impacted by the fault")
    error_category: ErrorCategory = Field(..., description="Categorized fault domain")
    severity: SeverityLevel = Field(default=SeverityLevel.HIGH, description="Incident severity level")
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score of the diagnosis (0.0 to 1.0)")
    evidence: List[str] = Field(default_factory=list, description="Telemetry logs and command outputs supporting the diagnosis")
    details: Dict[str, Any] = Field(default_factory=dict, description="Structured diagnostics context")
