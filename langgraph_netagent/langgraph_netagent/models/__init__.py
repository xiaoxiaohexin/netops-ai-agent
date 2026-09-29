"""Pydantic v2 data models for LangGraph NetAgent."""

from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CanonicalRemediationIntent,
    CompilationResult,
    CompiledRemediationResult,
    IntentAction,
    IntentActionType,
    IsolationMode,
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    PlatformType,
    ProtocolType,
    QoSLevel,
    RollbackStep,
    TargetPlatform,
)
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.models.validation import (
    ValidationErrorDetail,
    ValidationResult,
    ValidationSeverity,
)
from langgraph_netagent.models.diagnostic import (
    DiagnosticReport,
    ErrorCategory,
    SeverityLevel,
)
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.models.telemetry import (
    InterfaceTelemetry,
    NetworkHealthReport,
    PingTelemetry,
    RouteEntry,
    RouteTableTelemetry,
)
from langgraph_netagent.models.operational import (
    AALResponse,
    AALToolCall,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.sandbox import (
    GCReport,
    PreflightSandboxPassReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.models.knowledge import (
    DualRetrievalResult,
    TreeNode,
    VectorIndexEntry,
    VendorDocSource,
)

__all__ = [
    "ProtocolType",
    "QoSLevel",
    "IsolationMode",
    "NodeIntent",
    "LinkIntent",
    "NetworkIntent",
    # Milestone 2 Intent Models
    "IntentAction",
    "IntentActionType",
    "TargetPlatform",
    "PlatformType",
    "CanonicalIntent",
    "CanonicalRemediationIntent",
    "RollbackStep",
    "CompilationResult",
    "CompiledRemediationResult",
    # Topology
    "ContainerlabMgmtConfig",
    "ContainerlabNodeConfig",
    "ContainerlabLinkEndpoint",
    "ContainerlabTopologyDefinition",
    "ContainerlabTopologyFile",
    "DeviceConfigFile",
    "IPAllocation",
    "FullTopologyPackage",
    # Validation & Diagnostic
    "ValidationSeverity",
    "ValidationErrorDetail",
    "ValidationResult",
    "ErrorCategory",
    "SeverityLevel",
    "DiagnosticReport",
    # Remediation
    "RemediationActionType",
    "ConfigurationPatch",
    "RemediationPlan",
    # Telemetry
    "PingTelemetry",
    "RouteEntry",
    "RouteTableTelemetry",
    "InterfaceTelemetry",
    "NetworkHealthReport",
    # Operational
    "FiveTuple",
    "InventoryPool",
    "NetworkDiscrepancy",
    "AALToolCall",
    "AALResponse",
    "ShadowSandboxResult",
    # Sandbox
    "ResourceQuota",
    "SandboxExecutionResult",
    "GCReport",
    "PreflightSandboxPassReport",
    # Knowledge & Dual-Retrieval
    "TreeNode",
    "VectorIndexEntry",
    "DualRetrievalResult",
    "VendorDocSource",
]
