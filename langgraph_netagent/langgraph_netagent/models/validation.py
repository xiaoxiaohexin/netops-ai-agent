"""Pre-flight Validation Result Contracts."""

from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ValidationSeverity(str, Enum):
    """Severity levels for pre-flight validation findings."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationErrorDetail(BaseModel):
    """Itemized pre-flight error or warning."""
    model_config = ConfigDict(populate_by_name=True)

    code: str = Field(..., description="Machine-readable error code (e.g. 'IP_OVERLAP', 'UNKNOWN_NODE_IN_LINK')")
    message: str = Field(..., description="Human-readable description of the validation issue")
    node: Optional[str] = Field(default=None, description="Affected node name")
    field: Optional[str] = Field(default=None, description="Schema field or file path involved")
    severity: ValidationSeverity = Field(default=ValidationSeverity.ERROR, description="Error severity level")
    suggested_fix: Optional[str] = Field(default=None, description="Actionable recommendation to resolve the error")


class ValidationResult(BaseModel):
    """Aggregated output of syntax, compliance, and semantic validation checks."""
    model_config = ConfigDict(populate_by_name=True)

    is_valid: bool = Field(..., description="True if no ERROR or CRITICAL violations exist")
    validator_name: str = Field(..., description="Name of validator engine ('offline_syntax_validator', 'clab_linter')")
    errors: List[ValidationErrorDetail] = Field(default_factory=list, description="List of blocking validation errors")
    warnings: List[ValidationErrorDetail] = Field(default_factory=list, description="List of non-blocking warnings")
    summary: str = Field(..., description="High-level validation summary statement")
    checked_items_count: int = Field(default=0, description="Total number of nodes, links, and configs validated")
