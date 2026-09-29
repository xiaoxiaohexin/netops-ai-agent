"""Vendor Knowledge and Hierarchical Dual-Retrieval Pydantic Data Models.

Defines the data structures for:
1. Tree-structured authoritative command database (TreeNode)
2. Lightweight vector index records (VectorIndexEntry)
3. Dual-retrieval results returned to diagnostic reasoning engines (DualRetrievalResult)
4. Vendor documentation source descriptors (VendorDocSource)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator


class TreeNode(BaseModel):
    """Hierarchical command syntax tree node.

    Represents either an internal routing/category node or an authoritative
    leaf node holding exact CLI syntax templates, inverse rollback templates,
    and parameter schemas.
    """
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    path: str = Field(
        default="",
        description="Hierarchical tree path string, e.g. 'cisco/ios/acl_security/drop_traffic'",
    )
    vendor: str = Field(
        default="",
        description="Target vendor identifier, e.g. 'cisco', 'huawei', 'frr', 'linux'",
    )
    platform: str = Field(
        default="",
        description="Platform / OS release, e.g. 'ios', 'vrp', 'vtysh', 'iptables', 'tc'",
    )
    domain: str = Field(
        default="",
        description="Operational domain / category, e.g. 'routing', 'acl_security', 'qos_policing'",
    )
    action: str = Field(
        default="",
        description="Specific action name, e.g. 'drop_traffic', 'static_route', 'rate_limit'",
    )
    command_template: str = Field(
        default="",
        description="Exact CLI syntax template with {parameter} placeholders",
    )
    rollback_template: str = Field(
        default="",
        description="Exact inverse CLI rollback template",
    )
    parameters: List[str] = Field(
        default_factory=list,
        description="List of required parameter placeholder names",
    )
    description: str = Field(
        default="",
        description="Technical description and operational intent of this command template",
    )
    is_leaf: bool = Field(
        default=True,
        description="True if this node contains actionable command templates, False if directory node",
    )
    children: Dict[str, Any] = Field(
        default_factory=dict,
        description="Child nodes keyed by component identifier",
    )
    mode: str = Field(
        default="config",
        description="CLI execution context/mode: 'exec', 'config', 'system-view', 'vtysh'",
    )

    @model_validator(mode="before")
    @classmethod
    def sync_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync tree_path alias
            if "tree_path" in data and not data.get("path"):
                data["path"] = data["tree_path"]
            elif "path" in data and not data.get("tree_path"):
                data["tree_path"] = data["path"]

            # Sync category / domain alias
            if "category" in data and not data.get("domain"):
                data["domain"] = data["category"]
            elif "domain" in data and not data.get("category"):
                data["category"] = data["domain"]

            # If path is not set, derive from vendor/platform/domain/action
            if not data.get("path") and data.get("vendor") and data.get("action"):
                parts = [
                    str(data.get("vendor", "")).strip().lower(),
                    str(data.get("platform", "")).strip().lower(),
                    str(data.get("domain", "")).strip().lower(),
                    str(data.get("action", "")).strip().lower(),
                ]
                data["path"] = "/".join(p for p in parts if p)
        return data

    @property
    def tree_path(self) -> str:
        """Alias for path for interface consistency."""
        return self.path

    @property
    def category(self) -> str:
        """Alias for domain for interface consistency."""
        return self.domain

    @property
    def command_templates(self) -> List[str]:
        """List representation of command templates."""
        return [self.command_template] if self.command_template else []

    @property
    def rollback_templates(self) -> List[str]:
        """List representation of rollback templates."""
        return [self.rollback_template] if self.rollback_template else []

    def add_child(self, child: TreeNode) -> None:
        """Add a child node to this node's children dictionary."""
        key = child.action or child.domain or child.platform or child.vendor or child.path
        self.children[key] = child
        self.is_leaf = False

    def get_child(self, key: str) -> Optional[TreeNode]:
        """Retrieve a direct child node by key."""
        child = self.children.get(key)
        if isinstance(child, dict):
            return TreeNode.model_validate(child)
        return child


class VectorIndexEntry(BaseModel):
    """Lean vector index record containing only semantic pointers.

    Stores scene and intent descriptions pointing to tree paths, preventing
    prompt bloat by omitting heavy syntax templates from the vector store.
    """
    model_config = ConfigDict(populate_by_name=True)

    entry_id: str = Field(
        ...,
        description="Unique entry identifier, e.g. 'vec-cisco-acl-01'",
    )
    tree_path: str = Field(
        ...,
        description="Authoritative tree path pointer into CommandTreeStore",
    )
    vendor: str = Field(
        ...,
        description="Vendor filter tag: 'cisco', 'huawei', 'frr', 'linux'",
    )
    intent: str = Field(
        ...,
        description="Normalized canonical intent, e.g. 'DROP_TRAFFIC', 'RESTORE_ROUTE', 'RATE_LIMIT'",
    )
    scene_description: str = Field(
        ...,
        description="Natural language description of operational scenario or diagnostic symptom",
    )
    symptom_keywords: List[str] = Field(
        default_factory=list,
        description="Keywords for hybrid lexical / term-overlap matching",
    )
    embedding: Optional[List[float]] = Field(
        default=None,
        description="Optional dense embedding vector for semantic cosine similarity",
    )

    @model_validator(mode="before")
    @classmethod
    def sync_intent_alias(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "canonical_intent" in data and not data.get("intent"):
                data["intent"] = data["canonical_intent"]
            elif "intent" in data and not data.get("canonical_intent"):
                data["canonical_intent"] = data["intent"]
        return data

    @property
    def canonical_intent(self) -> str:
        """Alias for intent."""
        return self.intent


class DualRetrievalResult(BaseModel):
    """Result returned by the dual-retrieval pipeline.

    Coordinates vector similarity search with hierarchical tree dereferencing
    to provide the exact authoritative command template and rollback sequence.
    """
    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)

    tree_path: str = Field(
        ...,
        description="Authoritative tree path of retrieved template",
    )
    vendor: str = Field(
        ...,
        description="Target vendor identifier",
    )
    command_template: str = Field(
        ...,
        description="Authoritative CLI remediation command template",
    )
    rollback_template: str = Field(
        ...,
        description="Exact inverse rollback command template",
    )
    parameters: List[str] = Field(
        default_factory=list,
        description="List of required parameters for template substitution",
    )
    score: float = Field(
        default=0.0,
        description="Relevance / similarity confidence score (0.0 - 1.0)",
    )
    matched_intent: str = Field(
        default="",
        description="Matched canonical intent or scene descriptor",
    )
    category: str = Field(
        default="",
        description="Operational category / domain",
    )
    action: str = Field(
        default="",
        description="Operational action identifier",
    )
    retrieval_method: str = Field(
        default="dual_vector_tree",
        description="Method used for retrieval",
    )

    @model_validator(mode="before")
    @classmethod
    def sync_confidence_score(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "confidence_score" in data and "score" not in data:
                data["score"] = float(data["confidence_score"])
            elif "score" in data and "confidence_score" not in data:
                data["confidence_score"] = float(data["score"])
        return data

    @property
    def confidence_score(self) -> float:
        """Alias for score."""
        return self.score

    @property
    def remediation_template(self) -> List[str]:
        """List of remediation command lines."""
        if not self.command_template:
            return []
        return [line.strip() for line in self.command_template.split("\n") if line.strip()]

    @property
    def rollback_templates(self) -> List[str]:
        """List of rollback command lines."""
        if not self.rollback_template:
            return []
        return [line.strip() for line in self.rollback_template.split("\n") if line.strip()]


class VendorDocSource(BaseModel):
    """Metadata descriptor for ingested vendor documentation."""
    model_config = ConfigDict(populate_by_name=True)

    vendor: str = Field(
        ...,
        description="Vendor identifier: 'cisco', 'huawei', 'frr', 'linux'",
    )
    title: str = Field(
        ...,
        description="Document or playbook title",
    )
    source_type: str = Field(
        default="playbook",
        description="Type of source: 'playbook', 'cli_reference', 'kb_article', 'rfc'",
    )
    version: str = Field(
        default="1.0",
        description="Vendor software / documentation version",
    )
    doc_path: Optional[str] = Field(
        default=None,
        description="File path or URI to the source documentation",
    )
    raw_content: Optional[str] = Field(
        default=None,
        description="Optional raw content snippet or full document body",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional vendor metadata attributes",
    )
