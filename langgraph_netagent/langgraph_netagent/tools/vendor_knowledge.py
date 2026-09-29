"""Vendor Documentation Ingestion & Hierarchical Dual-Retrieval Subsystem.

Provides:
1. CommandTreeStore: Hierarchical tree storage (vendor/platform/domain/action)
   indexing authoritative templates for Cisco, Huawei, Linux FRR, Linux host.
2. LightweightVectorIndex: In-process vector embedding & cosine similarity index
   with TF-IDF / term-overlap fallback for deterministic zero-dependency offline execution.
   Stores only scene/intent descriptions pointing to tree paths to prevent prompt bloat.
3. VendorDocIngestor: Ingests vendor documentation records, builds both tree store
   nodes and vector entries. Pre-populates authoritative vendor playbooks.
4. DualRetrievalEngine: Coordinates vector search -> tree path resolution -> exact
   template retrieval (<500B syntax injection).
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from langgraph_netagent.models.knowledge import (
    DualRetrievalResult,
    TreeNode,
    VectorIndexEntry,
    VendorDocSource,
)


# =============================================================================
# 1. CommandTreeStore: Hierarchical Command Syntax Storage
# =============================================================================

class CommandTreeStore:
    """Hierarchical tree-structured command database.

    Stores authoritative CLI syntax templates, inverse rollback templates,
    and parameter schemas indexed by `vendor/platform/domain/action`.
    """

    def __init__(self, root: Optional[TreeNode] = None) -> None:
        self.root: TreeNode = root or TreeNode(
            path="root",
            vendor="root",
            platform="root",
            domain="root",
            action="root",
            is_leaf=False,
            description="Root of command syntax tree",
        )
        self._index: Dict[str, TreeNode] = {}
        if root:
            self._rebuild_index(self.root)

    def _rebuild_index(self, node: TreeNode) -> None:
        if node.is_leaf and node.path and node.path != "root":
            self._index[self._normalize_path(node.path)] = node
        for child in node.children.values():
            if isinstance(child, TreeNode):
                self._rebuild_index(child)
            elif isinstance(child, dict):
                self._rebuild_index(TreeNode.model_validate(child))

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize tree path string to lowercase stripped slash-separated tokens."""
        clean = path.strip().lower().replace("\\", "/")
        parts = [p for p in clean.split("/") if p]
        return "/".join(parts)

    def insert(self, node: TreeNode) -> None:
        """Insert an authoritative command node into the tree hierarchy and fast index.

        Args:
            node: TreeNode containing command syntax and parameters.
        """
        if not node.path:
            parts = [
                node.vendor.strip().lower(),
                node.platform.strip().lower(),
                node.domain.strip().lower(),
                node.action.strip().lower(),
            ]
            node.path = "/".join(p for p in parts if p)

        norm_path = self._normalize_path(node.path)
        node.path = norm_path
        self._index[norm_path] = node

        # Traverse or create intermediate hierarchy nodes
        components = norm_path.split("/")
        curr = self.root
        accumulated_parts: List[str] = []

        for i, comp in enumerate(components[:-1]):
            accumulated_parts.append(comp)
            subpath = "/".join(accumulated_parts)
            if comp not in curr.children:
                curr.children[comp] = TreeNode(
                    path=subpath,
                    vendor=components[0] if i >= 0 else "",
                    platform=components[1] if i >= 1 else "",
                    domain=components[2] if i >= 2 else "",
                    action=comp,
                    is_leaf=False,
                    description=f"Intermediate branch node for {subpath}",
                )
                curr.is_leaf = False

            child = curr.children[comp]
            if isinstance(child, dict):
                child = TreeNode.model_validate(child)
                curr.children[comp] = child
            curr = child

        # Set leaf node at the terminal component
        leaf_key = components[-1]
        node.is_leaf = True
        curr.children[leaf_key] = node
        curr.is_leaf = False

    def get(self, path: str) -> Optional[TreeNode]:
        """Fetch a TreeNode by its hierarchical tree path in O(1) time.

        Args:
            path: Tree path string, e.g. 'cisco/ios/acl_security/drop_traffic'.

        Returns:
            TreeNode if found, None otherwise.
        """
        norm_path = self._normalize_path(path)
        if norm_path in self._index:
            return self._index[norm_path]

        # Fallback to hierarchical traversal
        components = norm_path.split("/")
        curr = self.root
        for comp in components:
            if not curr.children or comp not in curr.children:
                return None
            child = curr.children[comp]
            if isinstance(child, dict):
                child = TreeNode.model_validate(child)
                curr.children[comp] = child
            curr = child
        return curr

    def get_node(self, path: str) -> Optional[TreeNode]:
        """Alias for get(path)."""
        return self.get(path)

    def find(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        domain: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[TreeNode]:
        """Search and filter authoritative leaf nodes matching criteria.

        Args:
            vendor: Filter by vendor, e.g. 'cisco'.
            platform: Filter by platform, e.g. 'ios'.
            domain: Filter by domain/category, e.g. 'routing'.
            action: Filter by action, e.g. 'static_route'.

        Returns:
            List of matching leaf TreeNode instances.
        """
        matches: List[TreeNode] = []
        v_clean = vendor.strip().lower() if vendor else None
        p_clean = platform.strip().lower() if platform else None
        d_clean = domain.strip().lower() if domain else None
        a_clean = action.strip().lower() if action else None

        for node in self._index.values():
            if not node.is_leaf:
                continue
            if v_clean and node.vendor.strip().lower() != v_clean:
                continue
            if p_clean and node.platform.strip().lower() != p_clean:
                continue
            if d_clean and node.domain.strip().lower() != d_clean:
                continue
            if a_clean and node.action.strip().lower() != a_clean:
                continue
            matches.append(node)

        return matches

    def find_nodes(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        domain: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[TreeNode]:
        """Alias for find(...)."""
        return self.find(vendor=vendor, platform=platform, domain=domain, action=action)

    def find_nodes_by_action(self, action: str, vendor: Optional[str] = None) -> List[TreeNode]:
        """Convenience method to find nodes matching an action name."""
        return self.find(vendor=vendor, action=action)

    def list_paths(self) -> List[str]:
        """Return sorted list of all registered leaf tree paths."""
        return sorted(self._index.keys())

    def count(self) -> int:
        """Return total number of registered leaf nodes."""
        return len(self._index)

    def all_nodes(self) -> List[TreeNode]:
        """Return all registered leaf nodes."""
        return list(self._index.values())

    def clear(self) -> None:
        """Clear all registered nodes."""
        self._index.clear()
        self.root = TreeNode(
            path="root",
            vendor="root",
            platform="root",
            domain="root",
            action="root",
            is_leaf=False,
            description="Root of command syntax tree",
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize complete tree structure to dictionary."""
        return self.root.model_dump()

    @classmethod
    def build_default_tree(cls) -> CommandTreeStore:
        """Construct a new CommandTreeStore populated with default vendor templates."""
        ingestor = VendorDocIngestor()
        tree_store, _ = ingestor.build_default_stores()
        return tree_store


# =============================================================================
# 2. LightweightVectorIndex: In-Process Semantic & Term Overlap Index
# =============================================================================

class LightweightVectorIndex:
    """In-process vector embedding & cosine similarity index.

    Employs an in-process normalized vector representation with sublinear TF-IDF
    and term-overlap fallback for deterministic zero-dependency offline execution.
    Stores only scene and intent descriptions pointing to tree paths, completely
    preventing LLM prompt context bloat.
    """

    STOPWORDS: Set[str] = {
        "a", "an", "the", "in", "on", "at", "for", "to", "of", "and", "or",
        "is", "are", "was", "were", "be", "been", "with", "as", "by", "that",
        "this", "it", "from", "into", "through", "after", "over", "under",
    }

    def __init__(self) -> None:
        self._entries: Dict[str, VectorIndexEntry] = {}
        self._doc_tokens: Dict[str, List[str]] = {}
        self._doc_freq: Dict[str, int] = {}
        self._total_docs: int = 0

    @classmethod
    def _tokenize(cls, text: str) -> List[str]:
        """Tokenize string into lowercase alphanumeric words and subword tokens."""
        clean = text.lower().replace("-", " ").replace("_", " ").replace("/", " ")
        words = re.findall(r"[a-z0-9]+", clean)
        tokens = [w for w in words if len(w) > 1 and w not in cls.STOPWORDS]
        # Generate 3-gram character subwords for short technical keywords (e.g. 'acl', 'tcp')
        extra_tokens: List[str] = []
        for w in words:
            if len(w) >= 3:
                for i in range(len(w) - 2):
                    extra_tokens.append(w[i:i + 3])
        return tokens + extra_tokens

    def add_entry(self, entry: VectorIndexEntry) -> None:
        """Add a lean semantic pointer record to the vector index.

        Args:
            entry: VectorIndexEntry with scene description and tree path.
        """
        self._entries[entry.entry_id] = entry
        combined_text = (
            f"{entry.intent} {entry.scene_description} "
            f"{' '.join(entry.symptom_keywords)} {entry.vendor} {entry.tree_path}"
        )
        tokens = self._tokenize(combined_text)
        self._doc_tokens[entry.entry_id] = tokens

        # Update document frequency counts
        unique_tokens = set(tokens)
        for token in unique_tokens:
            self._doc_freq[token] = self._doc_freq.get(token, 0) + 1
        self._total_docs = len(self._entries)

    def _compute_tfidf_vector(self, tokens: List[str]) -> Dict[str, float]:
        """Compute sublinear TF-IDF weighted vector normalized to unit length."""
        if not tokens:
            return {}
        term_counts: Dict[str, int] = {}
        for t in tokens:
            term_counts[t] = term_counts.get(t, 0) + 1

        vec: Dict[str, float] = {}
        n_docs = max(self._total_docs, 1)

        for term, count in term_counts.items():
            tf = 1.0 + math.log(count)
            df = self._doc_freq.get(term, 1)
            idf = math.log(1.0 + (n_docs + 1.0) / (df + 1.0)) + 1.0
            vec[term] = tf * idf

        norm = math.sqrt(sum(v * v for v in vec.values()))
        if norm > 0:
            return {k: v / norm for k, v in vec.items()}
        return vec

    @staticmethod
    def _cosine_similarity_dense(v1: List[float], v2: List[float]) -> float:
        """Calculate cosine similarity between two dense float vectors."""
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = math.sqrt(sum(a * a for a in v1))
        norm2 = math.sqrt(sum(b * b for b in v2))
        if norm1 <= 0 or norm2 <= 0:
            return 0.0
        return max(0.0, min(1.0, dot / (norm1 * norm2)))

    def search(
        self,
        query: str,
        top_k: int = 3,
        vendor: Optional[str] = None,
        threshold: float = 0.0,
    ) -> List[Tuple[VectorIndexEntry, float]]:
        """Search vector index for entries matching query text and optional vendor filter.

        Args:
            query: Diagnostic symptoms, intent, or keywords.
            top_k: Maximum number of entries to return.
            vendor: Optional vendor filter ('cisco', 'huawei', 'frr', 'linux').
            threshold: Minimum similarity score cutoff.

        Returns:
            List of (VectorIndexEntry, score) tuples sorted descending by score.
        """
        if not self._entries or not query.strip():
            return []

        q_tokens = self._tokenize(query)
        q_vec = self._compute_tfidf_vector(q_tokens)
        q_words = {w.lower() for w in re.findall(r"[a-z0-9]+", query.lower())}

        v_filter = vendor.strip().lower() if vendor else None
        scored_results: List[Tuple[VectorIndexEntry, float]] = []

        for entry_id, entry in self._entries.items():
            # Apply vendor filter if specified
            if v_filter:
                entry_vendor = entry.vendor.strip().lower()
                # Also treat 'iptables'/'tc'/'iproute2' as linux
                if v_filter == "linux" and entry_vendor not in ("linux", "iptables", "tc", "iproute2"):
                    continue
                elif v_filter != "linux" and entry_vendor != v_filter:
                    continue

            # Dense embedding cosine similarity if precomputed embedding exists
            doc_vec = self._compute_tfidf_vector(self._doc_tokens.get(entry_id, []))
            # Dot product of normalized sparse vectors
            sparse_score = sum(val * doc_vec.get(term, 0.0) for term, val in q_vec.items())

            # Keyword & intent overlap bonus
            bonus = 0.0
            entry_kws = {k.lower() for k in entry.symptom_keywords}
            entry_intent = entry.intent.lower().replace("_", " ")

            kw_overlap = len(q_words.intersection(entry_kws))
            if kw_overlap > 0:
                bonus += min(0.35, kw_overlap * 0.12)

            # Intent direct match bonus
            for word in q_words:
                if len(word) >= 3 and word in entry_intent:
                    bonus += 0.15
                    break

            # Exact vendor match bonus when vendor keyword appears in query
            if entry.vendor.lower() in q_words:
                bonus += 0.10

            final_score = min(1.0, sparse_score + bonus)
            if final_score >= threshold:
                scored_results.append((entry, final_score))

        # Sort descending by score
        scored_results.sort(key=lambda x: x[1], reverse=True)
        return scored_results[:top_k]

    def get_entry(self, entry_id: str) -> Optional[VectorIndexEntry]:
        """Fetch entry by entry_id."""
        return self._entries.get(entry_id)

    def list_entries(self) -> List[VectorIndexEntry]:
        """Return all registered vector entries."""
        return list(self._entries.values())

    def count(self) -> int:
        """Return number of registered entries."""
        return len(self._entries)

    def clear(self) -> None:
        """Clear all entries from index."""
        self._entries.clear()
        self._doc_tokens.clear()
        self._doc_freq.clear()
        self._total_docs = 0


# =============================================================================
# 3. VendorDocIngestor: Documentation Parsing & Knowledge Ingestion
# =============================================================================

class VendorDocIngestor:
    """Ingests vendor documentation into tree-structured database and vector index.

    Pre-populates authoritative vendor playbooks for Cisco (IOS/XR), Huawei (VRP),
    Linux FRR (vtysh), and Linux host/gateway (iptables, tc, iproute2).
    """

    def __init__(
        self,
        tree_store: Optional[CommandTreeStore] = None,
        vector_index: Optional[LightweightVectorIndex] = None,
    ) -> None:
        self.tree_store = tree_store or CommandTreeStore()
        self.vector_index = vector_index or LightweightVectorIndex()

    def ingest_record(
        self,
        node: TreeNode,
        entry: Optional[VectorIndexEntry] = None,
    ) -> None:
        """Ingest a single command node and its corresponding vector index entry."""
        self.tree_store.insert(node)
        if not entry:
            entry_id = f"vec-{node.path.replace('/', '-')}"
            entry = VectorIndexEntry(
                entry_id=entry_id,
                tree_path=node.path,
                vendor=node.vendor,
                intent=node.action.upper(),
                scene_description=node.description,
                symptom_keywords=[node.vendor, node.platform, node.domain, node.action] + node.parameters,
            )
        self.vector_index.add_entry(entry)

    def ingest_markdown(
        self,
        markdown_text: str,
        vendor: str,
        platform: str,
    ) -> List[TreeNode]:
        """Parse structured markdown playbook documentation and ingest nodes.

        Supported Markdown Block Format:
        ```markdown
        ### Action: <action_name>
        Domain: <domain_name>
        Description: <description>
        Parameters: <param1>, <param2>
        Symptoms: <kw1>, <kw2>, <kw3>
        Command:
        <cli command template>
        Rollback:
        <cli rollback template>
        ```
        """
        nodes: List[TreeNode] = []
        blocks = re.split(r"(?=###\s+Action:)", markdown_text)

        for block in blocks:
            clean_block = block.strip()
            if not clean_block or not clean_block.startswith("### Action:"):
                continue

            action_match = re.search(r"###\s+Action:\s*([^\n]+)", clean_block)
            domain_match = re.search(r"Domain:\s*([^\n]+)", clean_block)
            desc_match = re.search(r"Description:\s*([^\n]+)", clean_block)
            params_match = re.search(r"Parameters:\s*([^\n]+)", clean_block)
            symptoms_match = re.search(r"Symptoms:\s*([^\n]+)", clean_block)

            action = action_match.group(1).strip() if action_match else "generic_action"
            domain = domain_match.group(1).strip() if domain_match else "general"
            desc = desc_match.group(1).strip() if desc_match else f"Remediation template for {action}"
            params = (
                [p.strip() for p in params_match.group(1).split(",") if p.strip()]
                if params_match else []
            )
            symptoms = (
                [s.strip() for s in symptoms_match.group(1).split(",") if s.strip()]
                if symptoms_match else []
            )

            # Extract Command and Rollback blocks
            cmd_match = re.search(r"Command:\s*\n```(?:bash|cli|sh)?\s*\n(.*?)\n```", clean_block, re.DOTALL)
            if not cmd_match:
                cmd_match = re.search(r"Command:\s*\n([^\n]+(?:\n[^\n]+)*?)(?=\nRollback:|\Z)", clean_block)
            command_template = cmd_match.group(1).strip() if cmd_match else ""

            rb_match = re.search(r"Rollback:\s*\n```(?:bash|cli|sh)?\s*\n(.*?)\n```", clean_block, re.DOTALL)
            if not rb_match:
                rb_match = re.search(r"Rollback:\s*\n([^\n]+(?:\n[^\n]+)*)", clean_block)
            rollback_template = rb_match.group(1).strip() if rb_match else ""

            path = f"{vendor.lower()}/{platform.lower()}/{domain.lower()}/{action.lower()}"
            node = TreeNode(
                path=path,
                vendor=vendor.lower(),
                platform=platform.lower(),
                domain=domain.lower(),
                action=action.lower(),
                command_template=command_template,
                rollback_template=rollback_template,
                parameters=params,
                description=desc,
                is_leaf=True,
            )

            entry_id = f"vec-{path.replace('/', '-')}"
            entry = VectorIndexEntry(
                entry_id=entry_id,
                tree_path=path,
                vendor=vendor.lower(),
                intent=action.upper(),
                scene_description=desc,
                symptom_keywords=symptoms + [vendor.lower(), platform.lower(), domain.lower(), action.lower()],
            )

            self.ingest_record(node, entry)
            nodes.append(node)

        return nodes

    def ingest_doc(self, source: VendorDocSource, raw_text: Optional[str] = None) -> List[TreeNode]:
        """Ingest vendor documentation source."""
        content = raw_text or source.raw_content or ""
        platform = source.metadata.get("platform", "default")
        return self.ingest_markdown(content, vendor=source.vendor, platform=platform)

    def build_default_stores(self) -> Tuple[CommandTreeStore, LightweightVectorIndex]:
        """Pre-populate authoritative vendor playbooks across Cisco, Huawei, FRR, Linux."""
        # ---------------------------------------------------------------------
        # 1. Cisco (IOS / IOS-XR)
        # ---------------------------------------------------------------------
        self.ingest_record(
            TreeNode(
                path="cisco/ios/acl_security/drop_traffic",
                vendor="cisco",
                platform="ios",
                domain="acl_security",
                action="drop_traffic",
                command_template=(
                    "ip access-list extended {acl_name}\n"
                    "deny {protocol} host {src_ip} host {dst_ip} eq {dst_port}\n"
                    "interface {interface}\n"
                    "ip access-group {acl_name} in"
                ),
                rollback_template=(
                    "interface {interface}\n"
                    "no ip access-group {acl_name} in\n"
                    "no ip access-list extended {acl_name}"
                ),
                parameters=["acl_name", "protocol", "src_ip", "dst_ip", "dst_port", "interface"],
                description="Cisco IOS extended ACL 5-tuple packet drop rule and interface binding",
            ),
            VectorIndexEntry(
                entry_id="vec-cisco-acl-drop",
                tree_path="cisco/ios/acl_security/drop_traffic",
                vendor="cisco",
                intent="DROP_TRAFFIC",
                scene_description="Block offending 5-tuple volumetric traffic flood, SYN flood, or unauthorized flows using Cisco extended ACL",
                symptom_keywords=["cisco", "acl", "deny", "drop", "packet_drop", "ddos", "syn_flood", "security", "firewall"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="cisco/ios/routing/static_route",
                vendor="cisco",
                platform="ios",
                domain="routing",
                action="static_route",
                command_template="configure terminal\nip route {dest_prefix} {mask} {next_hop}",
                rollback_template="configure terminal\nno ip route {dest_prefix} {mask} {next_hop}",
                parameters=["dest_prefix", "mask", "next_hop"],
                description="Cisco IOS IPv4 static route addition to restore reachable next-hop",
            ),
            VectorIndexEntry(
                entry_id="vec-cisco-route-static",
                tree_path="cisco/ios/routing/static_route",
                vendor="cisco",
                intent="RESTORE_ROUTE",
                scene_description="Restore missing static route or single-exit reachability discrepancy on Cisco router",
                symptom_keywords=["cisco", "route", "static", "missing_route", "next-hop", "reachability", "routing_misconfig"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="cisco/ios/qos_policing/rate_limit",
                vendor="cisco",
                platform="ios",
                domain="qos_policing",
                action="rate_limit",
                command_template=(
                    "policy-map {pm_name}\n"
                    "class class-default\n"
                    "police {rate_bps} conform-action transmit exceed-action drop\n"
                    "interface {interface}\n"
                    "service-policy input {pm_name}"
                ),
                rollback_template=(
                    "interface {interface}\n"
                    "no service-policy input {pm_name}\n"
                    "no policy-map {pm_name}"
                ),
                parameters=["pm_name", "rate_bps", "interface"],
                description="Cisco IOS input rate policing to throttle ingress traffic floods",
            ),
            VectorIndexEntry(
                entry_id="vec-cisco-qos-police",
                tree_path="cisco/ios/qos_policing/rate_limit",
                vendor="cisco",
                intent="RATE_LIMIT",
                scene_description="Mitigate ingress buffer overflow and queue drop bursts via Cisco policy-map rate policing",
                symptom_keywords=["cisco", "qos", "police", "rate_limit", "bandwidth", "traffic_overload", "buffer_overflow"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="cisco/ios/bgp/neighbor_peering",
                vendor="cisco",
                platform="ios",
                domain="bgp",
                action="neighbor_peering",
                command_template=(
                    "configure terminal\n"
                    "router bgp {local_as}\n"
                    "neighbor {peer_ip} remote-as {remote_as}"
                ),
                rollback_template=(
                    "configure terminal\n"
                    "router bgp {local_as}\n"
                    "no neighbor {peer_ip}"
                ),
                parameters=["local_as", "peer_ip", "remote_as"],
                description="Cisco IOS BGP neighbor peering session configuration",
            ),
            VectorIndexEntry(
                entry_id="vec-cisco-bgp-peer",
                tree_path="cisco/ios/bgp/neighbor_peering",
                vendor="cisco",
                intent="BGP_PEERING",
                scene_description="Restore down or unconfigured BGP neighbor session on Cisco border router",
                symptom_keywords=["cisco", "bgp", "neighbor", "remote-as", "peering", "session_down"],
            ),
        )

        # ---------------------------------------------------------------------
        # 2. Huawei (VRP)
        # ---------------------------------------------------------------------
        self.ingest_record(
            TreeNode(
                path="huawei/vrp/acl_security/drop_traffic",
                vendor="huawei",
                platform="vrp",
                domain="acl_security",
                action="drop_traffic",
                command_template=(
                    "system-view\n"
                    "acl number {acl_id}\n"
                    "rule deny {protocol} source {src_ip} 0 destination {dst_ip} 0\n"
                    "interface {interface}\n"
                    "traffic-filter inbound acl {acl_id}"
                ),
                rollback_template=(
                    "interface {interface}\n"
                    "undo traffic-filter inbound acl {acl_id}\n"
                    "undo acl number {acl_id}"
                ),
                parameters=["acl_id", "protocol", "src_ip", "dst_ip", "interface"],
                description="Huawei VRP advanced ACL packet filter inbound drop",
            ),
            VectorIndexEntry(
                entry_id="vec-huawei-acl-drop",
                tree_path="huawei/vrp/acl_security/drop_traffic",
                vendor="huawei",
                intent="DROP_TRAFFIC",
                scene_description="Filter out unauthorized traffic or drop attack streams on Huawei VRP gateway using inbound traffic-filter",
                symptom_keywords=["huawei", "vrp", "acl", "traffic-filter", "deny", "drop", "ddos", "syn_flood", "security"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="huawei/vrp/routing/static_route",
                vendor="huawei",
                platform="vrp",
                domain="routing",
                action="static_route",
                command_template="system-view\nip route-static {dest_prefix} {mask_len} {next_hop}",
                rollback_template="system-view\nundo ip route-static {dest_prefix} {mask_len} {next_hop}",
                parameters=["dest_prefix", "mask_len", "next_hop"],
                description="Huawei VRP static route creation to fix unreachable gateway or next-hop",
            ),
            VectorIndexEntry(
                entry_id="vec-huawei-route-static",
                tree_path="huawei/vrp/routing/static_route",
                vendor="huawei",
                intent="RESTORE_ROUTE",
                scene_description="Remediate missing static route in Huawei routing table with ip route-static",
                symptom_keywords=["huawei", "vrp", "route", "static", "ip route-static", "missing_route", "reachability"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="huawei/vrp/qos_policing/rate_limit",
                vendor="huawei",
                platform="vrp",
                domain="qos_policing",
                action="rate_limit",
                command_template=(
                    "system-view\n"
                    "traffic classifier {tc_name}\n"
                    "traffic behavior {tb_name}\n"
                    "car cir {rate_kbps}\n"
                    "traffic policy {tp_name}\n"
                    "classifier {tc_name} behavior {tb_name}\n"
                    "interface {interface}\n"
                    "traffic-policy {tp_name} inbound"
                ),
                rollback_template=(
                    "interface {interface}\n"
                    "undo traffic-policy inbound\n"
                    "undo traffic policy {tp_name}\n"
                    "undo traffic behavior {tb_name}\n"
                    "undo traffic classifier {tc_name}"
                ),
                parameters=["tc_name", "tb_name", "rate_kbps", "tp_name", "interface"],
                description="Huawei VRP CAR traffic-policy ingress rate limiting",
            ),
            VectorIndexEntry(
                entry_id="vec-huawei-qos-police",
                tree_path="huawei/vrp/qos_policing/rate_limit",
                vendor="huawei",
                intent="RATE_LIMIT",
                scene_description="Enforce bandwidth rate-limit on Huawei VRP interface to eliminate buffer exhaustion and queue drops",
                symptom_keywords=["huawei", "vrp", "traffic-policy", "car", "qos", "rate_limit", "cir", "traffic_overload"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="huawei/vrp/bgp/neighbor_peering",
                vendor="huawei",
                platform="vrp",
                domain="bgp",
                action="neighbor_peering",
                command_template=(
                    "system-view\n"
                    "bgp {local_as}\n"
                    "peer {peer_ip} as-number {remote_as}"
                ),
                rollback_template=(
                    "system-view\n"
                    "bgp {local_as}\n"
                    "undo peer {peer_ip}"
                ),
                parameters=["local_as", "peer_ip", "remote_as"],
                description="Huawei VRP BGP peer establishment",
            ),
            VectorIndexEntry(
                entry_id="vec-huawei-bgp-peer",
                tree_path="huawei/vrp/bgp/neighbor_peering",
                vendor="huawei",
                intent="BGP_PEERING",
                scene_description="Configure BGP peer session on Huawei router",
                symptom_keywords=["huawei", "vrp", "bgp", "peer", "as-number", "peering"],
            ),
        )

        # ---------------------------------------------------------------------
        # 3. Linux FRR (vtysh)
        # ---------------------------------------------------------------------
        self.ingest_record(
            TreeNode(
                path="frr/vtysh/routing/static_route",
                vendor="frr",
                platform="vtysh",
                domain="routing",
                action="static_route",
                command_template="vtysh -c 'configure terminal' -c 'ip route {destination_subnet} {next_hop_ip}'",
                rollback_template="vtysh -c 'configure terminal' -c 'no ip route {destination_subnet} {next_hop_ip}'",
                parameters=["destination_subnet", "next_hop_ip"],
                description="FRRouting vtysh static route addition for single-exit or subnet reachability",
            ),
            VectorIndexEntry(
                entry_id="vec-frr-route-static",
                tree_path="frr/vtysh/routing/static_route",
                vendor="frr",
                intent="RESTORE_ROUTE",
                scene_description="Remediate missing static route or ICMP drop across FRR router in Containerlab Clos fabric",
                symptom_keywords=["frr", "vtysh", "static", "route", "missing_route", "next-hop", "icmp drop", "routing_misconfig"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="frr/vtysh/bgp/neighbor_peering",
                vendor="frr",
                platform="vtysh",
                domain="bgp",
                action="neighbor_peering",
                command_template="vtysh -c 'configure terminal' -c 'router bgp {local_as}' -c 'neighbor {peer_ip} remote-as {remote_as}'",
                rollback_template="vtysh -c 'configure terminal' -c 'router bgp {local_as}' -c 'no neighbor {peer_ip}'",
                parameters=["local_as", "peer_ip", "remote_as"],
                description="FRRouting vtysh BGP neighbor session establishment",
            ),
            VectorIndexEntry(
                entry_id="vec-frr-bgp-peer",
                tree_path="frr/vtysh/bgp/neighbor_peering",
                vendor="frr",
                intent="BGP_PEERING",
                scene_description="Fix BGP session down or idle adjacency discrepancy on FRR leaf/spine routers",
                symptom_keywords=["frr", "vtysh", "bgp", "neighbor", "adjchange", "session", "as", "peering", "tcp 179"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="frr/vtysh/acl_security/drop_traffic",
                vendor="frr",
                platform="vtysh",
                domain="acl_security",
                action="drop_traffic",
                command_template="vtysh -c 'configure terminal' -c 'access-list {acl_id} deny {protocol} host {src_ip} host {dst_ip}'",
                rollback_template="vtysh -c 'configure terminal' -c 'no access-list {acl_id}'",
                parameters=["acl_id", "protocol", "src_ip", "dst_ip"],
                description="FRRouting vtysh access-list traffic drop rule",
            ),
            VectorIndexEntry(
                entry_id="vec-frr-acl-drop",
                tree_path="frr/vtysh/acl_security/drop_traffic",
                vendor="frr",
                intent="DROP_TRAFFIC",
                scene_description="Block malicious traffic via FRR access-list filtering",
                symptom_keywords=["frr", "vtysh", "access-list", "acl", "deny", "drop", "security"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="frr/vtysh/qos_policing/flowspec_rate_limit",
                vendor="frr",
                platform="vtysh",
                domain="qos_policing",
                action="flowspec_rate_limit",
                command_template=(
                    "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' "
                    "-c 'match-action RATE_LIMIT' -c 'rate {rate_bps}'"
                ),
                rollback_template=(
                    "vtysh -c 'configure terminal' -c 'flowspec' -c 'address-family ipv4' "
                    "-c 'no match-action RATE_LIMIT'"
                ),
                parameters=["rate_bps"],
                description="FRRouting BGP FlowSpec dynamic rate limiting policy",
            ),
            VectorIndexEntry(
                entry_id="vec-frr-flowspec-rate",
                tree_path="frr/vtysh/qos_policing/flowspec_rate_limit",
                vendor="frr",
                intent="RATE_LIMIT",
                scene_description="Throttle volumetric traffic flows dynamically with FRR BGP FlowSpec",
                symptom_keywords=["frr", "vtysh", "flowspec", "rate_limit", "qos", "bandwidth", "traffic_overload"],
            ),
        )

        # ---------------------------------------------------------------------
        # 4. Linux Host / Gateway
        # ---------------------------------------------------------------------
        self.ingest_record(
            TreeNode(
                path="linux/iptables/traffic_filtering/drop_traffic",
                vendor="linux",
                platform="iptables",
                domain="traffic_filtering",
                action="drop_traffic",
                command_template="iptables -I FORWARD -s {src_ip} -d {dst_ip} -p {protocol} --dport {dst_port} -j DROP",
                rollback_template="iptables -D FORWARD -s {src_ip} -d {dst_ip} -p {protocol} --dport {dst_port} -j DROP",
                parameters=["src_ip", "dst_ip", "protocol", "dst_port"],
                description="Linux iptables boundary 5-tuple drop hot-patch on FORWARD chain",
            ),
            VectorIndexEntry(
                entry_id="vec-linux-iptables-drop",
                tree_path="linux/iptables/traffic_filtering/drop_traffic",
                vendor="linux",
                intent="DROP_TRAFFIC",
                scene_description="Mitigate border gateway buffer overlimits, SYN flood, or external overload via iptables FORWARD drop",
                symptom_keywords=["linux", "iptables", "forward", "drop", "overlimits", "buffer", "syn_flood", "ddos", "traffic_overload"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="linux/tc/traffic_shaping/rate_limit",
                vendor="linux",
                platform="tc",
                domain="traffic_shaping",
                action="rate_limit",
                command_template=(
                    "tc qdisc add dev {interface} handle ffff: ingress\n"
                    "tc filter add dev {interface} parent ffff: protocol ip prio 1 u32 "
                    "match ip protocol {protocol} 0xff police rate {rate_bps} burst {burst} drop"
                ),
                rollback_template="tc qdisc del dev {interface} handle ffff: ingress",
                parameters=["interface", "protocol", "rate_bps", "burst"],
                description="Linux Traffic Control (tc) ingress policer token-bucket rate limiter",
            ),
            VectorIndexEntry(
                entry_id="vec-linux-tc-ratelimit",
                tree_path="linux/tc/traffic_shaping/rate_limit",
                vendor="linux",
                intent="RATE_LIMIT",
                scene_description="Throttle high volume UDP blast or queue drops on Linux WAN edge interface using tc ingress policer",
                symptom_keywords=["linux", "tc", "qdisc", "police", "rate_limit", "ingress", "bandwidth_saturation", "overlimits"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="linux/iproute2/routing/static_route",
                vendor="linux",
                platform="iproute2",
                domain="routing",
                action="static_route",
                command_template="ip route replace {destination_subnet} via {next_hop_ip} dev {interface}",
                rollback_template="ip route del {destination_subnet} via {next_hop_ip} dev {interface}",
                parameters=["destination_subnet", "next_hop_ip", "interface"],
                description="Linux iproute2 static route or default gateway remediation",
            ),
            VectorIndexEntry(
                entry_id="vec-linux-route-static",
                tree_path="linux/iproute2/routing/static_route",
                vendor="linux",
                intent="RESTORE_ROUTE",
                scene_description="Fix missing default gateway or subnet route on Linux end-host",
                symptom_keywords=["linux", "iproute2", "gateway", "default", "route", "reachability", "ip route"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="linux/iproute2/interface/link_up",
                vendor="linux",
                platform="iproute2",
                domain="interface",
                action="link_up",
                command_template="ip link set dev {interface} up",
                rollback_template="ip link set dev {interface} down",
                parameters=["interface"],
                description="Linux iproute2 link recovery bringing admin-down interface up",
            ),
            VectorIndexEntry(
                entry_id="vec-linux-link-up",
                tree_path="linux/iproute2/interface/link_up",
                vendor="linux",
                intent="RESET_INTERFACE",
                scene_description="Recover network interface in DOWN or admin_down state",
                symptom_keywords=["linux", "iproute2", "interface", "link", "down", "operstate", "admin_down", "up"],
            ),
        )

        self.ingest_record(
            TreeNode(
                path="linux/netfilter/l2_security/arp_defense",
                vendor="linux",
                platform="netfilter",
                domain="l2_security",
                action="arp_defense",
                command_template=(
                    "ip neigh replace {gateway_ip} lladdr {gateway_mac} nud permanent dev {interface}\n"
                    "sysctl -w net.ipv4.conf.all.arp_ignore=1\n"
                    "sysctl -w net.ipv4.conf.all.arp_announce=2"
                ),
                rollback_template=(
                    "ip neigh del {gateway_ip} dev {interface}\n"
                    "sysctl -w net.ipv4.conf.all.arp_ignore=0\n"
                    "sysctl -w net.ipv4.conf.all.arp_announce=0"
                ),
                parameters=["gateway_ip", "gateway_mac", "interface"],
                description="Linux static ARP binding and kernel spoofing defense",
            ),
            VectorIndexEntry(
                entry_id="vec-linux-arp-defense",
                tree_path="linux/netfilter/l2_security/arp_defense",
                vendor="linux",
                intent="SECURE_ARP",
                scene_description="Mitigate ARP cache poisoning, gateway spoofing, and MITM attacks on Linux",
                symptom_keywords=["linux", "arp", "arp_spoofing", "arp_poisoning", "mitm", "ip_neigh"],
            ),
        )

        return self.tree_store, self.vector_index


# =============================================================================
# 4. DualRetrievalEngine: Semantic Search -> Tree Resolution Pipeline
# =============================================================================

class DualRetrievalEngine:
    """Orchestrates Hierarchical Dual-Retrieval for NetOps operational playbooks.

    Pipeline:
    1. Query LightweightVectorIndex using diagnostic symptoms or inferred keywords.
    2. Retrieve top matching VectorIndexEntry pointers.
    3. Dereference exact tree node path from CommandTreeStore.
    4. Return DualRetrievalResult with exact CLI command & rollback templates (<500B).
    """

    def __init__(
        self,
        tree_store: Optional[CommandTreeStore] = None,
        vector_index: Optional[LightweightVectorIndex] = None,
    ) -> None:
        if tree_store is None or vector_index is None:
            ingestor = VendorDocIngestor()
            self.tree_store, self.vector_index = ingestor.build_default_stores()
            if tree_store is not None:
                self.tree_store = tree_store
            if vector_index is not None:
                self.vector_index = vector_index
        else:
            self.tree_store = tree_store
            self.vector_index = vector_index

    def retrieve(
        self,
        query: str,
        vendor: Optional[str] = None,
        top_k: int = 3,
        threshold: float = 0.05,
    ) -> List[DualRetrievalResult]:
        """Perform dual retrieval: vector search -> tree resolution.

        Args:
            query: Diagnostic symptom description, RAG keywords, or canonical intent.
            vendor: Optional vendor filter ('cisco', 'huawei', 'frr', 'linux').
            top_k: Maximum number of templates to retrieve.
            threshold: Minimum score cutoff for candidate matches.

        Returns:
            List of DualRetrievalResult instances ordered by confidence score.
        """
        # Step 1: Query vector index for top candidate pointers
        hits = self.vector_index.search(
            query=query,
            top_k=top_k * 2,
            vendor=vendor,
            threshold=threshold,
        )

        # Fallback: if vendor filter yielded no hits, try without vendor filter
        if not hits and vendor:
            hits = self.vector_index.search(
                query=query,
                top_k=top_k * 2,
                vendor=None,
                threshold=threshold,
            )

        results: List[DualRetrievalResult] = []
        seen_paths: Set[str] = set()

        # Step 2 & 3: Dereference tree node pointers
        for entry, score in hits:
            if entry.tree_path in seen_paths:
                continue
            node = self.tree_store.get(entry.tree_path)
            if node and node.command_template:
                seen_paths.add(entry.tree_path)
                result = DualRetrievalResult(
                    tree_path=node.path,
                    vendor=node.vendor,
                    command_template=node.command_template,
                    rollback_template=node.rollback_template,
                    parameters=node.parameters,
                    score=round(score, 4),
                    matched_intent=entry.intent,
                    category=node.domain,
                    action=node.action,
                    retrieval_method="dual_vector_tree",
                )
                results.append(result)
                if len(results) >= top_k:
                    break

        return results

    def get_template_by_path(self, path: str) -> Optional[TreeNode]:
        """Directly retrieve authoritative TreeNode by exact tree path."""
        return self.tree_store.get(path)

    @staticmethod
    def format_prompt_context(
        results: List[DualRetrievalResult],
        max_bytes: int = 500,
    ) -> str:
        """Format retrieved dual-retrieval results into concise prompt injection (<500B).

        Guarantees prompt context stays lean and authoritative, preventing prompt bloat.

        Args:
            results: List of DualRetrievalResult instances.
            max_bytes: Maximum byte size limit for formatted context (default: 500).

        Returns:
            Concise markdown string containing exact CLI commands and rollback templates.
        """
        if not results:
            return ""

        parts: List[str] = []
        current_len = 0

        for r in results:
            snippet = (
                f"[VENDOR_TEMPLATE: {r.tree_path}]\n"
                f"Action: {r.command_template}\n"
                f"Rollback: {r.rollback_template}\n"
                f"Params: {', '.join(r.parameters)}"
            )
            snippet_bytes = len(snippet.encode("utf-8"))
            if current_len + snippet_bytes > max_bytes and parts:
                break
            parts.append(snippet)
            current_len += snippet_bytes + 2  # account for separator

        formatted = "\n\n".join(parts)
        # Ensure hard ceiling on max_bytes
        if len(formatted.encode("utf-8")) > max_bytes:
            trimmed = formatted.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
            # Cut at last clean newline
            last_nl = trimmed.rfind("\n")
            if last_nl > 0:
                formatted = trimmed[:last_nl]
            else:
                formatted = trimmed

        return formatted
