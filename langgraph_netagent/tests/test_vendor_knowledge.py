"""Unit and Integration Tests for Vendor Knowledge & Hierarchical Dual-Retrieval (Milestone 3 / R3).

Validates:
1. Data models: TreeNode, VectorIndexEntry, DualRetrievalResult, VendorDocSource.
2. CommandTreeStore: Hierarchical storage, path resolution, multi-vendor templates, O(1) lookup.
3. LightweightVectorIndex: TF-IDF & term overlap search, vendor filtering, lean pointers.
4. VendorDocIngestor: Markdown documentation parsing and default store pre-population.
5. DualRetrievalEngine: Semantic search -> tree resolution pipeline with prompt bloat prevention (<500B).
6. SOPRetriever integration: Backward compatibility with DEFAULT_SOPS and tree-backed vendor retrieval.
"""

import pytest
from langgraph_netagent.models.knowledge import (
    DualRetrievalResult,
    TreeNode,
    VectorIndexEntry,
    VendorDocSource,
)
from langgraph_netagent.tools.vendor_knowledge import (
    CommandTreeStore,
    DualRetrievalEngine,
    LightweightVectorIndex,
    VendorDocIngestor,
)
from langgraph_netagent.tools.sop_retriever import (
    DEFAULT_SOPS,
    SOPRetriever,
)


# =============================================================================
# 1. Test Models
# =============================================================================

class TestKnowledgeModels:
    """Validate Pydantic v2 data models for knowledge subsystem."""

    def test_tree_node_creation_and_aliases(self):
        node = TreeNode(
            path="cisco/ios/acl_security/drop_traffic",
            vendor="cisco",
            platform="ios",
            domain="acl_security",
            action="drop_traffic",
            command_template="deny ip {src_ip} {dst_ip}",
            rollback_template="no deny ip {src_ip} {dst_ip}",
            parameters=["src_ip", "dst_ip"],
            description="Drop rule",
        )
        assert node.path == "cisco/ios/acl_security/drop_traffic"
        assert node.tree_path == node.path
        assert node.category == node.domain
        assert node.command_templates == ["deny ip {src_ip} {dst_ip}"]
        assert node.rollback_templates == ["no deny ip {src_ip} {dst_ip}"]
        assert node.is_leaf is True

    def test_tree_node_auto_path_derivation(self):
        node = TreeNode(
            vendor="huawei",
            platform="vrp",
            domain="routing",
            action="static_route",
            command_template="ip route-static {dest} {mask} {next_hop}",
            rollback_template="undo ip route-static {dest} {mask} {next_hop}",
        )
        assert node.path == "huawei/vrp/routing/static_route"

    def test_tree_node_hierarchy_children(self):
        parent = TreeNode(path="cisco/ios", is_leaf=False)
        child = TreeNode(path="cisco/ios/routing/static_route", action="static_route")
        parent.add_child(child)
        assert parent.is_leaf is False
        assert "static_route" in parent.children
        retrieved = parent.get_child("static_route")
        assert retrieved is not None
        assert retrieved.action == "static_route"

    def test_vector_index_entry_model(self):
        entry = VectorIndexEntry(
            entry_id="vec-test-01",
            tree_path="frr/vtysh/routing/static_route",
            vendor="frr",
            intent="RESTORE_ROUTE",
            scene_description="Fix missing static route in FRR",
            symptom_keywords=["frr", "route", "static"],
        )
        assert entry.canonical_intent == "RESTORE_ROUTE"
        assert entry.vendor == "frr"
        assert len(entry.symptom_keywords) == 3

    def test_dual_retrieval_result_model(self):
        result = DualRetrievalResult(
            tree_path="linux/iptables/traffic_filtering/drop_traffic",
            vendor="linux",
            command_template="iptables -I FORWARD -s {src_ip} -j DROP",
            rollback_template="iptables -D FORWARD -s {src_ip} -j DROP",
            parameters=["src_ip"],
            score=0.95,
            matched_intent="DROP_TRAFFIC",
        )
        assert result.confidence_score == 0.95
        assert len(result.remediation_template) == 1
        assert "iptables -I FORWARD" in result.remediation_template[0]
        assert len(result.rollback_templates) == 1
        assert "iptables -D FORWARD" in result.rollback_templates[0]

    def test_vendor_doc_source_model(self):
        source = VendorDocSource(
            vendor="cisco",
            title="Cisco IOS Security Configuration Guide",
            source_type="playbook",
            version="15.2",
            metadata={"platform": "ios"},
        )
        assert source.vendor == "cisco"
        assert source.version == "15.2"


# =============================================================================
# 2. Test CommandTreeStore
# =============================================================================

class TestCommandTreeStore:
    """Validate hierarchical command tree storage and lookup."""

    def test_insert_and_get_node(self):
        store = CommandTreeStore()
        node = TreeNode(
            path="cisco/ios/routing/static_route",
            vendor="cisco",
            platform="ios",
            domain="routing",
            action="static_route",
            command_template="ip route {prefix} {mask} {next_hop}",
            rollback_template="no ip route {prefix} {mask} {next_hop}",
            parameters=["prefix", "mask", "next_hop"],
        )
        store.insert(node)

        assert store.count() == 1
        retrieved = store.get("cisco/ios/routing/static_route")
        assert retrieved is not None
        assert retrieved.command_template == "ip route {prefix} {mask} {next_hop}"

        # Case and slash tolerance
        assert store.get("CISCO/IOS/ROUTING/STATIC_ROUTE") is not None
        assert store.get("/cisco/ios/routing/static_route/") is not None

    def test_nonexistent_node_returns_none(self):
        store = CommandTreeStore()
        assert store.get("nonexistent/path/for/test") is None

    def test_find_by_vendor_and_action(self):
        store = CommandTreeStore()
        node1 = TreeNode(
            path="cisco/ios/routing/static_route",
            vendor="cisco",
            platform="ios",
            domain="routing",
            action="static_route",
            command_template="cisco route",
            rollback_template="no cisco route",
        )
        node2 = TreeNode(
            path="huawei/vrp/routing/static_route",
            vendor="huawei",
            platform="vrp",
            domain="routing",
            action="static_route",
            command_template="huawei route",
            rollback_template="undo huawei route",
        )
        node3 = TreeNode(
            path="cisco/ios/acl_security/drop_traffic",
            vendor="cisco",
            platform="ios",
            domain="acl_security",
            action="drop_traffic",
            command_template="cisco acl",
            rollback_template="no cisco acl",
        )
        store.insert(node1)
        store.insert(node2)
        store.insert(node3)

        cisco_nodes = store.find(vendor="cisco")
        assert len(cisco_nodes) == 2

        route_nodes = store.find_nodes_by_action(action="static_route")
        assert len(route_nodes) == 2

        cisco_routes = store.find(vendor="cisco", action="static_route")
        assert len(cisco_routes) == 1
        assert cisco_routes[0].vendor == "cisco"

    def test_list_paths(self):
        store = CommandTreeStore()
        store.insert(TreeNode(path="b/b/b/b", vendor="b", platform="b", domain="b", action="b"))
        store.insert(TreeNode(path="a/a/a/a", vendor="a", platform="a", domain="a", action="a"))
        paths = store.list_paths()
        assert paths == ["a/a/a/a", "b/b/b/b"]

    def test_build_default_tree_coverage(self):
        store = CommandTreeStore.build_default_tree()
        assert store.count() >= 15

        # Check coverage across all 4 target platforms/vendors
        cisco_nodes = store.find(vendor="cisco")
        huawei_nodes = store.find(vendor="huawei")
        frr_nodes = store.find(vendor="frr")
        linux_nodes = store.find(vendor="linux")

        assert len(cisco_nodes) >= 4  # ACL drop, route, QoS, BGP
        assert len(huawei_nodes) >= 4  # ACL drop, route, QoS, BGP
        assert len(frr_nodes) >= 4  # route, BGP, ACL, Flowspec
        assert len(linux_nodes) >= 5  # iptables, tc, ip route, ip link, ARP defense


# =============================================================================
# 3. Test LightweightVectorIndex
# =============================================================================

class TestLightweightVectorIndex:
    """Validate lightweight vector embedding & cosine similarity index."""

    def test_add_and_search_by_keywords(self):
        index = LightweightVectorIndex()
        entry1 = VectorIndexEntry(
            entry_id="vec-1",
            tree_path="linux/iptables/traffic_filtering/drop_traffic",
            vendor="linux",
            intent="DROP_TRAFFIC",
            scene_description="Mitigate border gateway SYN flood and DDoS overload",
            symptom_keywords=["syn_flood", "ddos", "overload", "iptables", "drop"],
        )
        entry2 = VectorIndexEntry(
            entry_id="vec-2",
            tree_path="frr/vtysh/routing/static_route",
            vendor="frr",
            intent="RESTORE_ROUTE",
            scene_description="Fix missing static route in Clos fabric",
            symptom_keywords=["frr", "static", "route", "reachability"],
        )
        index.add_entry(entry1)
        index.add_entry(entry2)

        assert index.count() == 2

        # Query for DDoS overload
        hits = index.search("syn flood ddos traffic overload", top_k=1)
        assert len(hits) == 1
        assert hits[0][0].entry_id == "vec-1"
        assert hits[0][1] > 0.3

    def test_vendor_filtering(self):
        index = LightweightVectorIndex()
        index.add_entry(
            VectorIndexEntry(
                entry_id="cisco-acl",
                tree_path="cisco/ios/acl_security/drop_traffic",
                vendor="cisco",
                intent="DROP_TRAFFIC",
                scene_description="Drop packet flood using Cisco ACL",
                symptom_keywords=["cisco", "acl", "drop"],
            )
        )
        index.add_entry(
            VectorIndexEntry(
                entry_id="huawei-acl",
                tree_path="huawei/vrp/acl_security/drop_traffic",
                vendor="huawei",
                intent="DROP_TRAFFIC",
                scene_description="Drop packet flood using Huawei traffic-filter",
                symptom_keywords=["huawei", "vrp", "acl", "drop"],
            )
        )

        cisco_hits = index.search("drop traffic", vendor="cisco")
        assert all(entry.vendor == "cisco" for entry, _ in cisco_hits)

        huawei_hits = index.search("drop traffic", vendor="huawei")
        assert all(entry.vendor == "huawei" for entry, _ in huawei_hits)

    def test_empty_query_returns_empty(self):
        index = LightweightVectorIndex()
        assert index.search("") == []
        assert index.search("   ") == []

    def test_clear_index(self):
        index = LightweightVectorIndex()
        index.add_entry(
            VectorIndexEntry(
                entry_id="test",
                tree_path="p",
                vendor="v",
                intent="I",
                scene_description="d",
            )
        )
        assert index.count() == 1
        index.clear()
        assert index.count() == 0


# =============================================================================
# 4. Test VendorDocIngestor
# =============================================================================

class TestVendorDocIngestor:
    """Validate documentation ingestion parser and store populator."""

    def test_ingest_markdown_documentation(self):
        markdown_content = """
### Action: rate_limit
Domain: qos_policing
Description: Cisco IOS policing policy
Parameters: pm_name, rate_bps, interface
Symptoms: buffer_overflow, queue_drop, traffic_overload
Command:
```cli
policy-map {pm_name}
police {rate_bps} conform-action transmit exceed-action drop
```
Rollback:
```cli
no policy-map {pm_name}
```
"""
        ingestor = VendorDocIngestor()
        nodes = ingestor.ingest_markdown(markdown_content, vendor="cisco", platform="ios")

        assert len(nodes) == 1
        node = nodes[0]
        assert node.path == "cisco/ios/qos_policing/rate_limit"
        assert node.vendor == "cisco"
        assert node.domain == "qos_policing"
        assert node.action == "rate_limit"
        assert "policy-map {pm_name}" in node.command_template
        assert "no policy-map {pm_name}" in node.rollback_template
        assert "pm_name" in node.parameters

        # Verify it was added to tree and vector store
        assert ingestor.tree_store.get(node.path) is not None
        hits = ingestor.vector_index.search("buffer overflow queue drop", vendor="cisco")
        assert len(hits) >= 1
        assert hits[0][0].tree_path == node.path

    def test_build_default_stores(self):
        ingestor = VendorDocIngestor()
        tree, vec = ingestor.build_default_stores()
        assert tree.count() >= 15
        assert vec.count() >= 15


# =============================================================================
# 5. Test DualRetrievalEngine & Prompt Bloat Prevention (<500B)
# =============================================================================

class TestDualRetrievalEngine:
    """Validate the complete Dual-Retrieval pipeline and prompt size control."""

    @pytest.fixture
    def engine(self) -> DualRetrievalEngine:
        return DualRetrievalEngine()

    def test_retrieve_cisco_acl_drop(self, engine: DualRetrievalEngine):
        results = engine.retrieve("block malicious 5-tuple flood syn attack", vendor="cisco", top_k=1)
        assert len(results) == 1
        r = results[0]
        assert r.vendor == "cisco"
        assert "cisco/ios/acl_security/drop_traffic" in r.tree_path
        assert "ip access-list extended" in r.command_template
        assert "no ip access-group" in r.rollback_template
        assert "acl_name" in r.parameters

    def test_retrieve_huawei_static_route(self, engine: DualRetrievalEngine):
        results = engine.retrieve("missing static route reachability", vendor="huawei", top_k=1)
        assert len(results) == 1
        r = results[0]
        assert r.vendor == "huawei"
        assert "huawei/vrp/routing/static_route" in r.tree_path
        assert "ip route-static" in r.command_template
        assert "undo ip route-static" in r.rollback_template

    def test_retrieve_frr_bgp_peering(self, engine: DualRetrievalEngine):
        results = engine.retrieve("bgp neighbor session down adjacency", vendor="frr", top_k=1)
        assert len(results) == 1
        r = results[0]
        assert r.vendor == "frr"
        assert "frr/vtysh/bgp/neighbor_peering" in r.tree_path
        assert "router bgp" in r.command_template
        assert "no neighbor" in r.rollback_template

    def test_retrieve_linux_tc_rate_limit(self, engine: DualRetrievalEngine):
        results = engine.retrieve("tc qdisc ingress rate limit bandwidth", vendor="linux", top_k=1)
        assert len(results) == 1
        r = results[0]
        assert r.vendor == "linux"
        assert "linux/tc/traffic_shaping/rate_limit" in r.tree_path
        assert "tc qdisc add" in r.command_template

    def test_prompt_bloat_prevention_under_500_bytes(self, engine: DualRetrievalEngine):
        """MANDATORY: Verify that retrieved prompt context stays strictly under 500 bytes."""
        results = engine.retrieve("syn flood ddos drop traffic", vendor="linux", top_k=1)
        assert len(results) == 1

        prompt_context = engine.format_prompt_context(results, max_bytes=500)
        byte_len = len(prompt_context.encode("utf-8"))

        assert byte_len > 0
        assert byte_len < 500, f"Prompt context exceeded 500 bytes: {byte_len} bytes"
        assert "Action:" in prompt_context
        assert "Rollback:" in prompt_context

    def test_direct_path_lookup(self, engine: DualRetrievalEngine):
        node = engine.get_template_by_path("cisco/ios/routing/static_route")
        assert node is not None
        assert node.vendor == "cisco"
        assert "ip route" in node.command_template


# =============================================================================
# 6. Test SOPRetriever Integration & Backward Compatibility
# =============================================================================

class TestSOPRetrieverIntegration:
    """Validate SOPRetriever dual-retrieval connectivity with zero regression on DEFAULT_SOPS."""

    def test_legacy_default_sop_retrieval(self):
        """Preserve exact legacy behavior for existing test suites."""
        retriever = SOPRetriever()

        # FRR static route
        sops = retriever.retrieve(["frr", "route", "static"])
        assert len(sops) >= 1
        assert sops[0]["sop_id"] == "SOP-ROUTING-001"
        assert "configure terminal" in sops[0]["remediation_template"][0]

        # Interface down
        sops = retriever.retrieve(["interface", "link", "down"])
        assert len(sops) >= 1
        assert sops[0]["sop_id"] == "SOP-INTERFACE-002"

        # Overload / buffer overlimits
        sops = retriever.retrieve(["overlimits", "buffer", "ddos"])
        assert len(sops) >= 1
        assert sops[0]["sop_id"] == "SOP-OVERLOAD-005"

    def test_vendor_specific_retrieval_via_cisco_and_huawei(self):
        """Validate tree-backed dual retrieval when querying non-legacy vendor playbooks."""
        retriever = SOPRetriever()

        # Cisco extended ACL drop
        sops = retriever.retrieve(["cisco", "drop_traffic", "acl"])
        assert len(sops) >= 1
        assert "CISCO" in sops[0]["sop_id"]
        assert any("access-list" in cmd for cmd in sops[0]["remediation_template"])

        # Huawei static route
        sops = retriever.retrieve(["huawei", "route", "static"])
        assert len(sops) >= 1
        assert "HUAWEI" in sops[0]["sop_id"]
        assert any("ip route-static" in cmd for cmd in sops[0]["remediation_template"])

    def test_explicit_vendor_parameter(self):
        retriever = SOPRetriever()
        sops = retriever.retrieve(["drop_traffic"], vendor="cisco")
        assert len(sops) >= 1
        assert sops[0]["vendor"] == "cisco"

    def test_retrieve_dual_returns_typed_results(self):
        retriever = SOPRetriever()
        dual_results = retriever.retrieve_dual("drop syn flood traffic", vendor="linux")
        assert len(dual_results) >= 1
        assert isinstance(dual_results[0], DualRetrievalResult)
        assert dual_results[0].vendor == "linux"

    def test_retrieve_template_by_path(self):
        retriever = SOPRetriever()
        node = retriever.retrieve_template_by_path("huawei/vrp/acl_security/drop_traffic")
        assert node is not None
        assert node.vendor == "huawei"

    def test_format_dual_markdown_under_500_bytes(self):
        retriever = SOPRetriever()
        dual_results = retriever.retrieve_dual("static route next-hop", vendor="cisco", limit=1)
        markdown = retriever.format_dual_markdown(dual_results)
        assert len(markdown.encode("utf-8")) < 500
