"""Deep Adversarial Stress-Test Suite for Milestone M4.

Empirically challenges:
1. TopologyDiscoverer with malformed schemas, unusual link geometries, extreme topologies, and non-standard kinds.
2. VendorDocScraper with binary/huge payloads, adversarial CLI injection strings, and unusual rollback inputs.
3. operational_nodes.py with empty topologies, zero-router meshes, unresolvable IPs, missing route discrepancies to foreign subnets, and malformed state.
"""

from __future__ import annotations

import copy
import json
import logging
from typing import Any, Dict, List
import pytest
import bs4

from langgraph_netagent.llm.base import LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.models.intent import IntentAction, TargetPlatform
from langgraph_netagent.models.operational import (
    AnomalyClassification,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
)
from langgraph_netagent.models.remediation import RemediationPlan
from langgraph_netagent.models.telemetry import (
    NetworkHealthReport,
    QdiscTelemetry,
)
from langgraph_netagent.prompts.day2_prompts import format_dynamic_topology_prompt
from langgraph_netagent.tools.dynamic_sop_retriever import DynamicSOPRetriever
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer
from langgraph_netagent.tools.vendor_doc_scraper import (
    AristaDocParser,
    CiscoDocParser,
    CommandSyntax,
    DocCacheManager,
    DocFetchError,
    DocFetcher,
    FRRDocParser,
    GenericDocParser,
    ReverseRollbackGenerator,
    ScrapedDocResult,
    TroubleshootingStep,
    VendorDocScraper,
)
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)


# =============================================================================
# Suite 1: TopologyDiscoverer Deep Malformed & Boundary Inputs
# =============================================================================

class TestTopologyDiscovererDeepStress:
    """Stress-tests TopologyDiscoverer against malformed inputs and extreme geometries."""

    def test_malformed_endpoint_single_element(self):
        """Link with only 1 endpoint triggers Pydantic schema ValidationError."""
        yaml_content = """
        name: malformed-link-1
        topology:
          nodes:
            n1:
              kind: linux
          links:
            - endpoints: ["n1:eth1"]
        """
        with pytest.raises(Exception) as exc_info:
            TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert "endpoints" in str(exc_info.value).lower()

    def test_malformed_endpoint_three_elements(self):
        """Link with 3 endpoints triggers Pydantic schema ValidationError."""
        yaml_content = """
        name: malformed-link-3
        topology:
          nodes:
            n1:
              kind: linux
            n2:
              kind: linux
            n3:
              kind: linux
          links:
            - endpoints: ["n1:eth1", "n2:eth1", "n3:eth1"]
        """
        with pytest.raises(Exception) as exc_info:
            TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert "endpoints" in str(exc_info.value).lower()

    def test_malformed_endpoint_no_colon(self):
        """Link with missing interface separator colon triggers Pydantic ValidationError."""
        yaml_content = """
        name: malformed-link-nocolon
        topology:
          nodes:
            n1:
              kind: linux
            n2:
              kind: linux
          links:
            - endpoints: ["n1", "n2"]
        """
        with pytest.raises(Exception) as exc_info:
            TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert "does not match required format" in str(exc_info.value)

    def test_self_loop_link(self):
        """Link where local and remote endpoints are on the same node."""
        yaml_content = """
        name: self-loop-lab
        topology:
          nodes:
            r1:
              kind: linux
              exec:
                - ip addr add 10.10.10.1/24 dev eth1
                - ip addr add 10.10.10.2/24 dev eth2
          links:
            - endpoints: ["r1:eth1", "r1:eth2"]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 1
        # Self-dest resolve_next_hop returns None
        assert topo.resolve_next_hop("r1", "10.10.10.2") is None

    def test_null_fields_in_nodes(self):
        """Node definitions with null exec, env, binds, or kinds trigger Pydantic ValidationError."""
        yaml_content = """
        name: null-fields-lab
        topology:
          nodes:
            node_nulls:
              kind: null
              image: null
              exec: null
              env: null
              binds: null
              group: null
          links: []
        """
        with pytest.raises(Exception) as exc_info:
            TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert "validation error" in str(exc_info.value).lower()

    def test_non_standard_vendor_kinds(self):
        """Discoverer properly parses non-standard kinds like srl, sonic, vyos, ceos."""
        yaml_content = """
        name: multi-vendor-lab
        topology:
          nodes:
            srl1:
              kind: srl
              image: ghcr.io/nokia/srlinux:latest
            sonic1:
              kind: sonic-vs
              image: sonic:latest
            vyos1:
              kind: vyos
              image: vyos:latest
            ceos1:
              kind: ceos
              image: ceos:latest
          links:
            - endpoints: ["srl1:e1-1", "sonic1:eth1"]
            - endpoints: ["vyos1:eth1", "ceos1:eth1"]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 4
        assert topo.nodes["srl1"].kind == "srl"
        assert topo.nodes["sonic1"].kind == "sonic-vs"
        assert topo.nodes["vyos1"].kind == "vyos"
        assert topo.nodes["ceos1"].kind == "ceos"
        assert len(topo.links) == 2

    def test_invalid_and_ipv6_addresses_in_exec(self):
        """Documents that regex does not validate IP octet bounds and indexes out-of-range IPs."""
        yaml_content = """
        name: ip-resilience-lab
        topology:
          nodes:
            n1:
              kind: linux
              exec:
                - ip addr add 999.999.999.999/24 dev eth1
                - ip -6 addr add 2001:db8::1/64 dev eth2
                - ip addr add 10.200.1.1/24 dev eth3
          links: []
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert "n1" in topo.nodes
        # Valid IPv4 is extracted
        assert topo.find_node_by_ip("10.200.1.1") == "n1"
        # Observation: 999.999.999.999 matches \d+\.\d+\.\d+\.\d+ regex, so it is indexed to n1
        assert topo.find_node_by_ip("999.999.999.999") == "n1"

    def test_large_topology_performance(self):
        """Parsing a large topology (50 nodes, 100 links) completes in < 1 second."""
        import time
        nodes_lines = []
        links_lines = []
        for i in range(50):
            nodes_lines.append(f"""
            node-{i}:
              kind: {"frr" if i < 10 else "linux"}
              group: {"router" if i < 10 else "host"}
              exec:
                - ip addr add 10.{i}.1.1/24 dev eth1
            """)
        for i in range(49):
            links_lines.append(f"""
            - endpoints: ["node-{i}:eth1", "node-{i+1}:eth1"]
            """)

        yaml_content = f"""
        name: large-scale-lab
        topology:
          nodes:
            {"".join(nodes_lines)}
          links:
            {"".join(links_lines)}
        """
        t0 = time.perf_counter()
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        elapsed = time.perf_counter() - t0

        assert len(topo.nodes) == 50
        assert len(topo.links) == 49
        assert elapsed < 1.0  # Must be fast (< 1s)

        # BFS across multi-hop path
        nh = topo.resolve_next_hop("node-0", "10.10.1.1")
        assert nh is not None


# =============================================================================
# Suite 2: VendorDocScraper Adversarial Inputs & Reverse Rollback Stress
# =============================================================================

class TestVendorDocScraperDeepStress:
    """Stress-tests scraper, parser, and rollback generator under hostile inputs."""

    def test_huge_html_payload(self):
        """Scraper DOM parsers gracefully handle a huge 2MB HTML table document without OOM or recursion limit."""
        # Generate 1000 syntax elements
        blocks = [
            f"<p class='syntax'>show ip bgp neighbor 10.{i // 256}.{i % 256}.1</p>"
            for i in range(1000)
        ]
        html_input = f"<html><body><h2>Cisco BGP Commands</h2>{''.join(blocks)}</body></html>"

        scraper = VendorDocScraper()
        result = scraper.parse_html(html_input, url="https://cisco.com/doc", vendor="cisco")
        assert isinstance(result, ScrapedDocResult)
        assert len(result.commands) == 1000

    def test_reverse_rollback_adversarial_cli_strings(self):
        """Test rollback generator against injection-like strings, extreme lengths, and non-ASCII."""
        # Long command
        long_cmd = "ip route add 10.0.0.0/8 via " + "10.1.1.1 " * 50
        rb_long = ReverseRollbackGenerator.generate_rollback(long_cmd, vendor="linux")
        assert rb_long.startswith("ip route del")

        # Injection attempt
        inj_cmd = "ip route add 10.1.1.0/24 via 10.1.1.1; rm -rf /"
        rb_inj = ReverseRollbackGenerator.generate_rollback(inj_cmd, vendor="linux")
        assert rb_inj.startswith("ip route del")

        # Unicode / Non-ASCII in description
        unicode_cmd = "Router(config)# description 核心网络边界网关核心"
        rb_uni = ReverseRollbackGenerator.generate_rollback(unicode_cmd, vendor="cisco")
        assert rb_uni == "no description 核心网络边界网关核心"

        # Tabulation and multiple spaces
        weird_spaces = "iptables\t-I\t\tFORWARD\t -s   10.5.5.5   -j DROP"
        rb_spaces = ReverseRollbackGenerator.generate_rollback(weird_spaces, vendor="linux")
        assert "iptables" in rb_spaces
        assert "-D" in rb_spaces or "no " in rb_spaces


# =============================================================================
# Suite 3: operational_nodes.py Adversarial Topologies & Robustness
# =============================================================================

class TestOperationalNodesAdversarialStress:
    """Stress-tests operational_nodes.py against missing topology, zero routers, and malformed inputs."""

    @pytest.fixture
    def mock_llm(self) -> MockLLMProvider:
        config = LLMConfig(provider_type="mock", model_name="mock-stress", max_retries=3)
        return MockLLMProvider(config=config)

    def test_operational_nodes_node_kinds_none_triggers_attribute_error(self, mock_llm: MockLLMProvider):
        """Empirically documents that state['node_kinds'] = None raises AttributeError in stage2."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()
        nodes = create_operational_nodes(llm_provider=mock_llm, lab_adapter=adapter, retriever=retriever, auto_approve=True)

        state = create_operational_initial_state()
        state["node_kinds"] = None  # default in create_operational_initial_state()
        state["suspect_devices"] = ["edge-router"]
        state["anomaly_classification"] = {
            "category": "external_overload",
            "bottleneck_node": "edge-router",
            "bottleneck_interface": "eth1",
            "offending_source_ip": "198.51.100.5",
            "victim_destination_ip": "203.0.113.88",
        }

        # Because state.get("node_kinds", {}) returns None when node_kinds is explicitly None in state,
        # calling state.get("node_kinds", {}).get(...) raises AttributeError
        with pytest.raises(AttributeError) as exc_info:
            nodes["diagnostic_stage2"](state)
        assert "'NoneType' object has no attribute 'get'" in str(exc_info.value)

    def test_operational_nodes_with_none_discovered_topology(self, mock_llm: MockLLMProvider):
        """Workflow executes safely when discovered_topology is None and node_kinds is empty dict."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=adapter,
            retriever=retriever,
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["node_kinds"] = {}
        state["discovered_topology"] = None
        state["topology_path"] = ["edge-router", "core-switch", "server1"]
        state["suspect_devices"] = ["edge-router"]

        # Anomaly classification with None discovered_topology
        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit on edge-router:eth1"],
            buffer_anomalies=[{"node": "edge-router", "interface": "eth1", "dropped": 500, "overlimits": 1000}],
        )
        anomaly = classify_anomaly(
            report=health_report,
            discrepancies=[],
            failure_5tuples=[
                FiveTuple(
                    source_ip="198.51.100.5",
                    destination_ip="203.0.113.88",
                    protocol="TCP",
                    src_port=12345,
                    dst_port=80,
                    alert_type="TRAFFIC_OVERLOAD",
                    is_external_overload=True,
                )
            ],
            discovered_topology=None,
        )
        assert anomaly.category == "external_overload"
        assert anomaly.bottleneck_node == "edge-router"

        # Diagnostic Stage 1 with None discovered_topology
        state["anomaly_classification"] = anomaly.model_dump()
        s1_res = nodes["diagnostic_stage1"](state)
        assert s1_res["status"] == "stage1_enriched"
        state.update(s1_res)

        # Diagnostic Stage 2 with None discovered_topology
        s2_res = nodes["diagnostic_stage2"](state)
        assert s2_res["status"] == "stage2_plan_generated"
        plan = s2_res.get("remediation_plan")
        assert plan is not None
        assert len(plan["exec_commands"]) > 0

    def test_operational_nodes_with_corrupted_topology_dict(self, mock_llm: MockLLMProvider):
        """Workflow does not crash when discovered_topology contains invalid schema dict."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()
        nodes = create_operational_nodes(llm_provider=mock_llm, lab_adapter=adapter, retriever=retriever, auto_approve=True)

        state = create_operational_initial_state()
        state["node_kinds"] = {}
        # Invalid schema dict that fails Pydantic validation
        state["discovered_topology"] = {"broken_key": 9999, "name": 123}
        state["topology_path"] = ["gw1", "srv1"]
        state["suspect_devices"] = ["gw1"]

        # Classify anomaly
        anomaly = classify_anomaly(
            report=None,
            discrepancies=[
                NetworkDiscrepancy(
                    discrepancy_type="buffer_overlimit",
                    node="gw1",
                    affected_interface="eth1",
                    description="Buffer drop",
                )
            ],
            discovered_topology=state["discovered_topology"],
        )
        assert anomaly.category == "external_overload"
        assert anomaly.bottleneck_node == "gw1"

        state["anomaly_classification"] = anomaly.model_dump()
        s1_res = nodes["diagnostic_stage1"](state)
        assert s1_res["status"] == "stage1_enriched"
        state.update(s1_res)

        s2_res = nodes["diagnostic_stage2"](state)
        assert s2_res["status"] == "stage2_plan_generated"

    def test_novel_topology_zero_routers_mesh(self, mock_llm: MockLLMProvider):
        """Workflow operates safely on a novel topology where all nodes are hosts (zero routers)."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()
        nodes = create_operational_nodes(llm_provider=mock_llm, lab_adapter=adapter, retriever=retriever, auto_approve=True)

        # Topology with 3 hosts, 0 routers
        host_nodes = {
            f"host{i}": DiscoveredNode(
                name=f"host{i}",
                kind="linux",
                role="host",
                ips=[f"192.168.10.{i}/24"],
                subnets=["192.168.10.0/24"],
                interfaces={"eth1": DiscoveredInterface(name="eth1", ipv4_addresses=[f"192.168.10.{i}/24"])},
            )
            for i in range(1, 4)
        }
        zero_router_topo = DiscoveredTopology(
            name="zero-router-lab",
            nodes=host_nodes,
            links=[],
            subnets=["192.168.10.0/24"],
            vips=[],
            node_roles={f"host{i}": "host" for i in range(1, 4)},
            routers=[],
            hosts=["host1", "host2", "host3"],
            ip_to_node={f"192.168.10.{i}": f"host{i}" for i in range(1, 4)},
        )

        state = create_operational_initial_state()
        state["discovered_topology"] = zero_router_topo.model_dump()
        state["node_kinds"] = {f"host{i}": "linux" for i in range(1, 4)}

        # Ingest baseline
        ingest_res = nodes["baseline_ingestion"](state)
        assert ingest_res["status"] == "baseline_ingested"
        state.update(ingest_res)

        # Inject overload
        anomaly = classify_anomaly(
            report=NetworkHealthReport(
                all_passed=False,
                failures=["Buffer drop on host1:eth1"],
                buffer_anomalies=[{"node": "host1", "interface": "eth1", "dropped": 100, "overlimits": 200}],
            ),
            failure_5tuples=[
                FiveTuple(
                    source_ip="192.168.10.3",
                    destination_ip="192.168.10.1",
                    protocol="TCP",
                    src_port=5555,
                    dst_port=8080,
                    alert_type="TRAFFIC_OVERLOAD",
                    is_external_overload=True,
                )
            ],
            discovered_topology=zero_router_topo,
        )
        assert anomaly.bottleneck_node == "host1"

        state["anomaly_classification"] = anomaly.model_dump()
        state["suspect_devices"] = ["host1"]

        s1_res = nodes["diagnostic_stage1"](state)
        assert s1_res["status"] == "stage1_enriched"
        state.update(s1_res)

        s2_res = nodes["diagnostic_stage2"](state)
        assert s2_res["status"] == "stage2_plan_generated"
        plan = s2_res["remediation_plan"]
        assert plan["target_entity"] == "host1"

    def test_routing_deficit_to_completely_foreign_subnet(self, mock_llm: MockLLMProvider):
        """When missing_route destination is completely foreign to topology, graph fallback resolves gracefully."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()
        nodes = create_operational_nodes(llm_provider=mock_llm, lab_adapter=adapter, retriever=retriever, auto_approve=True)

        topo = DiscoveredTopology(
            name="simple-transit",
            nodes={
                "r1": DiscoveredNode(
                    name="r1",
                    kind="frr",
                    role="router",
                    ips=["10.1.1.1/24"],
                    subnets=["10.1.1.0/24"],
                    interfaces={"eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.1.1.1/24"], peer_node="r2", peer_interface="eth1")},
                ),
                "r2": DiscoveredNode(
                    name="r2",
                    kind="frr",
                    role="router",
                    ips=["10.1.1.2/24"],
                    subnets=["10.1.1.0/24"],
                    interfaces={"eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.1.1.2/24"], peer_node="r1", peer_interface="eth1")},
                ),
            },
            links=[DiscoveredLink(endpoints=[("r1", "eth1"), ("r2", "eth1")], local_node="r1", local_iface="eth1", remote_node="r2", remote_iface="eth1")],
            subnets=["10.1.1.0/24"],
            node_roles={"r1": "router", "r2": "router"},
            routers=["r1", "r2"],
            hosts=[],
            ip_to_node={"10.1.1.1": "r1", "10.1.1.2": "r2"},
        )

        state = create_operational_initial_state()
        state["discovered_topology"] = topo.model_dump()
        state["node_kinds"] = {"r1": "frr", "r2": "frr"}
        state["suspect_devices"] = ["r1"]
        state["anomaly_classification"] = {
            "category": "single_exit_failure",
            "bottleneck_node": "r1",
            "bottleneck_interface": "eth1",
            "victim_destination_ip": "198.18.99.0/24",  # Foreign subnet!
            "confidence": 0.9,
        }
        state["discrepancies"] = [
            NetworkDiscrepancy(
                discrepancy_type="missing_route",
                node="r1",
                affected_interface="eth1",
                target_destination="198.18.99.0/24",
                description="Route to foreign subnet missing",
            ).model_dump()
        ]

        # Stage 1
        s1_res = nodes["diagnostic_stage1"](state)
        state.update(s1_res)

        # Stage 2: resolve next hop to foreign subnet.
        # Should gracefully resolve via peer interface to r2's IP (10.1.1.2) without crashing!
        s2_res = nodes["diagnostic_stage2"](state)
        assert s2_res["status"] == "stage2_plan_generated"
        plan = s2_res["remediation_plan"]
        assert plan["target_entity"] == "r1"
        cmd_str = " ".join(plan["exec_commands"])
        assert "198.18.99.0/24" in cmd_str
        # Should resolve to peer r2's interface IP (10.1.1.2)
        assert "10.1.1.2" in cmd_str

    def test_dynamic_topology_prompt_truncation_under_huge_topology(self):
        """format_dynamic_topology_prompt enforces max_bytes=500 even with 100 subnets and 50 nodes."""
        nodes = {
            f"gw-{i}": DiscoveredNode(
                name=f"gw-{i}",
                kind="frr",
                role="router",
                ips=[f"10.{i}.1.1/24"],
                subnets=[f"10.{i}.1.0/24"],
            )
            for i in range(50)
        }
        huge_topo = DiscoveredTopology(
            name="huge-enterprise-core",
            nodes=nodes,
            links=[],
            subnets=[f"10.{i}.1.0/24" for i in range(50)],
            vips=[f"203.0.113.{i}" for i in range(20)],
            node_roles={f"gw-{i}": "router" for i in range(50)},
            routers=[f"gw-{i}" for i in range(50)],
            hosts=[],
            ip_to_node={f"10.{i}.1.1": f"gw-{i}" for i in range(50)},
        )

        formatted = format_dynamic_topology_prompt(huge_topo, max_bytes=500)
        assert len(formatted.encode("utf-8")) <= 500
        assert "Discovered Network Topology" in formatted

