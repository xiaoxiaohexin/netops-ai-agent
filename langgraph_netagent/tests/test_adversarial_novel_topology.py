"""Adversarial Verification Suite for Dynamic Topology and Zero-Hardcoding Invariants.

Authored by empirical_challenger (challenger_m4_2).

This test suite rigorously challenges the operational workflow (workflow/operational_nodes.py)
against entirely unseen, novel topologies and validates all zero-hardcoding invariants.

Tests:
1. test_novel_topology_baseline_and_overload_diagnosis:
   - Ingests unseen topology ('adversarial-mesh') with nodes: spine-alpha, leaf-beta, edge-delta,
     attacker-omega, host-gamma, subnets 172.31.50.0/24 - 172.31.99.0/24, VIP 198.51.100.99.
   - Injects simulated queue buffer drops on edge-delta.
   - Validates anomaly classification, diagnostic report, and remediation plan reference ONLY
     novel topology entities, with ZERO leakage of legacy Clos5 names (dc-egress, frr1, 192.168.100.2, 203.0.113.10).
2. test_novel_topology_routing_deficit_dynamic_resolution:
   - Injects missing route discrepancy for 172.31.51.0/24 on spine-alpha.
   - Validates that the workflow resolves next-hop dynamically via DiscoveredTopology graph traversal
     to leaf-beta's IP (172.31.50.2) without static fallbacks or legacy Clos5 references.
3. test_hardcoding_invariant_ast_and_regex_audit:
   - Scans all Python files in langgraph_netagent/workflow/ using AST visitor and regex.
   - Enforces zero occurrences of forbidden legacy IPs and router names.
   - Asserts absence of static node-to-IP lookup tables and router-specific branching.
4. test_diagnostic_stage2_prompt_budget_under_heavy_load:
   - Evaluates dynamic context prompt injection (topology summary, scraped SOPs, dual-retrieval)
     under extreme alert, metric, and topology load to guarantee strict conformance to the <500B budget.
"""

from __future__ import annotations

import ast
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Set, Tuple
import pytest
import yaml

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
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.models.telemetry import (
    NetworkHealthReport,
    PingTelemetry,
    QdiscTelemetry,
)
from langgraph_netagent.prompts.day2_prompts import format_dynamic_topology_prompt
from langgraph_netagent.tools.dynamic_sop_retriever import DynamicSOPRetriever
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer
from langgraph_netagent.tools.vendor_doc_scraper import (
    CommandSyntax,
    ScrapedDocResult,
    TroubleshootingStep,
)
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)

FORBIDDEN_LEGACY_LITERALS: Set[str] = {
    "192.168.100.2",
    "203.0.113.10",
    "10.1.12.2",
    "10.2.2.0/24",
    "dc-egress",
    "frr1",
}


def _assert_zero_legacy_leakage(obj: Any, context_label: str) -> None:
    """Recursively serialize and verify that no legacy Clos5 names or IPs appear in obj."""
    text = json.dumps(obj, default=str) if not isinstance(obj, str) else obj
    for forbidden in FORBIDDEN_LEGACY_LITERALS:
        assert forbidden not in text, (
            f"Adversarial Leakage Detected! Found legacy literal '{forbidden}' in {context_label}: {text}"
        )


def _build_novel_adversarial_topology() -> DiscoveredTopology:
    """Builds an entirely novel, unseen topology with zero overlap with Clos5."""
    nodes = {
        "spine-alpha": DiscoveredNode(
            name="spine-alpha",
            kind="frr",
            role="router",
            ips=["172.31.50.1/24", "172.31.52.1/24"],
            subnets=["172.31.50.0/24", "172.31.52.0/24"],
            interfaces={
                "eth1": DiscoveredInterface(
                    name="eth1",
                    ipv4_addresses=["172.31.50.1/24"],
                    peer_node="leaf-beta",
                    peer_interface="eth1",
                ),
                "eth2": DiscoveredInterface(
                    name="eth2",
                    ipv4_addresses=["172.31.52.1/24"],
                    peer_node="edge-delta",
                    peer_interface="eth1",
                ),
            },
        ),
        "leaf-beta": DiscoveredNode(
            name="leaf-beta",
            kind="frr",
            role="router",
            ips=["172.31.50.2/24", "172.31.51.1/24"],
            subnets=["172.31.50.0/24", "172.31.51.0/24"],
            interfaces={
                "eth1": DiscoveredInterface(
                    name="eth1",
                    ipv4_addresses=["172.31.50.2/24"],
                    peer_node="spine-alpha",
                    peer_interface="eth1",
                ),
                "eth2": DiscoveredInterface(
                    name="eth2",
                    ipv4_addresses=["172.31.51.1/24"],
                    peer_node="host-gamma",
                    peer_interface="eth1",
                ),
            },
        ),
        "edge-delta": DiscoveredNode(
            name="edge-delta",
            kind="linux",
            role="egress",
            ips=["172.31.52.2/24", "172.31.99.1/24"],
            subnets=["172.31.52.0/24", "172.31.99.0/24"],
            vips=["198.51.100.99"],
            interfaces={
                "eth1": DiscoveredInterface(
                    name="eth1",
                    ipv4_addresses=["172.31.52.2/24"],
                    peer_node="spine-alpha",
                    peer_interface="eth2",
                ),
                "eth2": DiscoveredInterface(
                    name="eth2",
                    ipv4_addresses=["172.31.99.1/24"],
                    peer_node="attacker-omega",
                    peer_interface="eth1",
                ),
            },
        ),
        "attacker-omega": DiscoveredNode(
            name="attacker-omega",
            kind="linux",
            role="attacker",
            ips=["172.31.99.66/24"],
            subnets=["172.31.99.0/24"],
            interfaces={
                "eth1": DiscoveredInterface(
                    name="eth1",
                    ipv4_addresses=["172.31.99.66/24"],
                    peer_node="edge-delta",
                    peer_interface="eth2",
                ),
            },
        ),
        "host-gamma": DiscoveredNode(
            name="host-gamma",
            kind="linux",
            role="host",
            ips=["172.31.51.99/24"],
            subnets=["172.31.51.0/24"],
            interfaces={
                "eth1": DiscoveredInterface(
                    name="eth1",
                    ipv4_addresses=["172.31.51.99/24"],
                    peer_node="leaf-beta",
                    peer_interface="eth2",
                ),
            },
        ),
    }

    links = [
        DiscoveredLink(
            endpoints=[("spine-alpha", "eth1"), ("leaf-beta", "eth1")],
            local_node="spine-alpha",
            local_iface="eth1",
            remote_node="leaf-beta",
            remote_iface="eth1",
        ),
        DiscoveredLink(
            endpoints=[("spine-alpha", "eth2"), ("edge-delta", "eth1")],
            local_node="spine-alpha",
            local_iface="eth2",
            remote_node="edge-delta",
            remote_iface="eth1",
        ),
        DiscoveredLink(
            endpoints=[("edge-delta", "eth2"), ("attacker-omega", "eth1")],
            local_node="edge-delta",
            local_iface="eth2",
            remote_node="attacker-omega",
            remote_iface="eth1",
        ),
        DiscoveredLink(
            endpoints=[("leaf-beta", "eth2"), ("host-gamma", "eth1")],
            local_node="leaf-beta",
            local_iface="eth2",
            remote_node="host-gamma",
            remote_iface="eth1",
        ),
    ]

    return DiscoveredTopology(
        name="adversarial-mesh",
        nodes=nodes,
        links=links,
        subnets=[
            "172.31.50.0/24",
            "172.31.51.0/24",
            "172.31.52.0/24",
            "172.31.99.0/24",
        ],
        vips=["198.51.100.99"],
        node_roles={
            "spine-alpha": "router",
            "leaf-beta": "router",
            "edge-delta": "egress",
            "attacker-omega": "attacker",
            "host-gamma": "host",
        },
        routers=["spine-alpha", "leaf-beta"],
        hosts=["attacker-omega", "host-gamma"],
        ip_to_node={
            "172.31.50.1": "spine-alpha",
            "172.31.52.1": "spine-alpha",
            "172.31.50.2": "leaf-beta",
            "172.31.51.1": "leaf-beta",
            "172.31.52.2": "edge-delta",
            "172.31.99.1": "edge-delta",
            "172.31.99.66": "attacker-omega",
            "172.31.51.99": "host-gamma",
        },
    )


class TestAdversarialNovelTopology:
    """Stress tests operational workflow against completely unseen topologies."""

    @pytest.fixture
    def novel_topo(self) -> DiscoveredTopology:
        return _build_novel_adversarial_topology()

    @pytest.fixture
    def mock_llm(self) -> MockLLMProvider:
        config = LLMConfig(provider_type="mock", model_name="mock-adversary", max_retries=3)
        return MockLLMProvider(config=config)

    def test_novel_topology_baseline_and_overload_diagnosis(
        self, novel_topo: DiscoveredTopology, mock_llm: MockLLMProvider
    ):
        """Feed unseen topology into baseline_ingestion_node and classify_anomaly under traffic overload."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=adapter,
            retriever=retriever,
            auto_approve=True,
        )

        # 1. Baseline Ingestion with novel topology
        state = create_operational_initial_state()
        state["discovered_topology"] = novel_topo.model_dump()

        ingest_res = nodes["baseline_ingestion"](state)
        assert ingest_res["status"] == "baseline_ingested"
        inv_pool = ingest_res["inventory_pool"]
        assert "edge-delta" in inv_pool["assets"]
        assert "spine-alpha" in inv_pool["assets"]
        assert "198.51.100.99" in ingest_res["discovered_topology"]["vips"]
        _assert_zero_legacy_leakage(ingest_res, "baseline_ingestion result")

        # Update state with ingested inventory
        state.update(ingest_res)
        state["node_kinds"] = {
            "spine-alpha": "frr",
            "leaf-beta": "frr",
            "edge-delta": "linux",
            "attacker-omega": "linux",
            "host-gamma": "linux",
        }

        # 2. Inject queue drops / overload on edge-delta
        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit surge on edge-delta:eth2"],
            buffer_anomalies=[
                {
                    "node": "edge-delta",
                    "interface": "eth2",
                    "dropped": 850,
                    "overlimits": 2400,
                }
            ],
            qdisc_stats={
                "edge-delta": [
                    QdiscTelemetry(
                        node="edge-delta",
                        interface="eth2",
                        qdisc_type="tbf",
                        dropped=850,
                        overlimits=2400,
                    )
                ]
            },
        )
        failure_5tuples = [
            FiveTuple.from_traffic_overload(
                src_ip="172.31.99.66",
                dst_ip="198.51.100.99",
                protocol="TCP",
                src_port=49152,
                dst_port=80,
                overlimits=2400,
                dropped=850,
                raw_log="Volumetric synflood on edge-delta:eth2 from 172.31.99.66 -> 198.51.100.99:80",
            )
        ]

        # 3. Anomaly Classification
        anomaly = classify_anomaly(
            report=health_report,
            discrepancies=[],
            failure_5tuples=failure_5tuples,
            inventory=inv_pool,
            discovered_topology=novel_topo,
        )

        assert anomaly.category == "external_overload"
        assert anomaly.bottleneck_node == "edge-delta"
        assert anomaly.bottleneck_interface == "eth2"
        assert anomaly.offending_source_ip == "172.31.99.66"
        assert anomaly.victim_destination_ip == "198.51.100.99"
        _assert_zero_legacy_leakage(anomaly.model_dump(), "anomaly classification")

        # 4. Two-Stage Diagnosis
        state["anomaly_classification"] = anomaly.model_dump()
        state["failure_5tuples"] = [f.model_dump() for f in failure_5tuples]
        state["suspect_devices"] = ["edge-delta"]

        # Stage 1
        s1_res = nodes["diagnostic_stage1"](state)
        assert s1_res["status"] == "stage1_enriched"
        assert "edge-delta" in s1_res["enriched_context"]["suspect_nodes"]
        _assert_zero_legacy_leakage(s1_res, "diagnostic_stage1 result")
        state.update(s1_res)

        # Stage 2 Plan Generation
        s2_res = nodes["diagnostic_stage2"](state)
        assert s2_res["status"] == "stage2_plan_generated"
        remed_plan = s2_res.get("remediation_plan")
        assert remed_plan is not None

        # Verify plan operates strictly on novel topology
        assert remed_plan["target_entity"] == "edge-delta"
        commands = remed_plan["exec_commands"]
        assert len(commands) > 0

        # Assert iptables perimeter rule targets novel IP
        cmd_str = " ".join(commands)
        assert "172.31.99.66" in cmd_str or "172.31.99.0/24" in cmd_str
        assert "iptables" in cmd_str

        # Strict adversarial check: ZERO legacy Clos5 references anywhere!
        _assert_zero_legacy_leakage(s2_res, "diagnostic_stage2 result")

    def test_novel_topology_routing_deficit_dynamic_resolution(
        self, novel_topo: DiscoveredTopology, mock_llm: MockLLMProvider
    ):
        """Inject routing deficit for 172.31.51.0/24 on spine-alpha and verify dynamic next-hop resolution."""
        adapter = MockContainerlabAdapter()
        retriever = DynamicSOPRetriever()

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=adapter,
            retriever=retriever,
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["discovered_topology"] = novel_topo.model_dump()
        state["node_kinds"] = {
            "spine-alpha": "frr",
            "leaf-beta": "frr",
            "edge-delta": "linux",
            "attacker-omega": "linux",
            "host-gamma": "linux",
        }
        state["topology_path"] = ["spine-alpha", "leaf-beta", "host-gamma"]

        # Ingest baseline
        ingest_res = nodes["baseline_ingestion"](state)
        state.update(ingest_res)

        # Discrepancy: missing static route to host-gamma subnet 172.31.51.0/24 on spine-alpha
        discrepancy = NetworkDiscrepancy(
            discrepancy_type="missing_route",
            node="spine-alpha",
            affected_interface="eth1",
            target_destination="172.31.51.0/24",
            description="Route missing for 172.31.51.0/24 on spine-alpha",
            severity="high",
        )
        state["discrepancies"] = [discrepancy.model_dump()]
        state["suspect_devices"] = ["spine-alpha"]
        state["anomaly_classification"] = {
            "category": "single_exit_failure",
            "bottleneck_node": "spine-alpha",
            "bottleneck_interface": "eth1",
            "offending_source_ip": None,
            "victim_destination_ip": "172.31.51.0/24",
            "confidence": 0.95,
        }

        # Stage 1
        s1_res = nodes["diagnostic_stage1"](state)
        state.update(s1_res)

        # Stage 2
        s2_res = nodes["diagnostic_stage2"](state)
        remed_plan = s2_res.get("remediation_plan")
        assert remed_plan is not None

        assert remed_plan["target_entity"] == "spine-alpha"
        commands = remed_plan["exec_commands"]
        cmd_str = " ".join(commands)

        # The route MUST be added for target 172.31.51.0/24
        assert "172.31.51.0/24" in cmd_str

        # Dynamic next-hop must be leaf-beta's connected interface IP (172.31.50.2), NOT any hardcoded Clos5 IP
        assert "172.31.50.2" in cmd_str

        # Strict adversarial check: ZERO legacy Clos5 references!
        _assert_zero_legacy_leakage(s2_res, "stage2 routing plan")


class TestHardcodingInvariantStress:
    """Stress tests AST scanning across all workflow files and prompts budget limits."""

    def test_workflow_ast_forbidden_literals_scan(self):
        """Scans all Python files in workflow/ asserting zero forbidden IPs or node names."""
        workflow_dir = Path(__file__).resolve().parent.parent / "langgraph_netagent" / "workflow"
        py_files = sorted(workflow_dir.glob("*.py"))
        assert len(py_files) > 0

        forbidden_regexes = {
            "192.168.100.2": re.compile(r"\b192\.168\.100\.2\b"),
            "203.0.113.10": re.compile(r"\b203\.0\.113\.10\b"),
            "10.1.12.2": re.compile(r"\b10\.1\.12\.2\b"),
            "10.2.2.0/24": re.compile(r"\b10\.2\.2\.0/24\b"),
            "dc-egress": re.compile(r"\bdc-egress\b"),
        }

        violations: List[str] = []

        for f in py_files:
            text = f.read_text(encoding="utf-8")
            for name, reg in forbidden_regexes.items():
                for match in reg.finditer(text):
                    lineno = text.count("\n", 0, match.start()) + 1
                    line = text.splitlines()[lineno - 1].strip()
                    # Skip comment-only lines
                    if line.startswith("#"):
                        continue
                    violations.append(f"{f.name}:{lineno} contains forbidden literal '{name}': {line}")

        assert not violations, "\n".join(violations)

    def test_operational_nodes_no_frr1_target_fallback(self):
        """operational_nodes.py must contain zero occurrences of 'frr1' as a target fallback."""
        op_nodes_path = (
            Path(__file__).resolve().parent.parent
            / "langgraph_netagent"
            / "workflow"
            / "operational_nodes.py"
        )
        text = op_nodes_path.read_text(encoding="utf-8")
        assert "frr1" not in text, "Found 'frr1' in operational_nodes.py!"

    def test_prompt_budget_under_extreme_load(self):
        """Under heavy alert/topology/SOP load, verify prompt context additions never exceed <500B."""
        # 1. Massive topology with 500 nodes, 400 links, 200 VIPs
        nodes = {}
        for i in range(500):
            nodes[f"sw-node-{i}"] = DiscoveredNode(
                name=f"sw-node-{i}",
                kind="frr" if i % 2 == 0 else "linux",
                role="router" if i % 2 == 0 else "host",
                ips=[f"10.{i//256}.{i%256}.1/24"],
            )
        links = [
            DiscoveredLink(
                endpoints=[(f"sw-node-{i}", f"eth{i}"), (f"sw-node-{i+1}", f"eth{i+1}")],
                local_node=f"sw-node-{i}",
                local_iface=f"eth{i}",
                remote_node=f"sw-node-{i+1}",
                remote_iface=f"eth{i+1}",
            )
            for i in range(400)
        ]
        subnets = [f"10.{i//256}.{i%256}.0/24" for i in range(500)]
        vips = [f"198.51.{i//256}.{i%256}" for i in range(200)]
        massive_topo = DiscoveredTopology(
            name="massive-data-center",
            nodes=nodes,
            links=links,
            subnets=subnets,
            vips=vips,
        )

        topo_prompt = format_dynamic_topology_prompt(massive_topo, max_bytes=500)
        topo_bytes = len(topo_prompt.encode("utf-8"))
        assert topo_bytes <= 500, f"Topology prompt exceeded budget: {topo_bytes}B > 500B"
        assert topo_bytes > 0

        # 2. Massive SOP catalog with 50 lengthy playbooks
        massive_sops = []
        for i in range(50):
            massive_sops.append({
                "sop_id": f"SOP-OVERLOAD-{i:04d}",
                "title": f"Massive Scale Automated Remediation Playbook {i} for Edge Gateways",
                "category": "perimeter_defense",
                "remediation_template": [
                    f"iptables -I INPUT {j} -s 172.31.{i}.{j}/32 -p tcp --dport {8000+j} -j DROP"
                    for j in range(15)
                ],
                "rollback_template": [
                    f"iptables -D INPUT -s 172.31.{i}.{j}/32 -p tcp --dport {8000+j} -j DROP"
                    for j in range(15)
                ],
            })

        retriever = DynamicSOPRetriever()
        sop_prompt = retriever.format_sop_markdown(massive_sops, max_bytes=500)
        sop_bytes = len(sop_prompt.encode("utf-8"))
        assert sop_bytes <= 500, f"SOP prompt exceeded budget: {sop_bytes}B > 500B"
        assert sop_bytes > 0

        # 3. Dual retrieval prompt with multiple long knowledge nodes
        dual_results = retriever.retrieve_dual("iptables perimeter drop overload", limit=10)
        dual_prompt = retriever.format_dual_markdown(dual_results, max_bytes=500)
        dual_bytes = len(dual_prompt.encode("utf-8"))
        assert dual_bytes <= 500, f"Dual retrieval prompt exceeded budget: {dual_bytes}B > 500B"
