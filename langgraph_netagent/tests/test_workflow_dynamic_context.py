"""Comprehensive test suite for Milestone 3: Dynamic Workflow Context Integration & Zero-Hardcoding Refactor.

Validates:
1. OperationalState accepts and stores `discovered_topology`, `scraped_sops`, and `runtime_incident_context`.
2. baseline_ingestion_node parses clos5_dhcp.yml dynamically and populates discovered_topology and inventory_pool.
3. telemetry_extraction_node and classify_anomaly operate purely dynamically on dynamic topology without hardcoded literals.
4. diagnostic_stage2_node retrieves dynamically scraped SOPs via DynamicSOPRetriever and enforces <500B prompt budget.
5. Route remediation dynamically computes next-hop via DiscoveredTopology graph traversal without lookup tables.
6. Zero-hardcoded network values grep check across workflow/operational_nodes.py.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Dict, List
import pytest

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
    OperationalStateModel,
    create_operational_initial_state,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CLOS5_PATH = REPO_ROOT / "clos5_dhcp.yml"


# ==============================================================================
# Test 1: OperationalState Dynamic Fields
# ==============================================================================
class TestOperationalStateDynamicFields:
    """Verifies that OperationalState schema and initial state support dynamic context."""

    def test_initial_state_contains_dynamic_fields(self):
        """Verifies create_operational_initial_state initializes dynamic context fields."""
        state = create_operational_initial_state()
        assert "discovered_topology" in state
        assert state["discovered_topology"] is None

        assert "scraped_sops" in state
        assert state["scraped_sops"] == []

        assert "runtime_incident_context" in state
        assert state["runtime_incident_context"] == {}

    def test_operational_state_model_validation(self):
        """Verifies OperationalStateModel accepts and validates dynamic fields."""
        synth_node = DiscoveredNode(
            name="test-router",
            kind="linux",
            role="router",
            ips=["192.0.2.1/24"],
        )
        synth_topo = DiscoveredTopology(
            name="test-lab",
            nodes={"test-router": synth_node},
        )
        scraped_doc = ScrapedDocResult(
            title="Dynamic SOP Doc",
            vendor="linux",
            commands=[CommandSyntax(command_template="ip route add {prefix} via {gw}")],
            url="https://example.com/doc",
        )

        model = OperationalStateModel(
            discovered_topology=synth_topo,
            scraped_sops=[scraped_doc],
            runtime_incident_context={"incident_id": "INC-12345", "priority": "P1"},
        )

        dumped = model.model_dump()
        assert dumped["discovered_topology"]["name"] == "test-lab"
        assert len(dumped["scraped_sops"]) == 1
        assert dumped["scraped_sops"][0]["title"] == "Dynamic SOP Doc"
        assert dumped["runtime_incident_context"]["incident_id"] == "INC-12345"


# ==============================================================================
# Test 2: Baseline Ingestion Ingests Clos5 Dynamic Topology
# ==============================================================================
class TestBaselineIngestionDynamicTopology:
    """Verifies baseline_ingestion_node ingests clos5_dhcp.yml into discovered_topology."""

    @pytest.fixture
    def mock_llm(self) -> MockLLMProvider:
        config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
        return MockLLMProvider(config=config)

    def test_baseline_ingestion_parses_clos5_dynamic_topology(self, mock_llm: MockLLMProvider):
        """Baseline ingestion parses clos5_dhcp.yml, populating discovered_topology and inventory_pool."""
        assert CLOS5_PATH.exists(), f"clos5_dhcp.yml must exist at {CLOS5_PATH}"

        adapter = MockContainerlabAdapter()
        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=adapter,
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["topology_file"] = str(CLOS5_PATH)
        state["lab_name"] = "clos5"

        result = nodes["baseline_ingestion"](state)

        assert result["status"] == "baseline_ingested"
        disc_topo = result.get("discovered_topology")
        assert disc_topo is not None
        assert disc_topo["name"] == "clos5"

        expected_nodes = {
            "leaf1", "leaf2", "leaf3", "leaf4",
            "spine1", "spine2", "spine3", "spine4",
            "superspine1", "superspine2",
            "dc-egress", "ext-router", "attacker",
            "h1", "h2", "h3", "h4",
            "sflow-rt",
        }
        assert set(disc_topo["nodes"].keys()) == expected_nodes
        assert len(disc_topo["links"]) == 19

        inv_pool = result.get("inventory_pool")
        assert inv_pool is not None
        assert set(inv_pool["assets"]) == expected_nodes

        # Check VIPs and RFC 1918 subnets extracted dynamically without hardcoded fallback
        for vip in ("203.0.113.10", "203.0.113.20", "203.0.113.30", "203.0.113.40"):
            assert vip in disc_topo["vips"]

        # 172.16.x.x subnets must be preserved
        subnets_str = " ".join(inv_pool["subnets"])
        assert "172.16.1.0/24" in subnets_str or "172.16." in subnets_str


# ==============================================================================
# Test 3: Telemetry Extraction & classify_anomaly Purely Dynamic
# ==============================================================================
class TestTelemetryExtractionAndAnomalyClassificationDynamic:
    """Verifies telemetry extraction and anomaly classification operate on dynamic topology."""

    def _build_custom_topology(self) -> DiscoveredTopology:
        """Constructs an arbitrary non-standard topology with custom names and IPs."""
        gw_interfaces = {
            "eth0": DiscoveredInterface(name="eth0", ipv4_addresses=["172.100.100.99/24"]),
            "eth7": DiscoveredInterface(name="eth7", ipv4_addresses=["198.51.100.1/24"]),
            "eth8": DiscoveredInterface(name="eth8", ipv4_addresses=["10.88.1.1/24"]),
        }
        gw_node = DiscoveredNode(
            name="gw-edge-99",
            kind="linux",
            role="router",
            interfaces=gw_interfaces,
            ips=["198.51.100.1/24", "10.88.1.1/24"],
        )

        client_interfaces = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["198.51.100.42/24"]),
        }
        client_node = DiscoveredNode(
            name="client-bot-42",
            kind="linux",
            role="attacker",
            interfaces=client_interfaces,
            ips=["198.51.100.42/24"],
        )

        srv_interfaces = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.88.1.50/24"]),
        }
        srv_node = DiscoveredNode(
            name="app-srv-01",
            kind="linux",
            role="server",
            interfaces=srv_interfaces,
            ips=["10.88.1.50/24"],
        )

        links = [
            DiscoveredLink(
                endpoints=[("client-bot-42", "eth1"), ("gw-edge-99", "eth7")],
                local_node="client-bot-42",
                local_iface="eth1",
                remote_node="gw-edge-99",
                remote_iface="eth7",
            ),
            DiscoveredLink(
                endpoints=[("gw-edge-99", "eth8"), ("app-srv-01", "eth1")],
                local_node="gw-edge-99",
                local_iface="eth8",
                remote_node="app-srv-01",
                remote_iface="eth1",
            ),
        ]

        return DiscoveredTopology(
            name="custom-dyn-lab",
            nodes={
                "gw-edge-99": gw_node,
                "client-bot-42": client_node,
                "app-srv-01": srv_node,
            },
            links=links,
            subnets=["198.51.100.0/24", "10.88.1.0/24"],
            ip_to_node={
                "198.51.100.1": "gw-edge-99",
                "10.88.1.1": "gw-edge-99",
                "198.51.100.42": "client-bot-42",
                "10.88.1.50": "app-srv-01",
            },
            vips=["198.51.200.77"],
            node_roles={
                "gw-edge-99": "egress",
                "client-bot-42": "attacker",
                "app-srv-01": "server",
            },
            routers=["gw-edge-99"],
            hosts=["client-bot-42", "app-srv-01"],
            mgmt_ipv4_subnet="172.100.100.0/24",
        )

    def test_classify_anomaly_with_custom_dynamic_topology(self):
        """classify_anomaly dynamically resolves bottleneck node, interface, offending IP, and VIP."""
        custom_topo = self._build_custom_topology()

        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit on gw-edge-99:eth7"],
            buffer_anomalies=[
                {
                    "node": "gw-edge-99",
                    "interface": "eth7",
                    "dropped": 99,
                    "overlimits": 300,
                }
            ],
            qdisc_stats={
                "gw-edge-99": [
                    QdiscTelemetry(
                        node="gw-edge-99",
                        interface="eth7",
                        qdisc_type="tbf",
                        dropped=99,
                        overlimits=300,
                    )
                ]
            },
        )

        anomaly = classify_anomaly(health_report, discovered_topology=custom_topo)

        assert anomaly.category == "external_overload"
        # Must resolve dynamic values, NOT hardcoded literals ("dc-egress", "eth2", "192.168.100.2", "203.0.113.10")
        assert anomaly.bottleneck_node == "gw-edge-99"
        assert anomaly.bottleneck_interface == "eth7"
        assert anomaly.offending_source_ip == "198.51.100.42"
        assert anomaly.victim_destination_ip == "198.51.200.77"


# ==============================================================================
# Test 4: Stage 2 Dynamic SOP Retrieval & Prompt Budget (<500B)
# ==============================================================================
class TestDiagnosticStage2DynamicSOPRetrieval:
    """Verifies diagnostic_stage2_node retrieves dynamically scraped SOPs within <500B budget."""

    def test_stage2_retrieves_scraped_sops_within_budget(self):
        """Verifies scraped SOPs are ingested into retriever and prompt context conforms to <500B budget."""
        scraped_doc = ScrapedDocResult(
            title="Vendor Traffic Control & Ingress Filtering SOP",
            vendor="linux",
            topic="overload_protection",
            commands=[
                CommandSyntax(
                    command_template="iptables -I INPUT 1 -s {src_ip} -j DROP",
                    syntax="iptables -I INPUT 1 -s <IP> -j DROP",
                    description="Perimeter drop rule",
                    parameters={"src_ip": "Offending client IP"},
                )
            ],
            troubleshooting_steps=[
                TroubleshootingStep(step_number=1, title="Verify drops", verification_commands=["tc -s qdisc show"]),
                TroubleshootingStep(step_number=2, title="Deploy iptables drop filter", remediation_commands=["iptables -I INPUT 1 -s 198.51.100.9 -j DROP"]),
            ],
            url="https://docs.kernel.org/networking/filter.html",
            raw_text_summary="Filter ingress traffic using iptables drop rules.",
        )

        custom_topo = DiscoveredTopology(
            name="dyn-lab",
            nodes={
                "r-edge": DiscoveredNode(name="r-edge", kind="linux", role="router", ips=["198.51.100.1/24"]),
                "c-bad": DiscoveredNode(name="c-bad", kind="linux", role="attacker", ips=["198.51.100.9/24"]),
            },
            links=[],
            subnets=["198.51.100.0/24"],
            vips=["198.51.200.99"],
            node_roles={"r-edge": "router", "c-bad": "attacker"},
            routers=["r-edge"],
            hosts=["c-bad"],
        )

        retriever = DynamicSOPRetriever()

        # Check prompt topology formatter satisfies budget
        topo_prompt = format_dynamic_topology_prompt(custom_topo, max_bytes=500)
        assert len(topo_prompt.encode("utf-8")) <= 500
        assert "r-edge" in topo_prompt
        assert "198.51.200.99" in topo_prompt

        # Verify DynamicSOPRetriever format_sop_markdown satisfies budget
        ingested_sops = retriever.ingest_scraped_result(scraped_doc)
        assert len(ingested_sops) > 0
        retrieved_sops = retriever.retrieve(["linux", "overload", "filter"])
        assert len(retrieved_sops) > 0
        sop_markdown = retriever.format_sop_markdown(retrieved_sops, max_bytes=500)
        assert len(sop_markdown.encode("utf-8")) <= 500

        # Run diagnostic_stage2_node with dynamic context
        config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
        mock_llm = MockLLMProvider(config=config)
        mock_llm.register_canned_response(
            DiagnosticReport(
                telemetry_trigger="Qdisc queue buffer overlimit",
                root_cause="External overload from 198.51.100.9",
                affected_nodes=["r-edge"],
                error_category=ErrorCategory.FIREWALL_FILTER_DROP,
                severity=SeverityLevel.CRITICAL,
                confidence_score=0.95,
            )
        )
        mock_llm.register_canned_response(
            RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity="r-edge",
                exec_commands=["iptables -I INPUT 1 -s 198.51.100.9 -j DROP"],
                rollback_steps=[],
                expected_outcome="Overload mitigated",
            )
        )

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=MockContainerlabAdapter(),
            retriever=retriever,
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["discovered_topology"] = custom_topo.model_dump()
        state["scraped_sops"] = [scraped_doc.model_dump()]
        state["node_kinds"] = {"r-edge": "linux", "c-bad": "linux"}
        state["anomaly_classification"] = {
            "anomaly_type": "external_overload",
            "bottleneck_node": "r-edge",
            "bottleneck_interface": "eth1",
            "offending_source_ip": "198.51.100.9",
            "victim_destination_ip": "198.51.200.99",
            "confidence": 0.95,
        }
        state["discrepancies"] = [
            {
                "node": "r-edge",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth1",
                "description": "Buffer overlimit on r-edge:eth1",
                "suspect_nodes": ["r-edge"],
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "198.51.100.9",
                "destination_ip": "198.51.200.99",
                "protocol": "tcp",
                "destination_port": 80,
                "alert_type": "TRAFFIC_OVERLOAD",
            }
        ]

        result = nodes["diagnostic_stage2"](state)
        assert result["status"] == "stage2_plan_generated"
        assert result["remediation_plan"] is not None
        assert result["remediation_plan"]["target_entity"] == "r-edge"

        # Verify that canonical intents were synthesized dynamically
        canonical_intents = result.get("canonical_intents") or []
        assert len(canonical_intents) > 0
        assert canonical_intents[0]["target_node"] == "r-edge"
        assert canonical_intents[0]["source_ip"] == "198.51.100.9"


# ==============================================================================
# Test 5: Route Remediation Dynamic Next-Hop Calculation
# ==============================================================================
class TestRouteRemediationDynamicNextHop:
    """Verifies route remediation dynamically derives next-hop via DiscoveredTopology graph traversal."""

    def test_route_remediation_computes_dynamic_next_hop(self):
        """Verifies graph BFS next-hop calculation without hardcoded route lookup tables."""
        r1_interfaces = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.55.1.1/24"]),
            "eth2": DiscoveredInterface(name="eth2", ipv4_addresses=["10.55.2.1/24"]),
        }
        r1_node = DiscoveredNode(
            name="r-alpha",
            kind="frr",
            role="router",
            interfaces=r1_interfaces,
            ips=["10.55.1.1/24", "10.55.2.1/24"],
        )

        r2_interfaces = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.55.1.2/24"]),
            "eth3": DiscoveredInterface(name="eth3", ipv4_addresses=["10.99.0.1/24"]),
        }
        r2_node = DiscoveredNode(
            name="r-beta",
            kind="frr",
            role="router",
            interfaces=r2_interfaces,
            ips=["10.55.1.2/24", "10.99.0.1/24"],
        )

        dest_interfaces = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["10.99.0.10/24"]),
        }
        dest_node = DiscoveredNode(
            name="h-dest",
            kind="linux",
            role="server",
            interfaces=dest_interfaces,
            ips=["10.99.0.10/24"],
        )

        links = [
            DiscoveredLink(
                endpoints=[("r-alpha", "eth1"), ("r-beta", "eth1")],
                local_node="r-alpha",
                local_iface="eth1",
                remote_node="r-beta",
                remote_iface="eth1",
            ),
            DiscoveredLink(
                endpoints=[("r-beta", "eth3"), ("h-dest", "eth1")],
                local_node="r-beta",
                local_iface="eth3",
                remote_node="h-dest",
                remote_iface="eth1",
            ),
        ]

        topo = DiscoveredTopology(
            name="dynamic-route-lab",
            nodes={"r-alpha": r1_node, "r-beta": r2_node, "h-dest": dest_node},
            links=links,
            subnets=["10.55.1.0/24", "10.55.2.0/24", "10.99.0.0/24"],
            ip_to_node={
                "10.55.1.1": "r-alpha",
                "10.55.2.1": "r-alpha",
                "10.55.1.2": "r-beta",
                "10.99.0.1": "r-beta",
                "10.99.0.10": "h-dest",
            },
            node_roles={"r-alpha": "router", "r-beta": "router", "h-dest": "server"},
            routers=["r-alpha", "r-beta"],
            hosts=["h-dest"],
        )

        # Graph BFS test: from r-alpha to 10.99.0.10 -> next hop must be 10.55.1.2
        derived_nh = topo.resolve_next_hop("r-alpha", "10.99.0.10")
        assert derived_nh == "10.55.1.2"

        # Verify diagnostic_stage2_node uses this dynamic next-hop
        config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
        mock_llm = MockLLMProvider(config=config)
        mock_llm.register_canned_response(
            DiagnosticReport(
                telemetry_trigger="Ping failure: r-alpha -> 10.99.0.10: 100% loss",
                root_cause="Missing static route to 10.99.0.0/24 on r-alpha",
                affected_nodes=["r-alpha"],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.92,
            )
        )
        mock_llm.register_canned_response(
            RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity="r-alpha",
                exec_commands=["vtysh -c 'configure terminal' -c 'ip route 10.99.0.0/24 10.55.1.2'"],
                rollback_steps=[],
                expected_outcome="Route restored",
            )
        )

        nodes = create_operational_nodes(
            llm_provider=mock_llm,
            lab_adapter=MockContainerlabAdapter(),
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["discovered_topology"] = topo.model_dump()
        state["node_kinds"] = {"r-alpha": "frr", "r-beta": "frr", "h-dest": "linux"}
        state["topology_path"] = ["r-alpha", "r-beta", "h-dest"]
        state["discrepancies"] = [
            {
                "node": "r-alpha",
                "discrepancy_type": "missing_route",
                "affected_interface": "eth1",
                "target_destination": "10.99.0.0/24",
                "description": "Missing static route to 10.99.0.0/24",
                "suspect_nodes": ["r-alpha"],
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "10.55.1.1",
                "destination_ip": "10.99.0.10",
                "protocol": "icmp",
                "alert_type": "PING_DROP",
            }
        ]

        result = nodes["diagnostic_stage2"](state)
        assert result["status"] == "stage2_plan_generated"

        canonical_intents = result.get("canonical_intents") or []
        assert len(canonical_intents) > 0
        restore_intent = canonical_intents[0]
        assert restore_intent["action"] == IntentAction.RESTORE_ROUTE
        assert restore_intent["target_node"] == "r-alpha"  # NOT hardcoded "frr1"
        assert restore_intent["network_prefix"] == "10.99.0.0/24"  # NOT hardcoded "10.2.2.0/24"
        assert restore_intent["next_hop"] == "10.55.1.2"  # NOT hardcoded "10.1.12.2"


# ==============================================================================
# Test 6: Zero-Hardcoded Network Literals Grep Verification
# ==============================================================================
class TestZeroHardcodedGrepAudit:
    """Verifies that operational_nodes.py contains zero hardcoded target literals."""

    def test_no_hardcoded_literals_in_operational_nodes(self):
        """Scans operational_nodes.py source code and asserts 0 matches for target literals."""
        nodes_file = REPO_ROOT / "langgraph_netagent" / "langgraph_netagent" / "workflow" / "operational_nodes.py"
        assert nodes_file.exists(), f"operational_nodes.py not found at {nodes_file}"

        source_code = nodes_file.read_text(encoding="utf-8")

        forbidden_literals = [
            "192.168.100.2",
            "203.0.113.10",
            "10.1.12.2",
            "10.2.2.0/24",
            '"dc-egress"',
            "'dc-egress'",
            '"frr1"',
            "'frr1'",
        ]

        for literal in forbidden_literals:
            matches = [
                (idx + 1, line.strip())
                for idx, line in enumerate(source_code.splitlines())
                if literal in line and not line.strip().startswith("#") and "Test" not in line
            ]
            assert len(matches) == 0, f"Found {len(matches)} hardcoded occurrence(s) of {literal} in operational_nodes.py: {matches}"
