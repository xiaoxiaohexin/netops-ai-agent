"""End-to-End Dynamic Operational Workflow Verification Tests.

Validates:
1. Containerlab small environment (netagent-lab.clab.yml and clos5_dhcp.yml) integration.
2. Dynamic topology ingestion via TopologyDiscoverer without hardcoded lookup tables.
3. Vendor documentation scraping and ingestion via DynamicSOPRetriever / VendorDocScraper.
4. Injection of dynamic topology and scraped documentation into OperationalState.
5. Successful two-stage diagnosis and remediation planning utilizing runtime context.
6. DiagnosticReport and RemediationPlan contain dynamically derived nodes, interfaces, IPs,
   and automated reverse rollback commands.
7. Closed-loop execution: sandbox validation, auto-approval, live hot-patch, and re-verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock
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
from langgraph_netagent.models.intent import IntentAction
from langgraph_netagent.models.operational import (
    AnomalyClassification,
    FiveTuple,
    NetworkDiscrepancy,
)
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.models.telemetry import (
    NetworkHealthReport,
    PingTelemetry,
    QdiscTelemetry,
)
from langgraph_netagent.tools.dynamic_sop_retriever import DynamicSOPRetriever
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import (
    MockContainerlabAdapter,
    RouteEntry,
    VirtualInterface,
    VirtualNode,
)
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer
from langgraph_netagent.tools.vendor_doc_scraper import (
    CommandSyntax,
    ReverseRollbackGenerator,
    ScrapedDocResult,
    TroubleshootingStep,
    VendorDocScraper,
)
from langgraph_netagent.workflow.operational_graph import (
    build_operational_graph,
    run_operational_workflow,
)
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
NETAGENT_LAB_YAML = REPO_ROOT / "clab_output" / "netagent-lab.clab.yml"
CLOS5_YAML = REPO_ROOT / "clos5_dhcp.yml"


# ==============================================================================
# Helper Fixtures: Realistic Scraped Vendor Documentation
# ==============================================================================

def _get_scraped_frr_routing_doc() -> ScrapedDocResult:
    """Simulates authoritative scraped FRR documentation for static routing."""
    return ScrapedDocResult(
        title="FRRouting Static Routing Daemon Guide",
        vendor="frr",
        topic="static_routing",
        commands=[
            CommandSyntax(
                command_template="vtysh -c 'configure terminal' -c 'ip route {prefix} {next_hop}'",
                syntax="ip route NETWORK GATEWAY [distance <(1-255)>]",
                description="Install static route in zebra RIB",
                parameters={"prefix": "Destination network prefix", "next_hop": "Next-hop IP address"},
                mode="vtysh",
                vendor="frr",
            ),
            CommandSyntax(
                command_template="vtysh -c 'show ip route'",
                syntax="show ip route",
                description="Verify installed routes in zebra FIB",
                mode="vtysh",
                vendor="frr",
            ),
        ],
        troubleshooting_steps=[
            TroubleshootingStep(
                step_number=1,
                title="Inspect routing table",
                explanation="Check if destination network is present in FIB",
                verification_commands=["vtysh -c 'show ip route'"],
            ),
            TroubleshootingStep(
                step_number=2,
                title="Apply missing static route",
                explanation="Configure missing route via adjacent gateway interface",
                remediation_commands=["vtysh -c 'configure terminal' -c 'ip route {prefix} {next_hop}'"],
                rollback_commands=["vtysh -c 'configure terminal' -c 'no ip route {prefix} {next_hop}'"],
            ),
        ],
        url="https://docs.frrouting.org/en/latest/static.html",
        raw_text_summary="Configure and verify FRR static routes via vtysh.",
    )


def _get_scraped_linux_overload_doc() -> ScrapedDocResult:
    """Simulates authoritative scraped Linux netfilter documentation for perimeter filtering."""
    return ScrapedDocResult(
        title="Linux Netfilter Perimeter Traffic Filtering SOP",
        vendor="linux",
        topic="overload_protection",
        commands=[
            CommandSyntax(
                command_template="iptables -I INPUT 1 -s {src_ip} -j DROP",
                syntax="iptables -I INPUT 1 -s <IP> -j DROP",
                description="Deploy immediate packet drop rule on input chain",
                parameters={"src_ip": "Offending source IPv4 address"},
                mode="config",
                vendor="linux",
            ),
            CommandSyntax(
                command_template="tc -s qdisc show",
                syntax="tc -s qdisc show [dev <iface>]",
                description="Inspect queue discipline buffer drops and overlimits",
                mode="exec",
                vendor="linux",
            ),
        ],
        troubleshooting_steps=[
            TroubleshootingStep(
                step_number=1,
                title="Verify buffer drops",
                explanation="Monitor tc qdisc counters for drops and overlimits",
                verification_commands=["tc -s qdisc show"],
            ),
            TroubleshootingStep(
                step_number=2,
                title="Deploy ingress filter",
                explanation="Block abusive source IP on edge interface",
                remediation_commands=["iptables -I INPUT 1 -s {src_ip} -j DROP"],
                rollback_commands=["iptables -D INPUT -s {src_ip} -j DROP"],
            ),
        ],
        url="https://docs.kernel.org/networking/filter.html",
        raw_text_summary="Filter anomalous incoming traffic via iptables perimeter drops.",
    )


# ==============================================================================
# Test Suite 1: Netagent-Lab Dynamic E2E Diagnostic
# ==============================================================================

class TestE2ENetagentLabDynamicDiagnostic:
    """Tests dynamic workflow on netagent-lab.clab.yml (pc1 <-> frr1 <-> pc2)."""

    def test_dynamic_topology_ingestion_and_routing_diagnosis(self):
        """Verifies netagent-lab dynamic topology discovery, scraped SOP ingestion, and diagnosis."""
        assert NETAGENT_LAB_YAML.exists(), f"netagent-lab topology missing at {NETAGENT_LAB_YAML}"

        # 1. Discover topology dynamically from YAML
        discoverer = TopologyDiscoverer()
        discovered_topo = discoverer.discover_from_yaml(NETAGENT_LAB_YAML)

        assert discovered_topo.name == "netagent-lab"
        assert set(discovered_topo.nodes.keys()) == {"pc1", "frr1", "pc2"}
        assert len(discovered_topo.links) == 2

        # Verify dynamic IP extraction without static lookup tables
        assert discovered_topo.ip_to_node.get("10.1.1.2") == "pc1"
        assert discovered_topo.ip_to_node.get("10.1.1.1") == "frr1"
        assert discovered_topo.ip_to_node.get("10.2.2.1") == "frr1"
        assert discovered_topo.ip_to_node.get("10.2.2.2") == "pc2"

        # Verify graph BFS next-hop calculation
        nh_to_pc2 = discovered_topo.resolve_next_hop("pc1", "10.2.2.2")
        assert nh_to_pc2 == "10.1.1.1"

        # 2. Ingest scraped vendor documentation
        scraped_frr = _get_scraped_frr_routing_doc()
        retriever = DynamicSOPRetriever()
        ingested_sops = retriever.ingest_scraped_result(scraped_frr)
        assert len(ingested_sops) > 0

        # Verify reverse rollback generation
        cmd_template = scraped_frr.commands[0].command_template
        rollback_cmd = ReverseRollbackGenerator.generate_rollback(cmd_template, vendor="frr")
        assert "no ip route" in rollback_cmd

        # 3. Setup mock adapter and operational nodes
        adapter = MockContainerlabAdapter()
        adapter.deploy(NETAGENT_LAB_YAML)

        config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
        mock_llm = MockLLMProvider(config=config)
        mock_llm.register_canned_response(
            DiagnosticReport(
                telemetry_trigger="Ping loss pc1 -> 10.2.2.2: 100% loss",
                root_cause="Missing static route to 10.2.2.0/24 on frr1",
                affected_nodes=["frr1"],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.95,
            )
        )
        mock_llm.register_canned_response(
            RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity="frr1",
                exec_commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.2.2.1'"],
                rollback_steps=[],
                expected_outcome="Static route installed and connectivity restored",
            )
        )

        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            retriever=retriever,
            auto_approve=True,
        )

        # 4. Construct initial state with dynamic topology and scraped documentation
        state = create_operational_initial_state()
        state["topology_file"] = str(NETAGENT_LAB_YAML)
        state["lab_name"] = "netagent-lab"
        state["discovered_topology"] = discovered_topo.model_dump()
        state["scraped_sops"] = [scraped_frr.model_dump()]
        state["node_kinds"] = {"pc1": "linux", "frr1": "frr", "pc2": "linux"}
        state["topology_path"] = ["pc1", "frr1", "pc2"]
        state["discrepancies"] = [
            {
                "node": "frr1",
                "discrepancy_type": "missing_route",
                "affected_interface": "eth2",
                "target_destination": "10.2.2.0/24",
                "description": "Missing static route for subnet 10.2.2.0/24",
                "suspect_nodes": ["frr1"],
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "10.1.1.2",
                "destination_ip": "10.2.2.2",
                "protocol": "icmp",
                "alert_type": "PING_DROP",
            }
        ]

        # 5. Run baseline ingestion
        ingest_res = nodes["baseline_ingestion"](state)
        assert ingest_res["status"] == "baseline_ingested"
        assert ingest_res["discovered_topology"] is not None
        assert ingest_res["inventory_pool"] is not None
        assert set(ingest_res["inventory_pool"]["assets"]) == {"pc1", "frr1", "pc2"}

        # 6. Run diagnostic stage 1 (read-only inspection & RAG keyword inference)
        state.update(ingest_res)
        stage1_res = nodes["diagnostic_stage1"](state)
        assert stage1_res["status"] == "stage1_enriched"
        rag_kw = stage1_res.get("rag_keywords", [])
        assert any(k in rag_kw for k in ("missing_route", "route", "ping_drop", "frr1", "reachability_loss", "routing_misconfig"))

        # 7. Run diagnostic stage 2 (targeted plan generation with dynamic context)
        state.update(stage1_res)
        stage2_res = nodes["diagnostic_stage2"](state)
        assert stage2_res["status"] == "stage2_plan_generated"

        # Verify DiagnosticReport and RemediationPlan contain dynamically derived values
        remed_plan = stage2_res.get("remediation_plan")
        assert remed_plan is not None
        assert remed_plan["target_entity"] == "frr1"  # Dynamically derived, not hardcoded fallback

        canonical_intents = stage2_res.get("canonical_intents") or []
        assert len(canonical_intents) > 0
        intent = canonical_intents[0]
        assert intent["action"] == IntentAction.RESTORE_ROUTE
        assert intent["target_node"] == "frr1"
        # Next hop resolved dynamically from peer interfaces on frr1 (pc2:eth1 -> 10.2.2.2)
        assert intent["next_hop"] in ("10.2.2.2", "10.1.1.2")

        # Verify rollback steps contain valid reverse rollback commands
        rollback_steps = remed_plan.get("rollback_steps", [])
        assert len(rollback_steps) > 0
        assert any("no ip route" in step.get("payload", "") for step in rollback_steps)


# ==============================================================================
# Test Suite 2: Clos5 Dynamic E2E Diagnostic
# ==============================================================================

class TestE2EClos5DynamicDiagnostic:
    """Tests dynamic workflow on clos5_dhcp.yml (18 nodes, Clos fabric, VIPs)."""

    def test_clos5_dynamic_topology_and_overload_remediation(self):
        """Verifies Clos5 dynamic topology discovery, scraped SOP ingestion, and overload remediation."""
        assert CLOS5_YAML.exists(), f"clos5_dhcp.yml missing at {CLOS5_YAML}"

        # 1. Discover Clos5 topology dynamically
        discoverer = TopologyDiscoverer()
        clos5_topo = discoverer.discover_from_yaml(CLOS5_YAML)

        assert clos5_topo.name == "clos5"
        assert len(clos5_topo.nodes) == 18
        assert len(clos5_topo.links) == 19
        assert len(clos5_topo.vips) == 4
        assert "203.0.113.10" in clos5_topo.vips

        # Verify RFC 1918 subnets preserved without 172.x.x management filtering corruption
        subnets_joined = " ".join(clos5_topo.subnets)
        assert "172.16.1.0/24" in subnets_joined

        # 2. Ingest scraped Linux overload protection SOP
        scraped_linux = _get_scraped_linux_overload_doc()
        retriever = DynamicSOPRetriever()
        retriever.ingest_scraped_result(scraped_linux)

        # Verify rollback generation for iptables
        rule_cmd = "iptables -I INPUT 1 -s 172.16.254.2 -j DROP"
        inv_cmd = ReverseRollbackGenerator.generate_rollback(rule_cmd, vendor="linux")
        assert "iptables -D" in inv_cmd

        # 3. Simulate overload health report and classify anomaly dynamically
        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit on dc-egress:eth2"],
            buffer_anomalies=[
                {
                    "node": "dc-egress",
                    "interface": "eth2",
                    "dropped": 1200,
                    "overlimits": 4500,
                }
            ],
            qdisc_stats={
                "dc-egress": [
                    QdiscTelemetry(
                        node="dc-egress",
                        interface="eth2",
                        qdisc_type="tbf",
                        dropped=1200,
                        overlimits=4500,
                    )
                ]
            },
        )

        anomaly = classify_anomaly(health_report, discovered_topology=clos5_topo)
        assert anomaly.category == "external_overload"
        assert anomaly.bottleneck_node == "dc-egress"
        assert anomaly.bottleneck_interface == "eth2"
        # Victim VIP must be dynamically resolved from clos5_topo.vips
        assert anomaly.victim_destination_ip in clos5_topo.vips

        # 4. Run Stage 2 diagnosis with dynamic topology and scraped documentation
        config = LLMConfig(provider_type="mock", model_name="mock-qwen", max_retries=3)
        mock_llm = MockLLMProvider(config=config)
        mock_llm.register_canned_response(
            DiagnosticReport(
                telemetry_trigger="Qdisc buffer overlimit on dc-egress:eth2",
                root_cause="Volumetric traffic overload targeting VIP 203.0.113.10",
                affected_nodes=["dc-egress"],
                error_category=ErrorCategory.FIREWALL_FILTER_DROP,
                severity=SeverityLevel.CRITICAL,
                confidence_score=0.98,
            )
        )
        mock_llm.register_canned_response(
            RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity="dc-egress",
                exec_commands=["iptables -I INPUT 1 -s 172.16.254.2 -j DROP"],
                rollback_steps=[],
                expected_outcome="Overload mitigated at edge",
            )
        )

        nodes = create_operational_nodes(
            llm_provider=MagicMock(),
            lab_adapter=MockContainerlabAdapter(),
            retriever=retriever,
            auto_approve=True,
        )

        state = create_operational_initial_state()
        state["topology_file"] = str(CLOS5_YAML)
        state["discovered_topology"] = clos5_topo.model_dump()
        state["scraped_sops"] = [scraped_linux.model_dump()]
        state["node_kinds"] = {n: "frr" if any(k in n for k in ("leaf", "spine", "egress")) else "linux" for n in clos5_topo.nodes}
        state["anomaly_classification"] = anomaly.model_dump()
        state["discrepancies"] = [
            {
                "node": "dc-egress",
                "discrepancy_type": "buffer_overlimit",
                "affected_interface": "eth2",
                "description": "Buffer overlimit on dc-egress:eth2",
                "suspect_nodes": ["dc-egress"],
            }
        ]
        state["failure_5tuples"] = [
            {
                "source_ip": "172.16.254.2",
                "destination_ip": "203.0.113.10",
                "protocol": "tcp",
                "destination_port": 80,
                "alert_type": "TRAFFIC_OVERLOAD",
            }
        ]

        stage2_res = nodes["diagnostic_stage2"](state)
        assert stage2_res["status"] == "stage2_plan_generated"

        remed_plan = stage2_res.get("remediation_plan")
        assert remed_plan is not None
        assert remed_plan["target_entity"] == "dc-egress"

        # Canonical intents must be synthesized dynamically from topology
        canonical_intents = stage2_res.get("canonical_intents") or []
        assert len(canonical_intents) > 0
        assert canonical_intents[0]["action"] == IntentAction.DROP_TRAFFIC
        assert canonical_intents[0]["target_node"] == "dc-egress"
        expected_attacker_ip = clos5_topo.nodes["attacker"].ips[0].split("/")[0]
        assert canonical_intents[0]["source_ip"] == expected_attacker_ip

        # Rollback steps must contain reverse rollback commands
        rollback_steps = remed_plan.get("rollback_steps", [])
        assert len(rollback_steps) > 0
        assert any("iptables" in s.get("payload", "") and ("-D" in s.get("payload", "") or "-F" in s.get("payload", "")) for s in rollback_steps)


# ==============================================================================
# Test Suite 3: Closed-Loop Operational Workflow Execution
# ==============================================================================

class TestE2EClosedLoopWorkflowExecution:
    """Tests the complete state machine lifecycle on dynamic Containerlab topologies."""

    def test_full_operational_cycle_with_dynamic_context(self):
        """Executes full operational workflow: Ingestion -> Telemetry -> Diagnosis -> Sandbox -> Approval -> Patch -> Re-verification -> Fixed."""
        # Setup mock topology with edge router and internal server
        adapter = MockContainerlabAdapter()
        g = adapter.mock_engine.graph

        edge_router = VirtualNode(name="edge-gw", kind="linux", image="alpine")
        edge_router.add_interface(VirtualInterface(name="eth1", ip_cidr="198.51.100.1/24"))
        edge_router.add_interface(VirtualInterface(name="eth2", ip_cidr="10.88.0.1/24"))
        g.add_node(edge_router)
        g.register_ip("198.51.100.1/24", "edge-gw", "eth1")
        g.register_ip("10.88.0.1/24", "edge-gw", "eth2")

        srv = VirtualNode(name="app-srv", kind="linux", image="alpine")
        srv.add_interface(VirtualInterface(name="eth1", ip_cidr="10.88.0.10/24"))
        srv.default_gateway = "10.88.0.1"
        g.add_node(srv)
        g.register_ip("10.88.0.10/24", "app-srv", "eth1")

        # Inject buffer overlimit fault rule
        rule = FaultRule(
            fault_type=FaultType.BUFFER_OVERLIMIT,
            target_node="edge-gw",
            target_interface="eth1",
            overlimits=50000,
            dropped=12000,
            source_ip="198.51.100.77",
            dest_port=443,
        )
        adapter.fault_injector.add_rule(rule)

        # Build dynamic topology model
        dyn_topo = DiscoveredTopology(
            name="closed-loop-lab",
            nodes={
                "edge-gw": DiscoveredNode(name="edge-gw", kind="linux", role="egress", ips=["198.51.100.1/24", "10.88.0.1/24"]),
                "app-srv": DiscoveredNode(name="app-srv", kind="linux", role="server", ips=["10.88.0.10/24"]),
            },
            links=[],
            subnets=["198.51.100.0/24", "10.88.0.0/24"],
            ip_to_node={"198.51.100.1": "edge-gw", "10.88.0.1": "edge-gw", "10.88.0.10": "app-srv"},
            vips=["198.51.200.50"],
            node_roles={"edge-gw": "egress", "app-srv": "server"},
            routers=["edge-gw"],
            hosts=["app-srv"],
        )

        scraped_doc = _get_scraped_linux_overload_doc()

        initial_state = create_operational_initial_state(auto_approve=True, max_retries=3)
        initial_state["discovered_topology"] = dyn_topo.model_dump()
        initial_state["scraped_sops"] = [scraped_doc.model_dump()]
        initial_state["node_kinds"] = {"edge-gw": "linux", "app-srv": "linux"}
        initial_state["topology_path"] = ["edge-gw", "app-srv"]

        final_state = run_operational_workflow(
            llm_provider=MagicMock(),
            lab_adapter=adapter,
            auto_approve=True,
            initial_state=initial_state,
        )

        assert final_state["status"] == "fixed"
        assert final_state.get("sandbox_passed") is True
        assert final_state.get("human_approved") is True

        # Verify execution stages traversed
        stages = [log["stage"] for log in final_state.get("execution_logs", [])]
        assert "baseline_ingestion" in stages
        assert "telemetry_extraction" in stages
        assert "diagnostic_stage1" in stages
        assert "diagnostic_stage2" in stages
        assert "sandbox_validation" in stages
        assert "human_approval" in stages
        assert "live_hot_patch" in stages
        assert "re_verification" in stages

        # Verify active fault rule was cleared upon successful live remediation
        assert len(adapter.fault_injector.get_active_rules()) == 0


# ==============================================================================
# Test Suite 4: Dynamic Fallback Prevention
# ==============================================================================

class TestE2EDynamicFallbackPrevention:
    """Verifies that arbitrary unseen node names and IPs are handled purely dynamically."""

    def test_arbitrary_topology_names_prevent_static_fallbacks(self):
        """Verifies that arbitrary node 'alpha-border-99' and IP '198.18.55.99' are preserved without static defaults."""
        synth_topo = DiscoveredTopology(
            name="arbitrary-unseen-lab",
            nodes={
                "alpha-border-99": DiscoveredNode(
                    name="alpha-border-99",
                    kind="linux",
                    role="router",
                    ips=["198.18.55.1/24"],
                ),
                "botnet-client-44": DiscoveredNode(
                    name="botnet-client-44",
                    kind="linux",
                    role="attacker",
                    ips=["198.18.55.99/24"],
                ),
            },
            links=[],
            subnets=["198.18.55.0/24"],
            ip_to_node={"198.18.55.1": "alpha-border-99", "198.18.55.99": "botnet-client-44"},
            vips=["198.18.200.88"],
            node_roles={"alpha-border-99": "egress", "botnet-client-44": "attacker"},
            routers=["alpha-border-99"],
            hosts=["botnet-client-44"],
        )

        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit on alpha-border-99:eth1"],
            buffer_anomalies=[
                {
                    "node": "alpha-border-99",
                    "interface": "eth1",
                    "dropped": 300,
                    "overlimits": 900,
                }
            ],
            qdisc_stats={
                "alpha-border-99": [
                    QdiscTelemetry(
                        node="alpha-border-99",
                        interface="eth1",
                        qdisc_type="tbf",
                        dropped=300,
                        overlimits=900,
                    )
                ]
            },
        )

        anomaly = classify_anomaly(health_report, discovered_topology=synth_topo)
        assert anomaly.bottleneck_node == "alpha-border-99"
        assert anomaly.offending_source_ip == "198.18.55.99"
        assert anomaly.victim_destination_ip == "198.18.200.88"

        # Explicitly confirm no hardcoded values were chosen
        assert anomaly.bottleneck_node != "dc-egress"
        assert anomaly.bottleneck_node != "frr1"
        assert anomaly.offending_source_ip != "192.168.100.2"
        assert anomaly.victim_destination_ip != "203.0.113.10"
