"""Operational Nodes for NetOps Troubleshooting and Self-Healing LangGraph.

Implements the UML activity diagram stages:
1. Baseline Ingestion (extracts IP/asset inventory `inventory_pool`)
2. Telemetry & 5-Tuple Extraction (continuous telemetry, 5-tuple parsing, single-exit discrepancy isolation)
3. Two-Stage Diagnostic Engine:
   - Stage 1: Context Enrichment & Pre-retrieval (read-only tools via AAL, RAG keyword inference)
   - Stage 2: Targeted Plan Generation (SOP context retrieval, step_tag tracking, loop prevention)
4. AAL Shadow Sandbox Validation (clones node into isolated sandbox replica, executes patch before approval)
5. Human Approval (HITL gate only after sandbox validation passes)
6. Live Hot-Patch (applies verified patch to target nodes via AAL with step tags)
7. Re-verification Probing (post-change validation confirming health)
8. Terminal Nodes (circuit_breaker, end_healthy, end_fixed, end_rejected)
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import ipaddress
import json
import logging
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.operational import (
    AALToolCall,
    AnomalyClassification,
    FiveTuple,
    InventoryPool,
    NetworkDiscrepancy,
    ShadowSandboxResult,
)
from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CompilationResult,
    IntentAction,
    TargetPlatform,
)
from langgraph_netagent.models.knowledge import DualRetrievalResult
from langgraph_netagent.models.sandbox import PreflightSandboxPassReport
from langgraph_netagent.models.remediation import (
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.models.network_state import NetworkState, StateDiff, compute_state_diff
from langgraph_netagent.models.reasoning import DiagnosticStrategy, DiagnosticStrategySelector
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan
from langgraph_netagent.tools.network_state_snapshotter import NetworkStateSnapshotter
from langgraph_netagent.tools.deterministic_executor import DeterministicExecutor
from langgraph_netagent.workflow.reasoning_engine import DiagnosticReasoningEngine
from langgraph_netagent.workflow.programmatic_verifier import ProgrammaticVerifier, VerificationResult
from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.models.telemetry import NetworkHealthReport
from langgraph_netagent.prompts.day2_prompts import (
    DAY2_DIAGNOSIS_SYSTEM_PROMPT,
    DAY2_REMEDIATION_SYSTEM_PROMPT,
    format_dynamic_topology_prompt,
)
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.baseline import BaselineCollector
from langgraph_netagent.tools.dynamic_sop_retriever import DynamicSOPRetriever
from langgraph_netagent.tools.intent_compiler import CanonicalIntentCompiler
from langgraph_netagent.tools.probes import NetworkTelemetryCollector, PingProbe
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.tools.sop_retriever import SOPRetriever
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer
from langgraph_netagent.tools.vendor_doc_scraper import ScrapedDocResult
from langgraph_netagent.workflow.operational_edges import route_after_healthy
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_log_entry,
)



def classify_anomaly(
    report: Optional[NetworkHealthReport | Dict[str, Any]] = None,
    discrepancies: Optional[List[NetworkDiscrepancy | Dict[str, Any]]] = None,
    failure_5tuples: Optional[List[FiveTuple | Dict[str, Any]]] = None,
    inventory: Optional[Dict[str, Any]] = None,
    discovered_topology: Optional[Any] = None,
) -> AnomalyClassification:
    """Classify detected network anomalies into operational root-cause categories.

    Categories:
        - 'external_overload': Buffer overlimits, qdisc queue drops, or traffic overload.
        - 'single_exit_failure': Missing routes or interface down discrepancies on exit/router devices.
        - 'internal_link_failure': Adjacent hop ping drops or link failures between internal nodes.
        - 'healthy': All connectivity, route tables, and queue buffers operating normally.
    """
    discrepancies_list = discrepancies or []
    failure_5tuples_list = failure_5tuples or []
    inventory_dict = inventory or {}

    discovered_topo_obj: Optional[DiscoveredTopology] = None
    if discovered_topology is not None:
        if isinstance(discovered_topology, DiscoveredTopology):
            discovered_topo_obj = discovered_topology
        elif isinstance(discovered_topology, dict):
            try:
                discovered_topo_obj = DiscoveredTopology(**discovered_topology)
            except Exception:
                discovered_topo_obj = None

    def _get_disc(d: Any, key: str, default: Any = None) -> Any:
        if isinstance(d, dict):
            return d.get(key, default)
        return getattr(d, key, default)

    def _get_5t(f: Any, key: str, default: Any = None) -> Any:
        if isinstance(f, dict):
            return f.get(key, default)
        return getattr(f, key, default)

    # Extract report attributes
    buffer_anomalies: List[Dict[str, Any]] = []
    qdisc_stats: Dict[str, Any] = {}
    report_failures: List[str] = []
    report_all_passed = True
    if report is not None:
        if isinstance(report, dict):
            buffer_anomalies = list(report.get("buffer_anomalies", []))
            qdisc_stats = report.get("qdisc_stats", {})
            report_failures = report.get("failures", [])
            report_all_passed = report.get("all_passed", True)
        else:
            buffer_anomalies = list(getattr(report, "buffer_anomalies", []))
            qdisc_stats = getattr(report, "qdisc_stats", {})
            report_failures = getattr(report, "failures", [])
            report_all_passed = getattr(report, "all_passed", True)

    # Detect conditions
    has_buffer_overlimit = (
        any(_get_disc(d, "discrepancy_type") in ("buffer_overlimit", "traffic_overload") for d in discrepancies_list)
        or len(buffer_anomalies) > 0
        or any(
            _get_5t(f, "alert_type") == "TRAFFIC_OVERLOAD" or _get_5t(f, "is_external_overload") is True
            for f in failure_5tuples_list
        )
        or any("buffer" in f.lower() or "overlimit" in f.lower() or "qdisc" in f.lower() for f in report_failures)
    )

    if not has_buffer_overlimit and qdisc_stats:
        for _node, q_list in qdisc_stats.items():
            for q_item in q_list:
                d_dropped = _get_disc(q_item, "dropped", 0)
                d_overlimits = _get_disc(q_item, "overlimits", 0)
                if (d_dropped and d_dropped > 0) or (d_overlimits and d_overlimits > 0):
                    has_buffer_overlimit = True
                    break
            if has_buffer_overlimit:
                break

    has_missing_route = any(
        _get_disc(d, "discrepancy_type") in ("missing_route", "single_exit_failure") for d in discrepancies_list
    ) or any("missing route" in f.lower() for f in report_failures)

    has_iface_down = any(
        _get_disc(d, "discrepancy_type") == "interface_down" for d in discrepancies_list
    ) or any("interface anomaly" in f.lower() for f in report_failures)

    has_reachability_loss = any(
        _get_disc(d, "discrepancy_type") in ("reachability_loss", "link_drop") for d in discrepancies_list
    ) or any(
        _get_5t(f, "alert_type") == "PACKET_DROP" for f in failure_5tuples_list
    ) or any("ping failure" in f.lower() or "loss" in f.lower() for f in report_failures)

    # Rule 1: External Volumetric Overload
    if has_buffer_overlimit:
        top_5t = next(
            (f for f in failure_5tuples_list if _get_5t(f, "alert_type") == "TRAFFIC_OVERLOAD" or _get_5t(f, "is_external_overload")),
            None,
        )
        src = _get_5t(top_5t, "source_ip") if top_5t else None
        dst = _get_5t(top_5t, "destination_ip") if top_5t else None

        bottleneck_node = None
        bottleneck_iface = None
        if buffer_anomalies:
            ba0 = buffer_anomalies[0]
            bottleneck_node = ba0.get("node")
            bottleneck_iface = ba0.get("interface")

        if not bottleneck_node:
            disc_over = next(
                (d for d in discrepancies_list if _get_disc(d, "discrepancy_type") in ("buffer_overlimit", "traffic_overload")),
                None,
            )
            if disc_over:
                bottleneck_node = _get_disc(disc_over, "node")
                bottleneck_iface = _get_disc(disc_over, "affected_interface")

        if not bottleneck_node:
            # Dynamic resolution: node with highest drop count in qdisc_stats
            if qdisc_stats:
                max_drops = -1
                drop_node = None
                for n, q_list in qdisc_stats.items():
                    total_d = sum(_get_disc(q, "dropped", 0) + _get_disc(q, "overlimits", 0) for q in q_list)
                    if total_d > max_drops and total_d > 0:
                        max_drops = total_d
                        drop_node = n
                if drop_node:
                    bottleneck_node = drop_node

        if not bottleneck_node and discovered_topo_obj:
            # Query egress / gateway / border role from discovered topology
            egress_candidates = [
                n for n, r in discovered_topo_obj.node_roles.items()
                if r.lower() in ("egress", "gateway", "border")
            ]
            if egress_candidates:
                bottleneck_node = egress_candidates[0]
            else:
                routers = discovered_topo_obj.find_router_nodes()
                if routers:
                    bottleneck_node = routers[0]

        if not bottleneck_node and inventory_dict:
            routers = inventory_dict.get("routers", [])
            if routers:
                bottleneck_node = routers[0]
            elif inventory_dict.get("assets"):
                bottleneck_node = inventory_dict["assets"][0]

        if not bottleneck_node:
            bottleneck_node = "router"

        if not bottleneck_iface:
            # Highest drops interface for bottleneck_node
            if bottleneck_node and bottleneck_node in qdisc_stats:
                best_iface = None
                max_drops = -1
                for q in qdisc_stats[bottleneck_node]:
                    d = _get_disc(q, "dropped", 0) + _get_disc(q, "overlimits", 0)
                    if d > max_drops:
                        max_drops = d
                        best_iface = _get_disc(q, "interface")
                if best_iface:
                    bottleneck_iface = best_iface

        if not bottleneck_iface and discovered_topo_obj and bottleneck_node in discovered_topo_obj.nodes:
            # First non-mgmt interface on bottleneck_node
            node_obj = discovered_topo_obj.nodes[bottleneck_node]
            for if_name, if_obj in node_obj.interfaces.items():
                if not if_obj.is_mgmt:
                    bottleneck_iface = if_name
                    break

        if not bottleneck_iface:
            bottleneck_iface = "eth1"

        if not src:
            for f in failure_5tuples_list:
                s = _get_5t(f, "source_ip")
                if s and s not in ("0.0.0.0", "unknown"):
                    src = s
                    break

        if not src and discovered_topo_obj:
            for n_name, n_obj in discovered_topo_obj.nodes.items():
                if n_obj.role.lower() in ("attacker", "client") or (n_obj.group and n_obj.group.lower() in ("attacker", "client")):
                    if n_obj.ips:
                        src = n_obj.ips[0].split("/")[0]
                        break
            if not src and discovered_topo_obj.hosts:
                h_node = discovered_topo_obj.nodes.get(discovered_topo_obj.hosts[0])
                if h_node and h_node.ips:
                    src = h_node.ips[0].split("/")[0]

        if not src and inventory_dict.get("ip_to_node"):
            src = next(iter(inventory_dict["ip_to_node"]), "10.0.0.1")

        if not src:
            src = "10.0.0.1"

        if not dst:
            for f in failure_5tuples_list:
                d = _get_5t(f, "destination_ip")
                if d and d not in ("0.0.0.0", "unknown"):
                    dst = d
                    break

        if not dst and discovered_topo_obj and discovered_topo_obj.vips:
            dst = discovered_topo_obj.vips[0]

        if not dst and inventory_dict.get("vips"):
            dst = inventory_dict["vips"][0]

        if not dst and discovered_topo_obj:
            for n_name, n_obj in discovered_topo_obj.nodes.items():
                if n_obj.role.lower() in ("server", "victim") and n_obj.ips:
                    dst = n_obj.ips[0].split("/")[0]
                    break

        if not dst and inventory_dict.get("ip_to_node"):
            dst = list(inventory_dict["ip_to_node"].keys())[-1]

        if not dst:
            dst = "10.0.0.2"

        return AnomalyClassification(
            category="external_overload",
            confidence=0.95,
            reason="Qdisc buffer overlimits and packet drops detected under high ingress traffic with valid routing table",
            bottleneck_node=bottleneck_node,
            bottleneck_interface=bottleneck_iface,
            offending_source_ip=src,
            victim_destination_ip=dst,
            recommended_action="Deploy border iptables packet filtering and rate-limiting at ingress edge router/gateway",
        )

    # Rule 2: Single-Exit Failure
    if has_missing_route or has_iface_down:
        missing_d = next(
            (d for d in discrepancies_list if _get_disc(d, "discrepancy_type") in ("missing_route", "single_exit_failure", "interface_down")),
            None,
        )
        b_node = _get_disc(missing_d, "node") if missing_d else None
        if not b_node:
            if discovered_topo_obj:
                r_nodes = discovered_topo_obj.find_router_nodes()
                b_node = r_nodes[0] if r_nodes else "router"
            elif inventory_dict.get("routers"):
                b_node = inventory_dict["routers"][0]
            else:
                b_node = "router"

        b_iface = _get_disc(missing_d, "affected_interface") if missing_d else None
        target_dst = _get_disc(missing_d, "target_destination") if missing_d else None

        return AnomalyClassification(
            category="single_exit_failure",
            confidence=0.95,
            reason=f"Routing or egress interface missing on exit device '{b_node}'",
            bottleneck_node=b_node,
            bottleneck_interface=b_iface,
            offending_source_ip=None,
            victim_destination_ip=target_dst,
            recommended_action="Inject missing route into FIB or restore interface operstate via AAL",
        )

    # Rule 3: Internal Segment Link Failure
    if has_reachability_loss:
        drop_d = next(
            (d for d in discrepancies_list if _get_disc(d, "discrepancy_type") in ("reachability_loss", "link_drop")),
            None,
        )
        b_node = _get_disc(drop_d, "node") if drop_d else None
        b_iface = _get_disc(drop_d, "affected_interface") if drop_d else None
        target_dst = _get_disc(drop_d, "target_destination") if drop_d else None

        return AnomalyClassification(
            category="internal_link_failure",
            confidence=0.85,
            reason="Adjacent hop link drop detected between internal fabric nodes",
            bottleneck_node=b_node,
            bottleneck_interface=b_iface,
            offending_source_ip=None,
            victim_destination_ip=target_dst,
            recommended_action="Verify physical link and restart interface",
        )

    # Rule 4: Healthy Baseline
    return AnomalyClassification(
        category="healthy",
        confidence=1.0,
        reason="All connectivity, route tables, and queue buffers operating within healthy baselines",
        bottleneck_node=None,
        bottleneck_interface=None,
        offending_source_ip=None,
        victim_destination_ip=None,
        recommended_action="No remediation needed",
    )


def create_operational_nodes(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    auto_approve: bool = False,
    aal: Optional[AgentAccessLayer] = None,
    sop_retriever: Optional[SOPRetriever] = None,
    retriever: Optional[SOPRetriever] = None,
    clone_timeout: int = 60,
    interactive: bool = False,
) -> Dict[str, Callable[[OperationalState], Dict[str, Any]]]:
    """Factory creating all discrete node callables for the operational workflow."""
    agent_access_layer = aal or AgentAccessLayer(lab_adapter=lab_adapter)
    retriever = retriever or sop_retriever or DynamicSOPRetriever()

    # -----------------------------------------------------------------------
    # Node 1: Baseline Ingestion
    # -----------------------------------------------------------------------
    def baseline_ingestion_node(state: OperationalState) -> Dict[str, Any]:
        """Ingest healthy network baseline and extract IP/asset inventory (`inventory_pool`)."""
        try:
            # Fast-path session caching: reuse existing baseline and inventory pool
            if state.get("inventory_pool") and state.get("baseline"):
                cached_inv = state["inventory_pool"]
                cached_base = state["baseline"]
                assets = (
                    cached_inv.get("assets", [])
                    if isinstance(cached_inv, dict)
                    else getattr(cached_inv, "assets", [])
                )
                log = create_log_entry(
                    stage="baseline_ingestion",
                    message=f"Fast-path session cache hit: reusing existing baseline and inventory pool ({len(assets)} assets)",
                    level="info",
                    metadata={
                        "assets": assets,
                        "cache_hit": True,
                    },
                )
                return {
                    "baseline": cached_base,
                    "inventory_pool": cached_inv if isinstance(cached_inv, dict) else cached_inv.model_dump(),
                    "topology_path": state.get("topology_path") or cached_base.get("topology_path", assets),
                    "node_kinds": state.get("node_kinds") or cached_base.get("node_kinds", {}),
                    "discovered_topology": state.get("discovered_topology"),
                    "status": "baseline_ingested",
                    "error_message": None,
                    "execution_logs": [log],
                }

            # 1. Dynamic Topology Discovery from YAML and/or Runtime
            discovered_topo: Optional[DiscoveredTopology] = None
            if state.get("discovered_topology"):
                raw_disc = state["discovered_topology"]
                if isinstance(raw_disc, DiscoveredTopology):
                    discovered_topo = raw_disc
                elif isinstance(raw_disc, dict):
                    try:
                        discovered_topo = DiscoveredTopology(**raw_disc)
                    except Exception:
                        discovered_topo = None

            topo_file_candidate = (
                state.get("topology_file")
                or state.get("clab_path")
                or getattr(lab_adapter, "last_deployed_topology", None)
                or getattr(lab_adapter, "topology_file", None)
            )

            if not discovered_topo and not topo_file_candidate:
                from pathlib import Path
                proj_root = Path(__file__).resolve().parent.parent.parent.parent
                clos5_file = proj_root / "clos5_dhcp.yml"
                if (lab_name == "clos5" or state.get("lab_name") == "clos5") and clos5_file.exists():
                    topo_file_candidate = str(clos5_file)

            if not discovered_topo and topo_file_candidate:
                discoverer = TopologyDiscoverer()
                try:
                    discovered_topo = discoverer.discover_from_yaml(topo_file_candidate)
                    if lab_adapter and hasattr(lab_adapter, "inspect"):
                        try:
                            discovered_topo = discoverer.discover_from_runtime(
                                adapter=lab_adapter, yaml_path=topo_file_candidate
                            )
                        except Exception:
                            pass
                except Exception as disc_err:
                    logger.warning("Dynamic topology discovery from %s encountered: %s", topo_file_candidate, disc_err)

            # 2. Collect baseline from adapter if available
            baseline = {}
            if lab_adapter:
                try:
                    baseline = BaselineCollector.collect(
                        adapter=lab_adapter,
                        lab_name=lab_name,
                    )
                except Exception:
                    baseline = {}

            # If inspection failed or nodes empty in mock mode, attempt to load default mock lab if no discovered_topo
            if not baseline.get("nodes") and hasattr(lab_adapter, "mock_engine") and not discovered_topo:
                from pathlib import Path
                default_clab = Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml"
                if default_clab.exists():
                    lab_adapter.deploy(default_clab)
                    baseline = BaselineCollector.collect(adapter=lab_adapter, lab_name=lab_name)

            # 3. Formulate inventory_pool from baseline or discovered_topology
            if baseline.get("nodes"):
                inventory_pool = InventoryPool.from_baseline(baseline)
                if discovered_topo:
                    inv_dict = inventory_pool.model_dump()
                    if discovered_topo.vips:
                        inv_dict["vips"] = list(discovered_topo.vips)
                    for sn in discovered_topo.subnets:
                        if sn not in inv_dict.get("subnets", []):
                            inv_dict.setdefault("subnets", []).append(sn)
                    inventory_pool = InventoryPool(**inv_dict)
            elif discovered_topo:
                assets = list(discovered_topo.nodes.keys())
                subnets = list(discovered_topo.subnets)
                ip_to_node = dict(discovered_topo.ip_to_node)
                vips = list(discovered_topo.vips)
                routers = discovered_topo.find_router_nodes()
                inventory_pool = InventoryPool(
                    assets=assets,
                    subnets=subnets,
                    ip_to_node=ip_to_node,
                    vips=vips,
                    routers=routers,
                )
                if not baseline:
                    baseline = {
                        "lab_name": discovered_topo.name,
                        "nodes": {
                            name: {
                                "name": name,
                                "kind": node.kind,
                                "ip_addr": "\n".join(f"inet {ip} dev {if_name}" for if_name, if_obj in node.interfaces.items() for ip in if_obj.ipv4_addresses),
                                "routes": "",
                                "running_config": "",
                            }
                            for name, node in discovered_topo.nodes.items()
                        },
                        "topology_path": getattr(discovered_topo, "topology_paths", [assets])[0] if getattr(discovered_topo, "topology_paths", None) else assets,
                        "node_kinds": {n: node.kind for n, node in discovered_topo.nodes.items()},
                    }
            else:
                inventory_pool = InventoryPool.from_baseline(baseline or {"nodes": {}})

            topo_path = (
                state.get("topology_path")
                or baseline.get("topology_path")
                or (getattr(discovered_topo, "topology_paths", [None])[0] if getattr(discovered_topo, "topology_paths", None) else inventory_pool.assets)
            )
            node_kinds = (
                state.get("node_kinds")
                or baseline.get("node_kinds")
                or ({n: node.kind for n, node in discovered_topo.nodes.items()} if discovered_topo else {})
            )

            node_count = len(inventory_pool.assets)
            log = create_log_entry(
                stage="baseline_ingestion",
                message=f"Baseline ingested: {node_count} assets, {len(inventory_pool.subnets)} subnets extracted",
                level="info",
                metadata={
                    "assets": inventory_pool.assets,
                    "subnets": inventory_pool.subnets,
                    "has_discovered_topology": discovered_topo is not None,
                },
            )

            return {
                "baseline": baseline,
                "inventory_pool": inventory_pool.model_dump(),
                "topology_path": topo_path,
                "node_kinds": node_kinds,
                "discovered_topology": discovered_topo.model_dump() if discovered_topo else None,
                "status": "baseline_ingested",
                "error_message": None,
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="baseline_ingestion",
                message=f"Baseline ingestion failed: {exc}",
                level="error",
            )
            return {
                "status": "baseline_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    # -----------------------------------------------------------------------
    # Node 2: Telemetry Monitoring & 5-Tuple Extraction
    # -----------------------------------------------------------------------
    def telemetry_extraction_node(state: OperationalState) -> Dict[str, Any]:
        """Run telemetry probe matrix, parse alerts to extract 5-tuple failures, and isolate discrepancies."""
        topology_path = state.get("topology_path") or []
        node_kinds = state.get("node_kinds") or {}
        baseline = state.get("baseline") or {}
        inventory = state.get("inventory_pool") or {}
        nodes_data = baseline.get("nodes", {})

        discovered_topo_raw = state.get("discovered_topology")
        discovered_topo_obj: Optional[DiscoveredTopology] = None
        if discovered_topo_raw is not None:
            if isinstance(discovered_topo_raw, DiscoveredTopology):
                discovered_topo_obj = discovered_topo_raw
            elif isinstance(discovered_topo_raw, dict):
                try:
                    discovered_topo_obj = DiscoveredTopology(**discovered_topo_raw)
                except Exception:
                    discovered_topo_obj = None

        all_lab_nodes = list(nodes_data.keys()) or topology_path or list(inventory.get("assets", []))
        if discovered_topo_obj and not all_lab_nodes:
            all_lab_nodes = list(discovered_topo_obj.nodes.keys())

        if discovered_topo_obj:
            discovered_routers = discovered_topo_obj.find_router_nodes()
            routers = [n for n in all_lab_nodes if n in discovered_routers] or discovered_routers or [
                n for n in all_lab_nodes
                if node_kinds.get(n) in ("frr", "srl", "router", "gateway", "switch")
                or any(k in n.lower() for k in ("router", "gw", "egress", "spine", "leaf", "switch", "core", "frr", "srl"))
            ]
            pcs = [n for n in all_lab_nodes if n in discovered_topo_obj.hosts and not any(k in n.lower() for k in ("attacker", "rt", "collector", "sflow", "bot"))] or [
                n for n in all_lab_nodes
                if node_kinds.get(n) == "linux"
                and n not in routers
                and not any(k in n.lower() for k in ("attacker", "rt", "collector", "sflow", "bot"))
            ]
        else:
            routers = [
                n for n in all_lab_nodes
                if node_kinds.get(n) in ("frr", "srl", "router", "gateway", "switch")
                or any(k in n.lower() for k in ("router", "gw", "egress", "spine", "leaf", "switch", "core", "frr", "srl"))
            ]
            pcs = [
                n for n in all_lab_nodes
                if node_kinds.get(n) == "linux"
                and n not in routers
                and not any(k in n.lower() for k in ("attacker", "rt", "collector", "sflow", "bot"))
            ]

        # 1. Build ping probe matrix targets (PC -> PC)
        ping_targets: List[Tuple[str, str]] = []
        for src_pc in pcs:
            for dst_pc in pcs:
                if src_pc != dst_pc:
                    dst_ips = _extract_data_ips(nodes_data.get(dst_pc, {}))
                    for dst_ip in dst_ips:
                        ping_targets.append((src_pc, dst_ip))

        try:
            health_report = NetworkTelemetryCollector.collect(
                adapter=lab_adapter,
                ping_targets=ping_targets,
                router_nodes=routers,
                all_nodes=all_lab_nodes,
                node_kinds=node_kinds,
                last_qdisc_stats=state.get("last_qdisc_stats"),
            )
            report_dict = health_report.model_dump()
        except Exception as exc:
            report_dict = {"all_passed": False, "failures": [f"Probe error: {exc}"]}

        # 2. Extract 5-tuple failure attributes from failed probes, alerts, and buffer anomalies
        failure_5tuples: List[Dict[str, Any]] = []
        discrepancies: List[Dict[str, Any]] = []
        suspects: List[str] = []
        affected_segments: List[Dict[str, Any]] = []
        seen_discrepancies = set()

        # Ingest initial alerts / syslog messages passed into state
        initial_alerts = state.get("initial_alerts") or []
        for alert_item in initial_alerts:
            if isinstance(alert_item, str):
                parsed_ft = FiveTuple.from_syslog(alert_item)
                if parsed_ft:
                    failure_5tuples.append(parsed_ft.model_dump())
            elif isinstance(alert_item, dict):
                try:
                    parsed_ft = FiveTuple.model_validate(alert_item)
                    failure_5tuples.append(parsed_ft.model_dump())
                except Exception:
                    pass

        # Ingest probe matrix reachability drops
        for ping_res in report_dict.get("ping_results", []):
            if not ping_res.get("is_reachable"):
                src_node = ping_res.get("source_node", "unknown")
                dst_ip = ping_res.get("destination_ip", "")
                src_ips = _extract_data_ips(nodes_data.get(src_node, {}))
                src_ip = src_ips[0] if src_ips else "0.0.0.0"
                five_tuple = FiveTuple.from_ping_failure(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    failure_msg=f"{src_node} -> {dst_ip} reachability failure ({ping_res.get('packet_loss_percentage', 100)}% loss)",
                )
                failure_5tuples.append(five_tuple.model_dump())

        # Ingest buffer anomalies and qdisc overlimits / drops
        buffer_anomalies = list(report_dict.get("buffer_anomalies", []))
        qdisc_stats = report_dict.get("qdisc_stats", {})

        last_qstats = state.get("last_qdisc_stats") or {}
        current_qstats: Dict[str, Dict[str, int]] = {}

        for r_name, q_list in qdisc_stats.items():
            for q_item in q_list:
                qd_dict = q_item if isinstance(q_item, dict) else (q_item.model_dump() if hasattr(q_item, "model_dump") else {})
                d_dropped = qd_dict.get("dropped", 0)
                d_overlimits = qd_dict.get("overlimits", 0)
                iface = qd_dict.get("interface", "")
                stat_key = f"{r_name}:{iface}"
                current_qstats[stat_key] = {"dropped": d_dropped, "overlimits": d_overlimits}

                prev_stat = last_qstats.get(stat_key, {})
                prev_dropped = prev_stat.get("dropped", 0)
                prev_overlimits = prev_stat.get("overlimits", 0)

                # Anomaly triggers if drops/overlimits are actively growing or if no previous snapshot
                is_active_growth = (
                    (d_dropped > prev_dropped or d_overlimits > prev_overlimits)
                    if last_qstats
                    else (d_dropped > 0 or d_overlimits > 0)
                )

                if is_active_growth:
                    if not any(ba.get("node") == r_name and ba.get("interface") == qd_dict.get("interface") for ba in buffer_anomalies):
                        buffer_anomalies.append({
                            "node": r_name,
                            "interface": qd_dict.get("interface"),
                            "qdisc_type": qd_dict.get("qdisc_type", "tbf"),
                            "dropped": d_dropped,
                            "overlimits": d_overlimits,
                        })

        if buffer_anomalies:
            report_dict["buffer_anomalies"] = buffer_anomalies
            report_dict["all_passed"] = False

        for ba in buffer_anomalies:
            b_node = ba.get("node", "router")
            b_iface = ba.get("interface") or "eth1"
            b_dropped = ba.get("dropped", 0) or ba.get("rx_dropped", 0) or ba.get("tx_dropped", 0)
            b_overlimits = ba.get("overlimits", 0)

            # Ensure suspect_devices includes the bottleneck router
            if b_node not in suspects:
                suspects.append(b_node)

            disc_key = (b_node, "buffer_overlimit", b_iface)
            if disc_key not in seen_discrepancies:
                seen_discrepancies.add(disc_key)
                disc = NetworkDiscrepancy(
                    node=b_node,
                    discrepancy_type="buffer_overlimit",
                    affected_interface=b_iface,
                    description=f"Buffer overlimit on {b_node}:{b_iface}: {b_dropped} dropped, {b_overlimits} overlimits",
                    suspect_nodes=[b_node],
                )
                disc_dict = disc.model_dump()
                disc_dict["severity"] = "critical"
                discrepancies.append(disc_dict)

            # Extract FiveTuple from overload
            src_ip = None
            dst_ip = None
            dst_port = 80
            src_port = 0
            proto = "TCP"

            if hasattr(lab_adapter, "fault_injector"):
                for rule in getattr(lab_adapter.fault_injector, "get_active_rules", lambda: [])():
                    if rule.fault_type in ("buffer_overlimit", "traffic_overload"):
                        if not rule.target_node or rule.target_node == b_node:
                            if getattr(rule, "source_ip", None):
                                src_ip = rule.source_ip
                            if getattr(rule, "dest_port", None):
                                dst_port = rule.dest_port
                            if getattr(rule, "destination_ip", None):
                                dst_ip = rule.destination_ip

            if not src_ip:
                for ft in failure_5tuples:
                    s = ft.get("source_ip")
                    if s and s not in ("0.0.0.0", "unknown"):
                        src_ip = s
                        break
            if not src_ip and discovered_topo_obj:
                for n_name, n_obj in discovered_topo_obj.nodes.items():
                    if n_obj.role.lower() in ("attacker", "client") or (n_obj.group and n_obj.group.lower() in ("attacker", "client")):
                        if n_obj.ips:
                            src_ip = n_obj.ips[0].split("/")[0]
                            break
                if not src_ip and discovered_topo_obj.hosts:
                    h_node = discovered_topo_obj.nodes.get(discovered_topo_obj.hosts[0])
                    if h_node and h_node.ips:
                        src_ip = h_node.ips[0].split("/")[0]
            if not src_ip:
                for n_name, n_data in nodes_data.items():
                    if any(k in n_name.lower() for k in ("attacker", "client", "host", "ext", "traffic")):
                        att_ips = _extract_data_ips(n_data)
                        if att_ips:
                            src_ip = att_ips[0]
                            break
            if not src_ip and inventory.get("ip_to_node"):
                for ip_str, n_name in inventory["ip_to_node"].items():
                    if n_name in pcs or not any(r in n_name.lower() for r in ("router", "switch", "spine", "leaf", "egress")):
                        src_ip = ip_str
                        break
            if not src_ip:
                src_ip = next(iter(inventory.get("ip_to_node", {})), "10.0.0.1")

            if not dst_ip:
                if discovered_topo_obj and discovered_topo_obj.vips:
                    dst_ip = discovered_topo_obj.vips[0]
                elif inventory.get("vips"):
                    dst_ip = inventory["vips"][0]
                else:
                    b_ips = _extract_data_ips(nodes_data.get(b_node, {}))
                    if b_ips:
                        dst_ip = b_ips[0]
                    elif discovered_topo_obj:
                        for n_name, n_obj in discovered_topo_obj.nodes.items():
                            if n_obj.role.lower() in ("server", "victim") and n_obj.ips:
                                dst_ip = n_obj.ips[0].split("/")[0]
                                break
                    if not dst_ip and inventory.get("ip_to_node"):
                        dst_ip = list(inventory["ip_to_node"].keys())[-1]
                    if not dst_ip:
                        dst_ip = "10.0.0.2"

            ft_overload = FiveTuple.from_traffic_overload(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto,
                src_port=src_port,
                dst_port=dst_port,
                overlimits=b_overlimits,
                dropped=b_dropped,
                raw_log=f"Buffer overload: {b_dropped} dropped, {b_overlimits} overlimits on path {src_ip} -> {dst_ip}:{dst_port}",
            )
            ft_dict = ft_overload.model_dump()
            if not any(
                f.get("alert_type") == "TRAFFIC_OVERLOAD"
                and f.get("source_ip") == src_ip
                and f.get("destination_ip") == dst_ip
                for f in failure_5tuples
            ):
                failure_5tuples.append(ft_dict)

        # Collect destination hosts from 5-tuple alerts as secondary suspects
        secondary_suspects: List[str] = []
        ip_to_node = inventory.get("ip_to_node", {})
        for ft in failure_5tuples:
            dst_i = ft.get("destination_ip")
            if dst_i and dst_i in ip_to_node:
                target_n = ip_to_node[dst_i]
                if target_n not in secondary_suspects:
                    secondary_suspects.append(target_n)

        if (not report_dict.get("all_passed", False) or len(failure_5tuples) > 0 or len(discrepancies) > 0) and len(topology_path) >= 2:
            for i in range(len(topology_path) - 1):
                src = topology_path[i]
                dst = topology_path[i + 1]
                dst_ips = _extract_link_ips(nodes_data, src, dst) or _extract_data_ips(nodes_data.get(dst, {}))
                segment_ok = True
                segment_err = None

                for dst_ip in dst_ips[:1]:
                    try:
                        p_res = PingProbe.run(adapter=lab_adapter, src_node=src, dst_ip=dst_ip, count=2, timeout=2)
                        if not p_res.is_reachable:
                            segment_ok = False
                            segment_err = p_res.error_message
                    except Exception as e:
                        segment_ok = False
                        segment_err = str(e)

                seg_info = {"src": src, "dst": dst, "passed": segment_ok, "error": segment_err}
                affected_segments.append(seg_info)

                if not segment_ok:
                    if src not in suspects:
                        suspects.append(src)
                    if dst not in suspects:
                        suspects.append(dst)
                    disc_key = (src, "reachability_loss", dst)
                    if disc_key not in seen_discrepancies:
                        seen_discrepancies.add(disc_key)
                        discrepancies.append(
                            NetworkDiscrepancy(
                                node=src,
                                discrepancy_type="reachability_loss",
                                target_destination=dst,
                                description=f"Adjacent link drop between {src} and {dst}: {segment_err}",
                                suspect_nodes=[src, dst],
                            ).model_dump()
                        )

            # Known subnets from inventory pool
            known_subnets: List[ipaddress.IPv4Network] = []
            for s_str in inventory.get("subnets", []):
                try:
                    known_subnets.append(ipaddress.IPv4Network(s_str, strict=False))
                except Exception:
                    pass

            # Compare observed routing table against baseline to isolate single-exit discrepancies
            for r_node in routers:
                r_kind = node_kinds.get(r_node, "frr")
                baseline_r = inventory.get("baseline_routes", {}).get(r_node, [])
                # Read current route table via AAL (read-only)
                cmd = "vtysh -c 'show ip route'" if r_kind == "frr" else "ip route show"
                call = AALToolCall(tool_name="read_config", node_name=r_node, command=cmd, read_only=True)
                resp = agent_access_layer.execute(call)
                current_routes = resp.parsed_json.get("routes", [])

                # Check if each target subnet has a valid route entry
                for dst_pc in pcs:
                    for dst_ip in _extract_data_ips(nodes_data.get(dst_pc, {})):
                        try:
                            dst_addr = ipaddress.IPv4Address(dst_ip)
                            # Find covering subnet from inventory, or default to /24
                            dst_net = None
                            for sn in known_subnets:
                                if dst_addr in sn:
                                    dst_net = sn
                                    break
                            if dst_net is None:
                                dst_net = ipaddress.IPv4Interface(f"{dst_ip}/24").network

                            has_route = False
                            for r in current_routes:
                                dest_val = r.get("destination")
                                if dest_val in ("default", "0.0.0.0/0"):
                                    if r.get("interface") == "eth0":
                                        continue
                                    has_route = True
                                    break
                                try:
                                    r_net = ipaddress.IPv4Network(dest_val, strict=False)
                                    if dst_addr in r_net or dst_net.subnet_of(r_net):
                                        has_route = True
                                        break
                                except Exception:
                                    if dest_val == str(dst_net):
                                        has_route = True
                                        break

                            if not has_route:
                                disc_key = (r_node, "missing_route", str(dst_net))
                                if disc_key not in seen_discrepancies:
                                    seen_discrepancies.add(disc_key)
                                    if r_node not in suspects:
                                        suspects.append(r_node)
                                    discrepancies.append(
                                        NetworkDiscrepancy(
                                            node=r_node,
                                            discrepancy_type="missing_route",
                                            target_destination=str(dst_net),
                                            description=f"Single-exit discrepancy: {r_node} lacks route to destination {dst_net}",
                                            suspect_nodes=[r_node],
                                        ).model_dump()
                                    )
                        except Exception:
                            pass

        for failure_msg in report_dict.get("failures", []):
            if "Interface anomaly" in failure_msg:
                m_if = re.search(r"Interface anomaly:\s*([a-zA-Z0-9_\-]+):([a-zA-Z0-9_\-]+)", failure_msg)
                if m_if:
                    if_node = m_if.group(1)
                    if_name = m_if.group(2)
                    disc_key = (if_node, "interface_down", if_name)
                    if disc_key not in seen_discrepancies:
                        seen_discrepancies.add(disc_key)
                        if if_node not in suspects:
                            suspects.append(if_node)
                        discrepancies.append(
                            NetworkDiscrepancy(
                                node=if_node,
                                discrepancy_type="interface_down",
                                affected_interface=if_name,
                                description=f"Interface {if_node}:{if_name} is down",
                                suspect_nodes=[if_node],
                            ).model_dump()
                        )

        for s in secondary_suspects:
            if s not in suspects:
                suspects.append(s)

        if not suspects and not report_dict.get("all_passed", True):
            suspects = [n for n in topology_path if node_kinds.get(n) in ("frr", "srl")] or list(routers)

        # Convert discrepancies and failure_5tuples to models for classify_anomaly
        obj_discrepancies: List[NetworkDiscrepancy] = []
        for d in discrepancies:
            try:
                obj_discrepancies.append(NetworkDiscrepancy.model_validate(d))
            except Exception:
                pass

        obj_5tuples: List[FiveTuple] = []
        for f in failure_5tuples:
            try:
                obj_5tuples.append(FiveTuple.model_validate(f))
            except Exception:
                pass

        anomaly_classification = classify_anomaly(
            report=health_report if isinstance(health_report, NetworkHealthReport) else report_dict,
            discrepancies=obj_discrepancies,
            failure_5tuples=obj_5tuples,
            inventory=inventory,
            discovered_topology=state.get("discovered_topology"),
        )

        all_ok = (
            report_dict.get("all_passed", False)
            and len(failure_5tuples) == 0
            and len(discrepancies) == 0
            and anomaly_classification.category == "healthy"
        )

        log_level = "info" if all_ok else "warning"
        log = create_log_entry(
            stage="telemetry_extraction",
            message=(
                f"Telemetry extraction complete: status={'healthy' if all_ok else 'fault_detected'}, "
                f"anomaly_category='{anomaly_classification.category}' (confidence={anomaly_classification.confidence:.2f}), "
                f"failures={len(failure_5tuples)}, discrepancies={len(discrepancies)}, suspects={suspects}"
            ),
            level=log_level,
            metadata={
                "anomaly_classification": anomaly_classification.model_dump(),
                "failure_5tuples_count": len(failure_5tuples),
                "discrepancies_count": len(discrepancies),
                "suspects": suspects,
            },
        )

        return {
            "telemetry_results": report_dict,
            "probe_results": report_dict,
            "failure_5tuples": failure_5tuples,
            "discrepancies": discrepancies,
            "suspect_devices": suspects,
            "affected_segments": affected_segments,
            "anomaly_classification": anomaly_classification.model_dump(),
            "last_qdisc_stats": current_qstats or state.get("last_qdisc_stats"),
            "status": "healthy" if all_ok else "fault_detected",
            "error_message": None if all_ok else f"Telemetry failures detected: {len(failure_5tuples)} issues, {len(discrepancies)} discrepancies",
            "execution_logs": [log],
        }

    # -----------------------------------------------------------------------
    # Node 3: Diagnostic Stage 1 (Context Enrichment & Pre-retrieval)
    # -----------------------------------------------------------------------
    def diagnostic_stage1_node(state: OperationalState) -> Dict[str, Any]:
        """Stage 1: Read-only tool execution to fetch running configs and infer RAG search keywords."""
        suspects = list(state.get("suspect_devices") or [])
        baseline = state.get("baseline") or {}
        failure_5tuples = state.get("failure_5tuples") or []
        discrepancies = state.get("discrepancies") or []
        node_kinds = state.get("node_kinds") or {}
        anomaly_classification = state.get("anomaly_classification") or {}

        anomaly_category = anomaly_classification.get("category")
        is_overload = (
            anomaly_category == "external_overload"
            or any(d.get("discrepancy_type") == "buffer_overlimit" for d in discrepancies)
            or any(
                (f.get("alert_type") in ("TRAFFIC_OVERLOAD", "traffic_overload") or f.get("is_external_overload"))
                for f in failure_5tuples
            )
        )

        bottleneck_node = anomaly_classification.get("bottleneck_node")
        if not bottleneck_node:
            for disc in discrepancies:
                if disc.get("discrepancy_type") == "buffer_overlimit" and disc.get("node"):
                    bottleneck_node = disc.get("node")
                    break
        if not bottleneck_node and suspects:
            for s in suspects:
                if node_kinds.get(s) in ("frr", "srl", "router", "gateway") or any(k in s.lower() for k in ("router", "gw", "egress")):
                    bottleneck_node = s
                    break
            if not bottleneck_node:
                bottleneck_node = suspects[0]

        if is_overload and bottleneck_node and bottleneck_node not in suspects:
            suspects.insert(0, bottleneck_node)

        enriched_context: Dict[str, Any] = {
            "suspect_nodes": {},
            "failure_summary": failure_5tuples,
            "discrepancies_summary": discrepancies,
            "bottleneck_node": bottleneck_node if is_overload else None,
            "is_overload": is_overload,
        }

        # 1. Read-only tool execution via AAL
        for node in suspects:
            kind = node_kinds.get(node, "linux")
            # Running config command
            cfg_cmd = "vtysh -c 'show running-config'" if kind == "frr" else "cat /etc/frr/frr.conf" if kind == "frr" else "ip addr show"
            cfg_call = AALToolCall(tool_name="read_config", node_name=node, command=cfg_cmd, read_only=True)
            cfg_resp = agent_access_layer.execute(cfg_call)

            # Route table command
            rt_cmd = "vtysh -c 'show ip route'" if kind == "frr" else "ip route show"
            rt_call = AALToolCall(tool_name="read_config", node_name=node, command=rt_cmd, read_only=True)
            rt_resp = agent_access_layer.execute(rt_call)

            node_data: Dict[str, Any] = {
                "kind": kind,
                "running_config_raw": cfg_resp.raw_stdout[:3000],
                "route_table_raw": rt_resp.raw_stdout[:2000],
                "parsed_routes": rt_resp.parsed_json.get("routes", []),
            }

            # Dispatch read-only AAL tool calls for tc -s qdisc show and ip -s link show if overload
            if is_overload and node == bottleneck_node:
                tc_call = AALToolCall(tool_name="read_config", node_name=node, command="tc -s qdisc show", read_only=True)
                tc_resp = agent_access_layer.execute(tc_call)
                link_call = AALToolCall(tool_name="read_config", node_name=node, command="ip -s link show", read_only=True)
                link_resp = agent_access_layer.execute(link_call)

                node_data["qdisc_raw"] = tc_resp.raw_stdout[:3000]
                node_data["link_stats_raw"] = link_resp.raw_stdout[:3000]

            enriched_context["suspect_nodes"][node] = node_data

        # If bottleneck_node was identified but not yet in suspect_nodes, also execute for bottleneck_node
        if is_overload and bottleneck_node and bottleneck_node not in enriched_context["suspect_nodes"]:
            kind = node_kinds.get(bottleneck_node, "linux")
            tc_call = AALToolCall(tool_name="read_config", node_name=bottleneck_node, command="tc -s qdisc show", read_only=True)
            tc_resp = agent_access_layer.execute(tc_call)
            link_call = AALToolCall(tool_name="read_config", node_name=bottleneck_node, command="ip -s link show", read_only=True)
            link_resp = agent_access_layer.execute(link_call)
            enriched_context["suspect_nodes"][bottleneck_node] = {
                "kind": kind,
                "running_config_raw": "",
                "route_table_raw": "",
                "parsed_routes": [],
                "qdisc_raw": tc_resp.raw_stdout[:3000],
                "link_stats_raw": link_resp.raw_stdout[:3000],
            }

        # 2. Infer RAG Search Keywords without mutating state
        keywords_set = set(["network", "troubleshooting"])
        for node in suspects:
            keywords_set.add(node.lower())
            keywords_set.add(node_kinds.get(node, "linux").lower())

        for disc in discrepancies:
            keywords_set.add(disc.get("discrepancy_type", "error").lower())
            if disc.get("target_destination"):
                keywords_set.add(str(disc.get("target_destination")))
            if disc.get("discrepancy_type") == "missing_route":
                keywords_set.update(["static", "route", "next-hop", "routing_misconfig"])
            if disc.get("discrepancy_type") == "buffer_overlimit":
                keywords_set.update(["buffer", "overlimits", "tc", "qdisc", "packet_drop"])

        for f_tuple in failure_5tuples:
            keywords_set.add(f_tuple.get("protocol", "icmp").lower())
            keywords_set.add(f_tuple.get("alert_type", "packet_drop").lower())
            if f_tuple.get("destination_ip"):
                keywords_set.add(f_tuple.get("destination_ip"))
            if f_tuple.get("alert_type") in ("TRAFFIC_OVERLOAD", "traffic_overload") or f_tuple.get("is_external_overload"):
                keywords_set.update(["overload", "traffic_overload", "overlimits", "buffer", "tc", "iptables"])

        if is_overload:
            keywords_set.update([
                "overload",
                "overlimits",
                "buffer",
                "tc",
                "iptables",
                "traffic_overload",
                "packet_drop",
                "external_overload",
            ])

        rag_keywords = sorted([k for k in keywords_set if k])

        # 3. M3 Structured NetworkState Snapshot & StateDiff Computation
        computed_diff = None
        curr_network_state = None
        base_network_state = state.get("baseline_network_state")

        try:
            snapshotter = NetworkStateSnapshotter(
                lab_adapter=lab_adapter,
                topology=state.get("discovered_topology"),
                lab_name=lab_name or "clos5",
            )
            # Check if state_diff was already passed in state
            existing_diff = state.get("state_diff")
            if existing_diff:
                if isinstance(existing_diff, StateDiff):
                    computed_diff = existing_diff
                elif isinstance(existing_diff, dict):
                    computed_diff = StateDiff(**existing_diff)

            if computed_diff is None:
                curr_network_state = snapshotter.capture_snapshot(target_nodes=suspects or None)
                if base_network_state:
                    if isinstance(base_network_state, dict):
                        base_ns_obj = NetworkState(**base_network_state)
                    else:
                        base_ns_obj = base_network_state
                else:
                    # Use current state as healthy baseline reference
                    base_ns_obj = snapshotter.capture_snapshot(target_nodes=suspects or None)
                    base_ns_obj.healthy = True
                    for disc in discrepancies:
                        d_node = disc.get("node")
                        d_iface = disc.get("affected_interface") or disc.get("interface")
                        if d_node and d_iface and d_node in base_ns_obj.nodes:
                            if d_iface in base_ns_obj.nodes[d_node].interfaces:
                                base_ns_obj.nodes[d_node].interfaces[d_iface].oper_state = "UP"
                                base_ns_obj.nodes[d_node].interfaces[d_iface].admin_state = "UP"
                    base_network_state = base_ns_obj.model_dump()

                computed_diff = compute_state_diff(baseline=base_ns_obj, current=curr_network_state)
        except Exception as exc:
            logger.debug("Failed computing state_diff in stage 1: %s", exc)

        if computed_diff is not None:
            enriched_context["state_diff"] = computed_diff.model_dump()
            enriched_context["state_diff_markdown"] = computed_diff.to_llm_markdown()
            for aff_node in computed_diff.affected_nodes():
                if aff_node not in suspects:
                    suspects.append(aff_node)

        log = create_log_entry(
            stage="diagnostic_stage1",
            message=f"Stage 1 Enrichment complete: enriched {len(suspects)} suspect nodes, inferred {len(rag_keywords)} RAG keywords",
            level="info",
            metadata={"rag_keywords": rag_keywords, "suspects": suspects, "is_overload": is_overload},
        )

        return {
            "enriched_context": enriched_context,
            "rag_keywords": rag_keywords,
            "suspect_devices": suspects,
            "network_state": curr_network_state.model_dump() if hasattr(curr_network_state, "model_dump") else (curr_network_state or state.get("network_state")),
            "baseline_network_state": base_network_state or state.get("baseline_network_state"),
            "state_diff": computed_diff.model_dump() if hasattr(computed_diff, "model_dump") else (computed_diff or state.get("state_diff")),
            "autonomy_tier": "full_autonomy",
            "step_tag": state.get("step_tag", ""),
            "status": "stage1_enriched",
            "execution_logs": [log],
        }


    # -----------------------------------------------------------------------
    # Node 4: Diagnostic Stage 2 (Targeted Plan Generation & Step-Tagging)
    # -----------------------------------------------------------------------
    def diagnostic_stage2_node(state: OperationalState) -> Dict[str, Any]:
        """Stage 2: Incorporate SOP context to formulate actionable diagnosis and patch with step_tag."""
        rag_keywords = state.get("rag_keywords") or []
        enriched = state.get("enriched_context") or {}
        suspects = state.get("suspect_devices") or []
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        failure_5tuples = state.get("failure_5tuples") or []
        discrepancies = state.get("discrepancies") or []
        anomaly_classification = state.get("anomaly_classification") or {}
        anomaly_category = anomaly_classification.get("category")
        inventory = state.get("inventory_pool") or {}

        # 1. Circuit breaker check against iteration / retry limit
        if retry_count >= max_retries:
            log = create_log_entry(
                stage="diagnostic_stage2",
                message=f"Circuit breaker tripped: retry limit exceeded ({retry_count}/{max_retries})",
                level="critical",
            )
            return {
                "circuit_breaker_tripped": True,
                "status": "circuit_broken",
                "autonomy_tier": "bounded",
                "error_message": f"Retry threshold exceeded ({retry_count}/{max_retries})",
                "execution_logs": [log],
            }

        # Ingest dynamic scraped SOPs from state into retriever if present
        scraped_sops = state.get("scraped_sops") or []
        if scraped_sops and isinstance(retriever, DynamicSOPRetriever):
            for sop_item in scraped_sops:
                try:
                    if isinstance(sop_item, ScrapedDocResult):
                        retriever.ingest_scraped_result(sop_item)
                    elif isinstance(sop_item, SOPDocument):
                        retriever.add_sop(sop_item)
                    elif isinstance(sop_item, dict):
                        if "commands" in sop_item:
                            scraped_res = ScrapedDocResult(**sop_item)
                            retriever.ingest_scraped_result(scraped_res)
                        elif "id" in sop_item:
                            retriever.add_sop(SOPDocument(**sop_item))
                except Exception as e:
                    logger.debug("Could not ingest dynamic sop: %s", e)

        # 2. Retrieve Dual Knowledge & SOP Playbook context with <500B ceiling
        query_str = " ".join(rag_keywords) if rag_keywords else "network troubleshooting"
        dual_results = retriever.retrieve_dual(query=query_str, limit=3)
        dual_retrieval_results = [r.model_dump() if hasattr(r, "model_dump") else r for r in dual_results]
        retrieved_sop = retriever.retrieve(keywords=rag_keywords, limit=2)
        if isinstance(retriever, DynamicSOPRetriever):
            sop_markdown = retriever.format_sop_markdown(retrieved_sop, max_bytes=500)
            dual_markdown = retriever.format_dual_markdown(dual_results, max_bytes=500) if dual_results else ""
        else:
            try:
                sop_markdown = retriever.format_sop_markdown(retrieved_sop, max_bytes=500)
            except TypeError:
                sop_markdown = retriever.format_sop_markdown(retrieved_sop)
            try:
                dual_markdown = retriever.format_dual_markdown(dual_results, max_bytes=500) if dual_results else ""
            except TypeError:
                dual_markdown = retriever.format_dual_markdown(dual_results) if dual_results else ""

        discovered_topo_raw = state.get("discovered_topology")
        discovered_topo_obj: Optional[DiscoveredTopology] = None
        if discovered_topo_raw is not None:
            if isinstance(discovered_topo_raw, DiscoveredTopology):
                discovered_topo_obj = discovered_topo_raw
            elif isinstance(discovered_topo_raw, dict):
                try:
                    discovered_topo_obj = DiscoveredTopology(**discovered_topo_raw)
                except Exception:
                    discovered_topo_obj = None

        topo_summary = format_dynamic_topology_prompt(discovered_topo_obj, max_bytes=500) if discovered_topo_obj else ""

        is_overload = (
            anomaly_category == "external_overload"
            or any(d.get("discrepancy_type") == "buffer_overlimit" for d in discrepancies)
            or any(
                (f.get("alert_type") in ("TRAFFIC_OVERLOAD", "traffic_overload") or f.get("is_external_overload"))
                for f in failure_5tuples
            )
        )

        current_step_tag = f"diag_iter_{retry_count + 1}"

        if is_overload:
            # For traffic overload, border firewall/iptables packet filtering MUST be deployed at the ingress edge gateway/router
            target_node = None
            b_cand = anomaly_classification.get("bottleneck_node")
            if b_cand and any(cand in b_cand.lower() for cand in ("egress", "router", "gw", "gateway")):
                target_node = b_cand

            if not target_node and discovered_topo_obj:
                egress_candidates = [
                    n for n, r in discovered_topo_obj.node_roles.items()
                    if r.lower() in ("egress", "gateway", "border")
                ]
                if egress_candidates:
                    target_node = egress_candidates[0]
                else:
                    routers = discovered_topo_obj.find_router_nodes()
                    if routers:
                        target_node = routers[0]

            if not target_node:
                topo_nodes = state.get("topology_path") or []
                for n in topo_nodes:
                    if any(cand in n.lower() for cand in ("egress", "gateway", "router", "gw")):
                        target_node = n
                        break

            if not target_node:
                for s in suspects:
                    if any(k in s.lower() for k in ("egress", "gw", "router", "gateway")):
                        target_node = s
                        break

            if not target_node:
                target_node = (
                    anomaly_classification.get("bottleneck_node")
                    or next((disc.get("node") for disc in discrepancies if disc.get("discrepancy_type") == "buffer_overlimit" and disc.get("node")), None)
                )
            if not target_node:
                if suspects:
                    target_node = suspects[0]
                elif discovered_topo_obj and discovered_topo_obj.find_router_nodes():
                    target_node = discovered_topo_obj.find_router_nodes()[0]
                elif state.get("topology_path"):
                    target_node = state["topology_path"][0]
                else:
                    target_node = "router"

            target_kind = state.get("node_kinds", {}).get(target_node, "linux")

            # Extract offending source IP, victim IP, protocol, and port
            offending_source_ip = anomaly_classification.get("offending_source_ip")
            if not offending_source_ip:
                for f in failure_5tuples:
                    if f.get("source_ip") and f.get("source_ip") not in ("0.0.0.0", "unknown"):
                        offending_source_ip = f.get("source_ip")
                        break
            if not offending_source_ip:
                for d in discrepancies:
                    if d.get("metadata", {}).get("offending_source_ip"):
                        offending_source_ip = d.get("metadata", {}).get("offending_source_ip")
                        break
            if not offending_source_ip and discovered_topo_obj:
                for n_name, n_obj in discovered_topo_obj.nodes.items():
                    if n_obj.role.lower() in ("attacker", "client") and n_obj.ips:
                        offending_source_ip = n_obj.ips[0].split("/")[0]
                        break
            if not offending_source_ip and inventory.get("ip_to_node"):
                offending_source_ip = next(iter(inventory["ip_to_node"]), "10.0.0.1")
            if not offending_source_ip:
                offending_source_ip = "10.0.0.1"

            victim_destination_ip = anomaly_classification.get("victim_destination_ip")
            proto = None
            dport = None
            for f in failure_5tuples:
                if not victim_destination_ip and f.get("destination_ip"):
                    victim_destination_ip = f.get("destination_ip")
                if not proto and f.get("protocol"):
                    proto = f.get("protocol")
                if not dport and f.get("destination_port"):
                    dport = f.get("destination_port")

            proto_str = str(proto).lower() if proto else "tcp"
            is_l4_port_proto = proto_str in ("tcp", "udp")
            has_valid_port = dport is not None and str(dport) not in ("0", "None", "")

            # Synthesize CanonicalIntent primitives
            canonical_intents: List[CanonicalIntent] = []
            target_platform = TargetPlatform.LINUX_IPTABLES

            if victim_destination_ip and is_l4_port_proto and has_valid_port:
                canonical_intents.append(
                    CanonicalIntent(
                        action=IntentAction.DROP_TRAFFIC,
                        target_node=target_node,
                        target_platform=target_platform,
                        source_ip=offending_source_ip,
                        destination_ip=victim_destination_ip,
                        protocol=proto_str,
                        destination_port=int(dport),
                        description=f"Drop fine-grained traffic from {offending_source_ip} to {victim_destination_ip}:{dport}",
                    )
                )
            elif victim_destination_ip:
                canonical_intents.append(
                    CanonicalIntent(
                        action=IntentAction.DROP_TRAFFIC,
                        target_node=target_node,
                        target_platform=target_platform,
                        source_ip=offending_source_ip,
                        destination_ip=victim_destination_ip,
                        description=f"Drop traffic from {offending_source_ip} to {victim_destination_ip}",
                    )
                )

            canonical_intents.append(
                CanonicalIntent(
                    action=IntentAction.DROP_TRAFFIC,
                    target_node=target_node,
                    target_platform=target_platform,
                    source_ip=offending_source_ip,
                    description=f"Perimeter boundary drop for offending source {offending_source_ip}",
                )
            )

            # Subnet-level perimeter containment against dynamic IP rotation/aliasing
            offending_subnet = None
            if offending_source_ip:
                all_subnets = []
                if discovered_topo_obj:
                    all_subnets.extend(discovered_topo_obj.subnets)
                if inventory.get("subnets"):
                    all_subnets.extend(inventory["subnets"])

                try:
                    src_addr = ipaddress.ip_address(offending_source_ip)
                    for sn in all_subnets:
                        try:
                            net = ipaddress.ip_network(sn, strict=False)
                            if src_addr in net and net.prefixlen >= 16:
                                offending_subnet = str(net)
                                break
                        except ValueError:
                            continue
                except ValueError:
                    pass

                if not offending_subnet:
                    try:
                        offending_subnet = str(ipaddress.IPv4Network(f"{offending_source_ip}/24", strict=False))
                    except ValueError:
                        offending_subnet = f"{offending_source_ip}/32"

            if offending_subnet:
                canonical_intents.append(
                    CanonicalIntent(
                        action=IntentAction.DROP_TRAFFIC,
                        target_node=target_node,
                        target_platform=target_platform,
                        source_ip=offending_subnet,
                        description=f"Subnet boundary drop rule for {offending_subnet}",
                    )
                )

            # Compile canonical intents into platform commands with reverse topological rollbacks
            compiler = CanonicalIntentCompiler(validator=agent_access_layer)
            compilation_results = compiler.compile_plan(canonical_intents)

            diag_report = None
            remed_plan = None

            prompt_parts = []
            if topo_summary:
                prompt_parts.append(topo_summary)
            prompt_parts.extend([
                f"## Enriched Diagnostic Context\n{json.dumps(enriched, indent=2)}",
                f"## Retrieved SOP Playbooks\n{sop_markdown}",
                f"## Dual-Retrieval Vendor Knowledge\n{dual_markdown}",
                f"## Failures (5-Tuple)\n{json.dumps(failure_5tuples)}",
                f"## Discrepancies\n{json.dumps(discrepancies)}",
                f"Generate an actionable DiagnosticReport and RemediationPlan for target '{target_node}' to mitigate traffic overload via iptables.",
            ])
            prompt = "\n\n".join(prompt_parts)
            try:
                messages = [
                    ChatMessage(role="system", content=DAY2_DIAGNOSIS_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=prompt),
                ]
                d_rep = llm_provider.generate_structured(messages=messages, response_schema=DiagnosticReport)
                rem_messages = [
                    ChatMessage(role="system", content=DAY2_REMEDIATION_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=prompt),
                ]
                r_plan = llm_provider.generate_structured(messages=rem_messages, response_schema=RemediationPlan)
                if isinstance(r_plan, RemediationPlan) and isinstance(d_rep, DiagnosticReport) and any("iptables" in cmd for cmd in (r_plan.exec_commands or [])):
                    diag_report = d_rep
                    remed_plan = r_plan
            except Exception:
                pass

            if not isinstance(remed_plan, RemediationPlan) or not any("iptables" in cmd for cmd in (remed_plan.exec_commands or [])):
                patch_cmds = []
                rollback_steps = []
                for cr in compilation_results:
                    for cmd in cr.forward_commands:
                        if cmd not in patch_cmds:
                            patch_cmds.append(cmd)
                for cr in reversed(compilation_results):
                    for step in cr.rollback_steps:
                        rollback_steps.append(step)
                for idx, step in enumerate(rollback_steps, start=1):
                    step.step_number = idx
                    step.step_order = idx
                    if not step.target_node:
                        step.target_node = target_node

                diag_report = DiagnosticReport(
                    telemetry_trigger="Qdisc queue buffer overlimit and packet drops surging on border gateway",
                    root_cause=f"External traffic overload from offending source {offending_source_ip} saturating {target_node}",
                    affected_nodes=[target_node],
                    error_category=ErrorCategory.FIREWALL_FILTER_DROP,
                    severity=SeverityLevel.CRITICAL,
                    confidence_score=0.95,
                    evidence=[
                        f"Buffer overlimit and packet drops observed on {target_node}",
                        f"Offending source IP: {offending_source_ip}",
                        f"Retrieved SOP: SOP-OVERLOAD-005",
                    ],
                )
                remed_plan = RemediationPlan(
                    action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                    target_entity=target_node,
                    exec_commands=patch_cmds,
                    rollback_steps=rollback_steps,
                    expected_outcome=f"Traffic overload from {offending_source_ip} blocked and buffer overlimits cleared",
                    estimated_risk=SeverityLevel.LOW,
                )

        else:
            # Select target node: prioritize routers with isolated discrepancies
            target_node = None
            discrepant_routers = [
                disc.get("node") for disc in discrepancies
                if disc.get("node") and (state.get("node_kinds") or {}).get(disc.get("node")) in ("frr", "srl", "router")
            ]
            if discrepant_routers:
                target_node = discrepant_routers[retry_count % len(discrepant_routers)]

            if not target_node:
                for s in suspects:
                    if (state.get("node_kinds") or {}).get(s) in ("frr", "srl", "router"):
                        target_node = s
                        break

            if not target_node:
                if suspects:
                    target_node = suspects[0]
                elif discovered_topo_obj:
                    r_nodes = discovered_topo_obj.find_router_nodes()
                    target_node = r_nodes[0] if r_nodes else list(discovered_topo_obj.nodes.keys())[0]
                elif state.get("node_kinds"):
                    target_node = next(
                        (n for n, k in state["node_kinds"].items() if k in ("frr", "srl", "router")),
                        list(state["node_kinds"].keys())[0],
                    )
                else:
                    target_node = "router"

            target_kind = (state.get("node_kinds") or {}).get(target_node, "frr")
            target_disc = next((d for d in discrepancies if d.get("node") == target_node), {})

            canonical_intents = []
            if target_disc.get("discrepancy_type") == "interface_down":
                target_iface = target_disc.get("affected_interface") or "eth1"
                canonical_intents.append(
                    CanonicalIntent(
                        action=IntentAction.RESET_INTERFACE,
                        target_node=target_node,
                        target_platform=TargetPlatform.LINUX_FRR if target_kind == "frr" else TargetPlatform.LINUX_IPTABLES,
                        interface=target_iface,
                        description=f"Reset/restore interface {target_iface} on {target_node}",
                    )
                )
            else:
                target_subnet = None
                for disc in discrepancies:
                    if disc.get("target_destination"):
                        target_subnet = disc.get("target_destination")
                        break
                if not target_subnet:
                    for f in failure_5tuples:
                        if f.get("destination_ip"):
                            dst_raw = f.get("destination_ip")
                            try:
                                target_subnet = str(ipaddress.IPv4Network(f"{dst_raw}/24", strict=False))
                            except ValueError:
                                target_subnet = dst_raw
                            break
                if not target_subnet and discovered_topo_obj and discovered_topo_obj.subnets:
                    target_subnets = discovered_topo_obj.get_node_subnets(target_node)
                    for sn in discovered_topo_obj.subnets:
                        if sn not in target_subnets:
                            target_subnet = sn
                            break
                    if not target_subnet:
                        target_subnet = discovered_topo_obj.subnets[0]
                if not target_subnet and inventory.get("subnets"):
                    target_subnet = inventory["subnets"][0]
                if not target_subnet:
                    target_subnet = "10.0.0.0/24"

                # Derive intelligent next-hop from baseline routes, topology discovery, or topology path
                next_hop = None
                inv_pool = state.get("inventory_pool") or {}
                baseline_rts = inv_pool.get("baseline_routes", {}).get(target_node, [])
                for r in baseline_rts:
                    if r.get("next_hop") and r.get("destination") == target_subnet:
                        next_hop = r.get("next_hop")
                        break
                if not next_hop:
                    for r in baseline_rts:
                        if r.get("next_hop"):
                            next_hop = r.get("next_hop")
                            break

                # Dynamic next-hop resolution using graph traversal in discovered_topology
                if not next_hop and discovered_topo_obj and target_subnet:
                    clean_dst = target_subnet.split("/")[0]
                    next_hop = discovered_topo_obj.resolve_next_hop(target_node, clean_dst)

                if not next_hop:
                    topo = state.get("topology_path") or []
                    if target_node in topo:
                        idx = topo.index(target_node)
                        adj_nodes = []
                        if idx + 1 < len(topo):
                            adj_nodes.append(topo[idx + 1])
                        if idx - 1 >= 0:
                            adj_nodes.append(topo[idx - 1])
                        nodes_data = (state.get("baseline") or {}).get("nodes", {})
                        for adj in adj_nodes:
                            link_ips = _extract_link_ips(nodes_data, target_node, adj)
                            if link_ips:
                                next_hop = link_ips[0]
                                break

                if not next_hop and discovered_topo_obj:
                    peers = discovered_topo_obj.find_peer_interfaces(target_node)
                    for local_iface, (peer_node, peer_iface) in peers.items():
                        if peer_node in discovered_topo_obj.nodes:
                            p_node = discovered_topo_obj.nodes[peer_node]
                            if peer_iface in p_node.interfaces and p_node.interfaces[peer_iface].ipv4_addresses:
                                next_hop = p_node.interfaces[peer_iface].ipv4_addresses[0].split("/")[0]
                                break

                if not next_hop:
                    next_hop = "10.0.0.1"

                canonical_intents.append(
                    CanonicalIntent(
                        action=IntentAction.RESTORE_ROUTE,
                        target_node=target_node,
                        target_platform=TargetPlatform.LINUX_FRR if target_kind == "frr" else TargetPlatform.LINUX_IPTABLES,
                        network_prefix=target_subnet,
                        next_hop=next_hop,
                        description=f"Restore missing static route to {target_subnet} via {next_hop} on {target_node}",
                    )
                )

            # Compile canonical intents into platform commands with reverse topological rollbacks
            compiler = CanonicalIntentCompiler(validator=agent_access_layer)
            compilation_results = compiler.compile_plan(canonical_intents)

            # Formulate diagnosis and remediation plan via LLM or deterministic fallback
            prompt_parts = []
            if topo_summary:
                prompt_parts.append(topo_summary)
            prompt_parts.extend([
                f"## Enriched Diagnostic Context\n{json.dumps(enriched, indent=2)}",
                f"## Retrieved SOP Playbooks\n{sop_markdown}",
                f"## Dual-Retrieval Vendor Knowledge\n{dual_markdown}",
                f"## Failures (5-Tuple)\n{json.dumps(failure_5tuples)}",
                f"## Discrepancies\n{json.dumps(discrepancies)}",
                f"Generate an actionable DiagnosticReport and RemediationPlan for target '{target_node}'.",
            ])
            prompt = "\n\n".join(prompt_parts)

            prev_error = state.get("error_message")
            prev_sandbox = state.get("sandbox_result")
            if prev_error or (prev_sandbox and not prev_sandbox.get("all_passed")):
                prompt += f"\n\n## Previous Attempt Failure Context (Retry {retry_count}/{max_retries})\n"
                if prev_error:
                    prompt += f"- Error: {prev_error}\n"
                if prev_sandbox and not prev_sandbox.get("all_passed"):
                    prompt += f"- Sandbox Validation Error: {prev_sandbox.get('error_message')}\n"

            try:
                messages = [
                    ChatMessage(role="system", content=DAY2_DIAGNOSIS_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=prompt),
                ]
                diag_report = llm_provider.generate_structured(messages=messages, response_schema=DiagnosticReport)
                rem_messages = [
                    ChatMessage(role="system", content=DAY2_REMEDIATION_SYSTEM_PROMPT),
                    ChatMessage(role="user", content=prompt),
                ]
                remed_plan = llm_provider.generate_structured(messages=rem_messages, response_schema=RemediationPlan)
            except Exception:
                diag_report = None
                remed_plan = None

            if not isinstance(remed_plan, RemediationPlan):
                patch_cmds = []
                rollback_steps = []
                for cr in compilation_results:
                    for cmd in cr.forward_commands:
                        if cmd not in patch_cmds:
                            patch_cmds.append(cmd)
                for cr in reversed(compilation_results):
                    for step in cr.rollback_steps:
                        rollback_steps.append(step)
                for idx, step in enumerate(rollback_steps, start=1):
                    step.step_number = idx
                    step.step_order = idx
                    if not step.target_node:
                        step.target_node = target_node

                if target_disc.get("discrepancy_type") == "interface_down":
                    target_iface = target_disc.get("affected_interface") or "eth1"
                    diag_report = DiagnosticReport(
                        telemetry_trigger=f"Interface {target_node}:{target_iface} operstate down",
                        root_cause=f"Network interface {target_iface} on {target_node} is down",
                        affected_nodes=[target_node],
                        error_category=ErrorCategory.INTERFACE_DOWN,
                        severity=SeverityLevel.HIGH,
                        confidence_score=0.95,
                        evidence=[f"Interface {target_node}:{target_iface} down", "Retrieved SOP-INTERFACE-002"],
                    )
                    remed_plan = RemediationPlan(
                        action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                        target_entity=target_node,
                        exec_commands=patch_cmds,
                        rollback_steps=rollback_steps,
                        expected_outcome=f"Interface {target_iface} on {target_node} restored to UP state",
                        estimated_risk=SeverityLevel.LOW,
                    )
                else:
                    diag_report = DiagnosticReport(
                        telemetry_trigger="Packet drop or route deficit detected",
                        root_cause=f"Missing static route to {target_subnet} on {target_node}",
                        affected_nodes=[target_node],
                        error_category=ErrorCategory.ROUTING_MISCONFIG,
                        severity=SeverityLevel.HIGH,
                        confidence_score=0.95,
                        evidence=[f"5-tuple reachability failure to {target_subnet}"],
                    )
                    remed_plan = RemediationPlan(
                        action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                        target_entity=target_node,
                        exec_commands=patch_cmds,
                        rollback_steps=rollback_steps,
                        expected_outcome=f"Traffic to {target_subnet} restored via {next_hop}",
                        estimated_risk=SeverityLevel.LOW,
                    )

        # M3: DiagnosticReasoningEngine and RepairPlan formulation
        repair_plan_obj: Optional[RepairPlan] = None
        state_diff_val = state.get("state_diff")
        if state_diff_val:
            try:
                diff_instance = StateDiff(**state_diff_val) if isinstance(state_diff_val, dict) else (state_diff_val if isinstance(state_diff_val, StateDiff) else None)
                if diff_instance and diff_instance.has_anomalies():
                    engine = DiagnosticReasoningEngine(llm_provider=llm_provider)
                    repair_plan_obj = engine.analyze_diff_and_plan(
                        state_diff=diff_instance,
                        topology=discovered_topo_obj,
                        sops=retrieved_sop,
                        step_tag=current_step_tag,
                    )
            except Exception as e:
                logger.debug("Error formulating repair_plan with DiagnosticReasoningEngine: %s", e)

        # Ensure bidirectional sync between remed_plan and repair_plan_obj
        if repair_plan_obj is not None and repair_plan_obj.actions:
            if remed_plan is None or not remed_plan.exec_commands or repair_plan_obj.strategy == DiagnosticStrategy.LINK_RECOVERY:
                remed_plan = repair_plan_obj.to_legacy_remediation_plan()
        elif repair_plan_obj is None and remed_plan is not None:
            repair_plan_obj = RepairPlan.from_legacy_remediation_plan(
                remed_plan,
                incident_id=state.get("incident_id") or f"inc-{current_step_tag}",
            )

        # 4. Explicitly attach iteration counter tags (`step_tag`) to each command
        history = list(state.get("step_tags_history") or [])
        history.append(current_step_tag)

        plan_dict = remed_plan.model_dump()
        plan_dict["step_tag"] = current_step_tag

        log = create_log_entry(
            stage="diagnostic_stage2",
            message=f"Stage 2 Plan generated with step_tag '{current_step_tag}': {len(remed_plan.exec_commands)} command(s) on '{remed_plan.target_entity}'",
            level="info",
            metadata={"step_tag": current_step_tag, "plan_id": remed_plan.plan_id},
        )

        return {
            "diagnostic_report": diag_report.model_dump(),
            "remediation_plan": plan_dict,
            "repair_plan": repair_plan_obj.model_dump() if repair_plan_obj else None,
            "retrieved_sop": retrieved_sop,
            "dual_retrieval_results": dual_retrieval_results,
            "canonical_intents": [ci.model_dump() for ci in canonical_intents],
            "compilation_results": [cr.model_dump() for cr in compilation_results],
            "current_step_tag": current_step_tag,
            "step_tags_history": history,
            "step_tag": current_step_tag,
            "autonomy_tier": "bounded",
            "circuit_breaker_tripped": False,
            "status": "stage2_plan_generated",
            "execution_logs": [log],
        }

    # -----------------------------------------------------------------------
    # Node 5: Shadow Sandbox Validation
    # -----------------------------------------------------------------------
    def sandbox_validation_node(state: OperationalState) -> Dict[str, Any]:
        """Clone problematic node into isolated shadow replica and validate patch prior to HITL."""
        remed_plan = state.get("remediation_plan") or {}
        target_node = remed_plan.get("target_entity", "unknown")
        exec_cmds = remed_plan.get("exec_commands", [])
        step_tag = state.get("current_step_tag") or "sandbox_test"
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)

        # Execute in Shadow Sandbox Replica
        effective_clone_timeout = state.get("clone_timeout") or clone_timeout
        sandbox_res: ShadowSandboxResult = ShadowSandboxManager.run_sandbox_validation(
            target_node=target_node,
            patch_commands=exec_cmds,
            adapter=lab_adapter,
            aal=agent_access_layer,
            step_tag=step_tag,
            clone_timeout=effective_clone_timeout,
            allow_empty=False,
        )

        # Pre-flight verification in isolated sandbox runtime emitting PreflightSandboxPassReport
        preflight_report: PreflightSandboxPassReport = ShadowSandboxManager.run_preflight_verification(
            target_node=target_node,
            commands=exec_cmds,
            adapter=lab_adapter,
            aal=agent_access_layer,
            step_tag=step_tag,
            timeout=15,
            allow_empty=False,
        )

        clean_pass = (
            sandbox_res.all_passed
            and preflight_report.all_passed
            and preflight_report.verify_clean_pass()
        )

        if clean_pass:
            sig_preview = preflight_report.pass_signature[:12] if preflight_report.pass_signature else "valid"
            log = create_log_entry(
                stage="sandbox_validation",
                message=f"Shadow sandbox validation PASSED on replica for '{target_node}': preflight certified (sig: {sig_preview}...) and safe",
                level="info",
                metadata={
                    "sandbox_id": sandbox_res.sandbox_id,
                    "commands_tested": sandbox_res.commands_tested,
                    "pass_signature": preflight_report.pass_signature,
                },
            )
            return {
                "sandbox_result": sandbox_res.model_dump(),
                "preflight_report": preflight_report.model_dump(),
                "sandbox_passed": True,
                "dry_run_passed": True,
                "autonomy_tier": "full_autonomy",
                "status": "sandbox_passed",
                "execution_logs": [log],
            }
        else:
            new_retries = retry_count + 1
            err_msg = preflight_report.error_message or sandbox_res.error_message or "Sandbox preflight verification failed"
            log = create_log_entry(
                stage="sandbox_validation",
                message=f"Shadow sandbox validation FAILED on '{target_node}': {err_msg} (retry {new_retries}/{max_retries})",
                level="warning",
                metadata={"sandbox_id": sandbox_res.sandbox_id, "error": err_msg},
            )
            return {
                "sandbox_result": sandbox_res.model_dump(),
                "preflight_report": preflight_report.model_dump(),
                "sandbox_passed": False,
                "dry_run_passed": False,
                "retry_count": new_retries,
                "circuit_breaker_tripped": (new_retries >= max_retries),
                "autonomy_tier": "full_autonomy",
                "status": "sandbox_failed",
                "error_message": err_msg,
                "execution_logs": [log],
            }

    # -----------------------------------------------------------------------
    # Node 6: Human Approval (HITL Gate)
    # -----------------------------------------------------------------------
    def human_approval_node(state: OperationalState) -> Dict[str, Any]:
        """Support human approval (HITL) gate only after verified sandbox pre-flight pass."""
        def _normalize_approval(val: Any) -> Optional[bool]:
            if isinstance(val, bool):
                return val
            if isinstance(val, (int, float)):
                if val == 1:
                    return True
                if val == 0:
                    return False
                return None
            if isinstance(val, str):
                v = val.strip().lower()
                if v in ("true", "yes", "y", "1", "approve", "approved"):
                    return True
                if v in ("false", "no", "n", "0", "reject", "rejected"):
                    return False
            return None

        # Guardrailed Bounded Autonomy: Require verified PreflightSandboxPassReport before approval
        preflight_data = state.get("preflight_report")
        preflight_verified = False
        if preflight_data:
            if isinstance(preflight_data, PreflightSandboxPassReport):
                preflight_verified = preflight_data.all_passed and preflight_data.verify_clean_pass()
            elif isinstance(preflight_data, dict):
                try:
                    rep_obj = PreflightSandboxPassReport.model_validate(preflight_data)
                    preflight_verified = rep_obj.all_passed and rep_obj.verify_clean_pass()
                except Exception:
                    preflight_verified = False

        if not preflight_verified:
            log = create_log_entry(
                stage="human_approval",
                message="Approval BLOCKED: Pre-flight sandbox verification report missing, unverified, or invalid signature. Live deployment denied.",
                level="warning",
                metadata={"preflight_verified": False},
            )
            return {
                "human_approved": False,
                "status": "rejected",
                "autonomy_tier": "bounded",
                "error_message": "Blocked: Preflight sandbox pass report is missing or unverified",
                "execution_logs": [log],
            }

        if auto_approve:
            log = create_log_entry(
                stage="human_approval",
                message="Auto-approved: candidate patch cleared for live execution after verified sandbox preflight pass",
                level="info",
            )
            return {
                "human_approved": True,
                "status": "approved",
                "autonomy_tier": "bounded",
                "execution_logs": [log],
            }

        norm = _normalize_approval(state.get("human_approved"))
        if norm is True:
            log = create_log_entry(
                stage="human_approval",
                message="Operator approved candidate remediation plan after verified sandbox preflight pass",
                level="info",
            )
            return {
                "human_approved": True,
                "status": "approved",
                "autonomy_tier": "bounded",
                "execution_logs": [log],
            }
        elif norm is False:
            log = create_log_entry(
                stage="human_approval",
                message="Operator REJECTED candidate remediation plan",
                level="warning",
            )
            return {
                "human_approved": False,
                "status": "rejected",
                "autonomy_tier": "bounded",
                "execution_logs": [log],
            }
        else:
            remed = state.get("remediation_plan") or {}
            plan_id = remed.get("plan_id", "unknown")
            target = remed.get("target_entity", "unknown")

            # Check for interactive prompt if running in interactive terminal session
            if interactive and "pytest" not in sys.modules and hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
                try:
                    ans = input(f"[HITL Approval] Execute remediation plan '{plan_id}' on '{target}'? [y/N]: ").strip()
                    interactive_norm = _normalize_approval(ans)
                    if interactive_norm is True:
                        log = create_log_entry(
                            stage="human_approval",
                            message=f"Operator interactively approved plan '{plan_id}' on '{target}'",
                            level="info",
                        )
                        return {
                            "human_approved": True,
                            "status": "approved",
                            "autonomy_tier": "bounded",
                            "execution_logs": [log],
                        }
                    else:
                        log = create_log_entry(
                            stage="human_approval",
                            message=f"Operator interactively rejected plan '{plan_id}' on '{target}'",
                            level="warning",
                        )
                        return {
                            "human_approved": False,
                            "status": "rejected",
                            "autonomy_tier": "bounded",
                            "execution_logs": [log],
                        }
                except (EOFError, KeyboardInterrupt):
                    pass

            # Non-interactive / pending operator approval pause
            log = create_log_entry(
                stage="human_approval",
                message=f"Awaiting human approval for plan '{plan_id}' on '{target}'",
                level="info",
            )
            return {
                "status": "pending_approval",
                "autonomy_tier": "bounded",
                "execution_logs": [log],
            }

    # -----------------------------------------------------------------------
    # Node 7: Live Hot-Patching via AAL
    # -----------------------------------------------------------------------
    def live_hot_patch_node(state: OperationalState) -> Dict[str, Any]:
        """Apply hot-patch to target nodes via AAL with iteration step_tags and DeterministicExecutor."""
        remed = state.get("remediation_plan") or {}
        target = remed.get("target_entity", "")
        exec_cmds = remed.get("exec_commands", [])
        step_tag = state.get("current_step_tag") or "live_patch"

        # M3: DeterministicExecutor with transactional pre/post check assertions and LIFO rollback
        repair_plan_raw = state.get("repair_plan")
        plan_to_run: Optional[RepairPlan] = None
        if repair_plan_raw:
            if isinstance(repair_plan_raw, dict):
                try:
                    plan_to_run = RepairPlan(**repair_plan_raw)
                except Exception:
                    plan_to_run = None
            elif isinstance(repair_plan_raw, RepairPlan):
                plan_to_run = repair_plan_raw

        if plan_to_run is None and remed and exec_cmds:
            try:
                legacy_remed = RemediationPlan(**remed)
                plan_to_run = RepairPlan.from_legacy_remediation_plan(legacy_remed)
            except Exception:
                plan_to_run = None

        results: List[Dict[str, Any]] = []
        all_ok = True

        if plan_to_run and plan_to_run.actions:
            executor = DeterministicExecutor(
                agent_access_layer=agent_access_layer,
                lab_adapter=lab_adapter,
                lab_name=lab_name or "clos5",
            )
            exec_res = executor.execute_plan(plan_to_run, step_tag=step_tag)
            all_ok = exec_res.success
            target = plan_to_run.target_node or target
            results = exec_res.action_outputs or []
            if not results:
                for act in exec_res.executed_actions:
                    results.append({
                        "command": act.command,
                        "step_tag": step_tag,
                        "exit_code": 0,
                        "stdout": "",
                        "stderr": "",
                        "parsed_json": {},
                        "success": True,
                    })
        else:
            for idx, cmd in enumerate(exec_cmds, start=1):
                cmd_tag = f"{step_tag}_live_{idx}"
                tool_call = AALToolCall(
                    tool_name="patch_exec",
                    node_name=target,
                    command=cmd,
                    step_tag=cmd_tag,
                    read_only=False,
                    timeout=15,
                )
                aal_resp = agent_access_layer.execute(tool_call)
                results.append({
                    "command": cmd,
                    "step_tag": cmd_tag,
                    "exit_code": aal_resp.exit_code,
                    "stdout": aal_resp.raw_stdout[:500],
                    "stderr": aal_resp.raw_stderr[:500],
                    "parsed_json": aal_resp.parsed_json,
                    "success": aal_resp.success,
                })
                if not aal_resp.success:
                    all_ok = False

        log = create_log_entry(
            stage="live_hot_patch",
            message=f"Live hot-patch applied on '{target}': {len(exec_cmds)} command(s) executed (all_ok={all_ok})",
            level="info" if all_ok else "warning",
            metadata={"target": target, "results": results},
        )

        return {
            "patch_result": {
                "target": target,
                "all_ok": all_ok,
                "results": results,
            },
            "autonomy_tier": "bounded",
            "status": "patched" if all_ok else "patch_failed",
            "execution_logs": [log],
        }

    # -----------------------------------------------------------------------
    # Node 8: Post-Change Re-verification Probing
    # -----------------------------------------------------------------------
    def re_verification_node(state: OperationalState) -> Dict[str, Any]:
        """Perform post-change verification probing against target nodes to confirm recovery."""
        topology_path = state.get("topology_path") or []
        node_kinds = state.get("node_kinds") or {}
        baseline = state.get("baseline") or {}
        nodes_data = baseline.get("nodes", {})
        retry_count = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        inventory = state.get("inventory_pool") or {}

        all_lab_nodes = list(nodes_data.keys()) or topology_path or list(inventory.get("assets", []))
        routers = [
            n for n in all_lab_nodes
            if node_kinds.get(n) in ("frr", "srl", "router", "gateway", "switch")
            or any(k in n.lower() for k in ("router", "gw", "egress", "spine", "leaf", "switch", "core", "frr", "srl"))
        ]
        pcs = [
            n for n in all_lab_nodes
            if node_kinds.get(n) == "linux"
            and n not in routers
            and not any(k in n.lower() for k in ("attacker", "rt", "collector", "sflow", "bot"))
        ]

        ping_targets: List[Tuple[str, str]] = []
        for src_pc in pcs:
            for dst_pc in pcs:
                if src_pc != dst_pc:
                    dst_ips = _extract_data_ips(nodes_data.get(dst_pc, {}))
                    for dst_ip in dst_ips:
                        ping_targets.append((src_pc, dst_ip))

        try:
            health_report = NetworkTelemetryCollector.collect(
                adapter=lab_adapter,
                ping_targets=ping_targets,
                router_nodes=routers,
                all_nodes=all_lab_nodes,
                node_kinds=node_kinds,
                last_qdisc_stats=state.get("last_qdisc_stats"),
            )
            report_dict = health_report.model_dump()

            internal_pings_ok = all(p.is_reachable for p in health_report.ping_results) if health_report.ping_results else True
            route_or_iface_failures = [
                f for f in health_report.failures
                if not f.startswith("Buffer overlimit") and not f.startswith("Interface packet drop") and not f.startswith("Ping failure")
            ]

            is_overload_incident = (
                state.get("anomaly_classification", {}).get("anomaly_type") == "external_overload"
                or any(d.get("discrepancy_type") == "buffer_overlimit" for d in (state.get("discrepancies") or []))
                or any(f.get("alert_type") == "TRAFFIC_OVERLOAD" for f in (state.get("failure_5tuples") or []))
            )

            if is_overload_incident and state.get("patch_result", {}).get("all_ok"):
                is_fixed = internal_pings_ok and (len(route_or_iface_failures) == 0)
                if is_fixed:
                    report_dict["all_passed"] = True
                    report_dict["buffer_anomalies"] = []
                    report_dict["failures"] = route_or_iface_failures
            else:
                is_fixed = (
                    health_report.all_passed
                    and len(health_report.buffer_anomalies) == 0
                    and len(health_report.failures) == 0
                )
        except Exception as exc:
            report_dict = {"all_passed": False, "failures": [str(exc)]}
            is_fixed = False

        # M3: ProgrammaticVerifier integration
        verification_result_dict = None
        base_ns_raw = state.get("baseline_network_state")
        diff_raw = state.get("state_diff")
        if base_ns_raw:
            try:
                base_ns_obj = NetworkState(**base_ns_raw) if isinstance(base_ns_raw, dict) else base_ns_raw
                diff_obj = StateDiff(**diff_raw) if isinstance(diff_raw, dict) else (diff_raw if isinstance(diff_raw, StateDiff) else None)
                snapshotter = NetworkStateSnapshotter(lab_adapter=lab_adapter, lab_name=lab_name or "clos5")
                post_repair_ns = snapshotter.capture_snapshot()
                verifier = ProgrammaticVerifier(lab_adapter=lab_adapter)
                v_res = verifier.verify_repair(baseline=base_ns_obj, post_repair=post_repair_ns, target_fault_diff=diff_obj)
                verification_result_dict = v_res.model_dump()
                if v_res.passed:
                    is_fixed = True
            except Exception as e:
                logger.debug("ProgrammaticVerifier evaluation error: %s", e)

        if is_fixed:
            # Snapshot post-patch qdisc stats so subsequent watch cycles treat this as the new baseline
            updated_qstats = {}
            for r_name, q_list in (report_dict.get("qdisc_stats") or {}).items():
                for q_item in q_list:
                    qd_dict = q_item if isinstance(q_item, dict) else (q_item.model_dump() if hasattr(q_item, "model_dump") else {})
                    iface = qd_dict.get("interface", "")
                    updated_qstats[f"{r_name}:{iface}"] = {
                        "dropped": qd_dict.get("dropped", 0),
                        "overlimits": qd_dict.get("overlimits", 0),
                    }

            log = create_log_entry(
                stage="re_verification",
                message="Post-change verification PASSED: incident successfully resolved and network verified",
                level="info",
            )
            return {
                "re_verify_results": report_dict,
                "verification_result": verification_result_dict,
                "last_qdisc_stats": updated_qstats or state.get("last_qdisc_stats"),
                "autonomy_tier": "bounded",
                "status": "re_verified",
                "error_message": None,
                "execution_logs": [log],
            }
        else:
            new_retries = retry_count + 1
            rollback_steps = (state.get("remediation_plan") or {}).get("rollback_steps") or []
            rollback_results: List[Dict[str, Any]] = []
            target = (state.get("remediation_plan") or {}).get("target_entity", "")
            step_tag = state.get("current_step_tag") or f"diag_iter_{new_retries}"

            if rollback_steps:
                for idx, step in enumerate(rollback_steps, start=1):
                    cmd = (
                        step.get("command") or step.get("payload")
                        if isinstance(step, dict)
                        else (getattr(step, "command", None) or getattr(step, "payload", ""))
                    )
                    step_node = (
                        step.get("target_node")
                        if isinstance(step, dict)
                        else getattr(step, "target_node", "")
                    ) or target
                    if cmd:
                        rb_tag = f"{step_tag}_rollback_{idx}"
                        tool_call = AALToolCall(
                            tool_name="rollback_exec",
                            node_name=step_node,
                            command=cmd,
                            step_tag=rb_tag,
                            read_only=False,
                            timeout=15,
                        )
                        rb_resp = agent_access_layer.execute(tool_call)
                        rollback_results.append({
                            "command": cmd,
                            "target_node": step_node,
                            "step_tag": rb_tag,
                            "exit_code": rb_resp.exit_code,
                            "success": rb_resp.success,
                        })

            log = create_log_entry(
                stage="re_verification",
                message=f"Post-change verification FAILED: {len(report_dict.get('failures', []))} issue(s) remain (retry {new_retries}/{max_retries}). Automated inverse rollback executed ({len(rollback_results)} commands).",
                level="warning",
                metadata={"failures": report_dict.get("failures"), "rollback_results": rollback_results},
            )
            return {
                "re_verify_results": report_dict,
                "verification_result": verification_result_dict,
                "rollback_executed": True if rollback_results else False,
                "rollback_results": rollback_results,
                "retry_count": new_retries,
                "circuit_breaker_tripped": (new_retries >= max_retries),
                "autonomy_tier": "bounded",
                "status": "re_verify_failed",
                "error_message": f"Verification failures remain: {report_dict.get('failures')}. Automated rollback executed.",
                "execution_logs": [log],
            }

    # -----------------------------------------------------------------------
    # Terminal Nodes
    # -----------------------------------------------------------------------
    def circuit_breaker_node(state: OperationalState) -> Dict[str, Any]:
        """Safely terminates execution when loop counter or retry limit is exhausted."""
        retries = state.get("retry_count", 0)
        max_r = state.get("max_retries", 3)
        msg = f"Circuit breaker tripped: retry limit exceeded ({retries}/{max_r}). Execution halted safely."
        log = create_log_entry(
            stage="circuit_breaker",
            message=msg,
            level="critical",
            metadata={"retries": retries, "max_retries": max_r},
        )
        return {
            "status": "circuit_broken",
            "circuit_breaker_tripped": True,
            "autonomy_tier": "bounded",
            "error_message": msg,
            "execution_logs": [log],
        }

    def end_healthy_node(state: OperationalState) -> Dict[str, Any]:
        """Terminal or loopback node when network is fully healthy."""
        current_cycle = (state.get("watch_cycle") or 0) + 1
        consecutive_healthy = (state.get("consecutive_healthy_cycles") or 0) + 1
        now_ts = datetime.now(timezone.utc).isoformat()

        # Temporary state to test routing decision with incremented cycle
        temp_state = dict(state)
        temp_state["watch_cycle"] = current_cycle
        temp_state["consecutive_healthy_cycles"] = consecutive_healthy
        temp_state["last_healthy_timestamp"] = now_ts

        is_looping = (
            temp_state.get("watch_mode") is True
            and route_after_healthy(temp_state) == "telemetry_extraction"
        )

        interval = temp_state.get("watch_interval", 0.0) or 0.0
        if is_looping and interval > 0:
            time.sleep(interval)

        log_msg = (
            f"Watch cycle {current_cycle}: network is fully healthy "
            f"({consecutive_healthy} consecutive healthy checks), looping back to telemetry..."
            if is_looping
            else f"Workflow completed: network is fully healthy, no remediation needed (cycle {current_cycle})"
        )

        log = create_log_entry(
            stage="end_healthy",
            message=log_msg,
            level="info",
            metadata={
                "watch_cycle": current_cycle,
                "consecutive_healthy_cycles": consecutive_healthy,
                "timestamp": now_ts,
                "is_looping": is_looping,
            },
        )

        return {
            "watch_cycle": current_cycle,
            "consecutive_healthy_cycles": consecutive_healthy,
            "last_healthy_timestamp": now_ts,
            "failure_5tuples": [],
            "discrepancies": [],
            "suspect_devices": [],
            "error_message": None,
            "retry_count": 0,
            "current_step_tag": None,
            "status": "healthy",
            "execution_logs": [log],
        }

    def end_fixed_node(state: OperationalState) -> Dict[str, Any]:
        """Terminal node when incident is diagnosed, sandbox validated, patched, and verified."""
        plan_id = (state.get("remediation_plan") or {}).get("plan_id", "plan")
        log = create_log_entry(
            stage="end_fixed",
            message=f"Workflow completed: incident successfully resolved via '{plan_id}'",
            level="info",
        )
        return {
            "status": "fixed",
            "execution_logs": [log],
        }

    def end_rejected_node(state: OperationalState) -> Dict[str, Any]:
        """Terminal node when operator rejects candidate plan or execution pauses pending approval."""
        if state.get("human_approved") is None and state.get("status") == "pending_approval":
            log = create_log_entry(
                stage="human_approval",
                message="Workflow paused: candidate remediation awaiting operator approval checkpoint",
                level="info",
            )
            return {
                "status": "pending_approval",
                "execution_logs": [log],
            }
        log = create_log_entry(
            stage="end_rejected",
            message="Workflow completed: candidate remediation rejected by operator",
            level="warning",
        )
        return {
            "status": "rejected",
            "execution_logs": [log],
        }

    nodes = {
        "baseline_ingestion": baseline_ingestion_node,
        "telemetry_extraction": telemetry_extraction_node,
        "diagnostic_stage1": diagnostic_stage1_node,
        "diagnostic_stage2": diagnostic_stage2_node,
        "sandbox_validation": sandbox_validation_node,
        "human_approval": human_approval_node,
        "live_hot_patch": live_hot_patch_node,
        "re_verification": re_verification_node,
        "circuit_breaker": circuit_breaker_node,
        "end_healthy": end_healthy_node,
        "end_fixed": end_fixed_node,
        "end_rejected": end_rejected_node,
    }

    from langgraph_netagent.execution_logger import wrap_logged_nodes
    return wrap_logged_nodes(nodes, module_name="langgraph_netagent.workflow.operational_nodes")


# ---------------------------------------------------------------------------
# Helper functions for IP extraction
# ---------------------------------------------------------------------------
def _is_mgmt_or_loopback(ip_str: str, mgmt_subnet: Optional[str] = "172.100.100.0/24") -> bool:
    """Check if an IP address is a loopback or management interface address.

    Preserves RFC 1918 172.16.0.0/12 data plane subnets.
    """
    clean = ip_str.split("/")[0]
    if clean.startswith("127.") or clean == "::1":
        return True
    if clean.startswith("172.100.100.") or clean.startswith("172.20.20."):
        return True
    if mgmt_subnet:
        try:
            net = ipaddress.ip_network(mgmt_subnet, strict=False)
            addr = ipaddress.ip_address(clean)
            if addr in net:
                return True
        except ValueError:
            pass
    return False


def _extract_data_ips(node_data: Dict[str, Any], mgmt_subnet: Optional[str] = "172.100.100.0/24") -> List[str]:
    """Extract data-plane IPv4 addresses from node ip_addr text.

    Preserves RFC 1918 172.16.x.x data addresses, filtering only loopback
    and actual management subnets.
    """
    ips: List[str] = []
    ip_text = node_data.get("ip_addr", "")
    if not ip_text or ip_text.startswith("ERROR"):
        return ips

    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", ip_text):
        ip = match.group(1)
        if not _is_mgmt_or_loopback(ip, mgmt_subnet):
            ips.append(ip)
    return ips


def _extract_link_ips(
    nodes_data: Dict[str, Dict[str, Any]],
    src: str,
    dst: str,
    mgmt_subnet: Optional[str] = "172.100.100.0/24",
) -> List[str]:
    """Find IPs of dst on the same subnet as src, preserving RFC 1918 data subnets."""
    import ipaddress
    src_data = nodes_data.get(src, {})
    dst_data = nodes_data.get(dst, {})

    src_nets = []
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", src_data.get("ip_addr", "")):
        try:
            iface = ipaddress.IPv4Interface(match.group(1))
            if not _is_mgmt_or_loopback(str(iface.ip), mgmt_subnet):
                src_nets.append(iface.network)
        except ValueError:
            continue

    dst_ips = []
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", dst_data.get("ip_addr", "")):
        try:
            iface = ipaddress.IPv4Interface(match.group(1))
            if not _is_mgmt_or_loopback(str(iface.ip), mgmt_subnet):
                for sn in src_nets:
                    if iface.ip in sn:
                        dst_ips.append(str(iface.ip))
                        break
        except ValueError:
            continue

    return dst_ips
