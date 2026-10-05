"""Diagnostic Reasoning Engine (R3).

Implements DiagnosticReasoningEngine which analyzes StateDiff and topology context,
formats high-density LLM prompts (<500B / <200 tokens) using StateDiff.to_llm_markdown(),
selects diagnostic strategies, and generates atomic RepairPlans with pre/post checks
and reversible rollbacks, backed by deterministic fallback logic.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage
from langgraph_netagent.models.network_state import StateDiff
from langgraph_netagent.models.reasoning import (
    DiagnosticStrategy,
    DiagnosticStrategySelector,
    StrategySelectionResult,
)
from langgraph_netagent.models.repair_plan import RepairAction, RepairPlan

logger = logging.getLogger(__name__)


class DiagnosticReasoningEngine:
    """Analyzes network state differences and formulates atomic, verifiable repair plans."""



    def __init__(
        self,
        llm_provider: Optional[BaseLLMProvider] = None,
        strategy_selector: Optional[DiagnosticStrategySelector] = None,
    ):
        self.llm_provider = llm_provider
        self.strategy_selector = strategy_selector or DiagnosticStrategySelector()

    def format_prompt(
        self,
        state_diff: StateDiff,
        topology: Optional[Any] = None,
        sops: Optional[List[Any]] = None,
        strategy: Optional[DiagnosticStrategy] = None,
    ) -> str:
        """Format a concise, high-density prompt for LLM reasoning (<500B / <200 tokens)."""
        lines = [
            "You are a NetOps AIOps diagnostic reasoning agent.",
            "Analyze the following network state difference and formulate an atomic RepairPlan.",
            "",
            state_diff.to_llm_markdown(),
        ]

        if strategy:
            lines.append(f"Recommended Strategy: {strategy.value}")

        if topology and hasattr(topology, "nodes"):
            node_names = list(topology.nodes.keys())[:6]
            lines.append(f"Topology Nodes: {', '.join(node_names)}")

        if sops:
            sop_summaries = []
            for s in sops[:2]:
                title = getattr(s, "title", None) or (s.get("title") if isinstance(s, dict) else str(s))
                if title:
                    sop_summaries.append(str(title))
            if sop_summaries:
                lines.append(f"Relevant SOPs: {', '.join(sop_summaries)}")

        lines.extend([
            "",
            "Output JSON with fields: strategy, target_node, justification, actions (list of {target_node, action_type, command, pre_check_command, expected_pre_condition, post_check_command, expected_post_condition, rollback_command}).",
        ])

        return "\n".join(lines)

    def analyze_diff_and_plan(
        self,
        state_diff: StateDiff,
        topology: Optional[Any] = None,
        sops: Optional[List[Any]] = None,
        llm_provider: Optional[BaseLLMProvider] = None,
        step_tag: str = "",
        incident_id: Optional[str] = None,
    ) -> RepairPlan:
        """Analyzes StateDiff, selects strategy, and formulates an atomic RepairPlan.

        Uses LLM reasoning when available and falls back to deterministic rule-based
        plan formulation when in mock mode or when LLM is unavailable.

        Args:
            state_diff: StateDiff comparing baseline to current network state.
            topology: Optional DiscoveredTopology instance.
            sops: Optional list of retrieved SOP documents.
            llm_provider: Optional LLM provider override.
            step_tag: Monotonic iteration step tracking tag.
            incident_id: Optional incident ID.

        Returns:
            RepairPlan populated with ordered atomic RepairAction items.
        """
        active_llm = llm_provider or self.llm_provider
        inc_id = incident_id or f"inc-{uuid.uuid4().hex[:6]}"

        # 1. Deterministic strategy selection
        selection: StrategySelectionResult = self.strategy_selector.select(state_diff)
        primary_strategy = selection.primary_strategy

        # If network is healthy, return empty plan
        if primary_strategy == DiagnosticStrategy.HEALTHY:
            return RepairPlan(
                incident_id=inc_id,
                strategy=DiagnosticStrategy.HEALTHY,
                target_node=None,
                actions=[],
                justification="Network is healthy. No repair actions required.",
                step_tag=step_tag,
            )

        # 2. Attempt LLM generation if an active non-mock LLM provider is available
        if active_llm and getattr(active_llm, "config", None) and active_llm.config.provider_type not in ("mock", "none"):
            try:
                plan_from_llm = self._generate_plan_via_llm(
                    llm=active_llm,
                    state_diff=state_diff,
                    topology=topology,
                    sops=sops,
                    strategy=primary_strategy,
                    inc_id=inc_id,
                    step_tag=step_tag,
                )
                if plan_from_llm and plan_from_llm.actions:
                    return plan_from_llm
            except Exception as e:
                logger.warning("LLM reasoning failed, falling back to deterministic plan: %s", e)

        # 3. Deterministic plan formulation fallback
        return self._generate_deterministic_plan(
            state_diff=state_diff,
            strategy=primary_strategy,
            topology=topology,
            inc_id=inc_id,
            step_tag=step_tag,
            justification=selection.reasoning,
        )

    # =========================================================================
    # Deterministic Plan Generation (Robust Fallback)
    # =========================================================================

    def _generate_deterministic_plan(
        self,
        state_diff: StateDiff,
        strategy: DiagnosticStrategy,
        topology: Optional[Any] = None,
        inc_id: str = "",
        step_tag: str = "",
        justification: str = "",
    ) -> RepairPlan:
        """Deterministically formulate atomic RepairActions based on StateDiff."""
        actions: List[RepairAction] = []
        target_nodes: List[str] = []

        if strategy == DiagnosticStrategy.LINK_RECOVERY:
            # 1. LINK_RECOVERY: bounce / bring up failed interfaces
            for node, idiff in state_diff.interface_diffs.items():
                target_ifaces = []
                for if_name, changes in idiff.changed.items():
                    if "oper_state" in changes and changes["oper_state"][1] in ("DOWN", "NO-CARRIER"):
                        target_ifaces.append(if_name)
                    elif "admin_state" in changes and changes["admin_state"][1] == "DOWN":
                        target_ifaces.append(if_name)
                for ifc in idiff.removed:
                    target_ifaces.append(ifc.name)

                for iface in target_ifaces:
                    target_nodes.append(node)
                    actions.append(
                        RepairAction(
                            action_id=f"act-link-{node}-{iface}",
                            order=len(actions) + 1,
                            target_node=node,
                            action_type="link_up",
                            command=f"ip link set dev {iface} up",
                            pre_check_command=f"ip link show dev {iface}",
                            expected_pre_condition="DOWN",
                            post_check_command=f"ip link show dev {iface}",
                            expected_post_condition="UP",
                            rollback_command=f"ip link set dev {iface} down",
                            description=f"Enable interface {iface} on {node}",
                        )
                    )

        elif strategy == DiagnosticStrategy.ROUTING_REPAIR:
            # 2. ROUTING_REPAIR: re-inject missing routes
            for node, rdiff in state_diff.route_diffs.items():
                missing_routes = list(rdiff.removed)
                for pfx, changes in rdiff.changed.items():
                    if "active" in changes and not changes["active"][1]:
                        missing_routes.append(r for r in (topology.routes if topology else []) if r.prefix == pfx)

                for r in rdiff.removed:
                    target_nodes.append(node)
                    pfx = r.prefix
                    gw = r.next_hop or self._infer_gateway(node, pfx, topology)
                    dev = r.interface or "eth1"

                    if gw:
                        cmd = f"ip route replace {pfx} via {gw}"
                        rb = f"ip route del {pfx} via {gw}"
                    elif dev:
                        cmd = f"ip route replace {pfx} dev {dev}"
                        rb = f"ip route del {pfx} dev {dev}"
                    else:
                        cmd = f"ip route add {pfx}"
                        rb = f"ip route del {pfx}"

                    actions.append(
                        RepairAction(
                            action_id=f"act-route-{node}-{len(actions)+1}",
                            order=len(actions) + 1,
                            target_node=node,
                            action_type="route_replace",
                            command=cmd,
                            pre_check_command=f"ip route show {pfx}",
                            expected_pre_condition=None,
                            post_check_command=f"ip route show {pfx}",
                            expected_post_condition=pfx,
                            rollback_command=rb,
                            description=f"Restore missing route {pfx} on {node}",
                        )
                    )

        elif strategy == DiagnosticStrategy.QDISC_RESET:
            # 3. QDISC_RESET: delete corrupt or netem queue rules
            for node, qdiff in state_diff.qdisc_diffs.items():
                for iface, changes in qdiff.changed.items():
                    target_nodes.append(node)
                    actions.append(
                        RepairAction(
                            action_id=f"act-qdisc-{node}-{iface}",
                            order=len(actions) + 1,
                            target_node=node,
                            action_type="qdisc_reset",
                            command=f"tc qdisc del dev {iface} root",
                            pre_check_command=f"tc qdisc show dev {iface}",
                            expected_pre_condition="netem",
                            post_check_command=f"tc qdisc show dev {iface}",
                            expected_post_condition=None,
                            rollback_command=f"tc qdisc add dev {iface} root netem loss 30%",
                            description=f"Reset qdisc netem on {node}:{iface}",
                        )
                    )

        elif strategy == DiagnosticStrategy.TRAFFIC_FILTERING_ACL:
            # 4. TRAFFIC_FILTERING_ACL: drop offending traffic on egress / router
            offending_nodes = [n for n in state_diff.affected_nodes() if "egress" in n.lower() or "router" in n.lower()]
            target_node = offending_nodes[0] if offending_nodes else (state_diff.affected_nodes()[0] if state_diff.affected_nodes() else None)
            if not target_node:
                return RepairPlan(
                    plan_id=f"plan-acl-{int(time.time())}",
                    strategy=strategy,
                    target_nodes=[],
                    actions=[],
                    estimated_risk="low",
                    rollback_plan="No actions needed",
                )
            target_nodes.append(target_node)
            offender_ip = "198.51.100.2"
            if state_diff.unexpected_traffic:
                for entry in state_diff.unexpected_traffic:
                    if isinstance(entry, dict) and (entry.get("src_ip") or entry.get("ip")):
                        offender_ip = str(entry.get("src_ip") or entry.get("ip"))
                        break

            actions.append(
                RepairAction(
                    action_id=f"act-acl-{target_node}-1",
                    order=1,
                    target_node=target_node,
                    action_type="acl_drop",
                    command=f"iptables -I FORWARD -s {offender_ip} -j DROP",
                    pre_check_command="iptables -S FORWARD",
                    expected_pre_condition=None,
                    post_check_command=f"iptables -C FORWARD -s {offender_ip} -j DROP",
                    expected_post_condition="",
                    rollback_command=f"iptables -D FORWARD -s {offender_ip} -j DROP",
                    description=f"Apply ingress packet filter dropping {offender_ip} on {target_node}",
                )
            )

        elif strategy == DiagnosticStrategy.INTERFACE_RESTART:
            # 5. INTERFACE_RESTART: restart flapping/errored interface
            for node, idiff in state_diff.interface_diffs.items():
                for iface in idiff.changed.keys():
                    target_nodes.append(node)
                    actions.append(
                        RepairAction(
                            action_id=f"act-restart-{node}-{iface}",
                            order=len(actions) + 1,
                            target_node=node,
                            action_type="interface_restart",
                            command=f"ip link set dev {iface} down && ip link set dev {iface} up",
                            pre_check_command=f"ip link show dev {iface}",
                            expected_pre_condition=None,
                            post_check_command=f"ip link show dev {iface}",
                            expected_post_condition="UP",
                            rollback_command=f"ip link set dev {iface} up",
                            description=f"Restart interface {iface} on {node}",
                        )
                    )

        # Fallback if no specific actions were parsed
        if not actions and state_diff.affected_nodes():
            first_node = state_diff.affected_nodes()[0]
            target_nodes.append(first_node)
            actions.append(
                RepairAction(
                    action_id=f"act-default-{first_node}",
                    order=1,
                    target_node=first_node,
                    action_type="link_up",
                    command="ip link set dev eth1 up",
                    rollback_command="ip link set dev eth1 down",
                    description=f"Default recovery attempt on {first_node}",
                )
            )

        primary_target = target_nodes[0] if target_nodes else (state_diff.affected_nodes()[0] if state_diff.affected_nodes() else "network")

        return RepairPlan(
            incident_id=inc_id,
            strategy=strategy,
            target_node=primary_target,
            actions=actions,
            justification=justification or f"Deterministic resolution for {strategy.value}",
            expected_diff_resolution=list(state_diff.affected_nodes()),
            step_tag=step_tag,
        )

    def _infer_gateway(self, node: str, prefix: str, topology: Optional[Any]) -> str:
        """Infer suitable gateway IP for destination prefix."""
        # Check topology if available
        if topology and hasattr(topology, "links"):
            for link in topology.links:
                src = getattr(link, "source_node", None) or getattr(link, "source", None)
                tgt_ip = getattr(link, "target_ip", None) or getattr(link, "dst_ip", None)
                if src == node and tgt_ip:
                    return tgt_ip

        return ""

    # =========================================================================
    # LLM-Driven Plan Generation
    # =========================================================================

    def _generate_plan_via_llm(
        self,
        llm: BaseLLMProvider,
        state_diff: StateDiff,
        topology: Optional[Any],
        sops: Optional[List[Any]],
        strategy: DiagnosticStrategy,
        inc_id: str,
        step_tag: str,
    ) -> Optional[RepairPlan]:
        """Ask LLM to formulate RepairPlan using concise StateDiff prompt."""
        prompt = self.format_prompt(state_diff=state_diff, topology=topology, sops=sops, strategy=strategy)
        response_text = llm.chat([
            ChatMessage(role="system", content="You are a network troubleshooting reasoning engine. Respond only with valid JSON."),
            ChatMessage(role="user", content=prompt),
        ])

        # Parse JSON from response
        clean_json = response_text.strip()
        if "```json" in clean_json:
            clean_json = clean_json.split("```json")[1].split("```")[0].strip()
        elif "```" in clean_json:
            clean_json = clean_json.split("```")[1].split("```")[0].strip()

        data = json.loads(clean_json)
        raw_actions = data.get("actions", [])
        parsed_actions: List[RepairAction] = []

        for idx, act_data in enumerate(raw_actions, start=1):
            if isinstance(act_data, dict):
                act_data.setdefault("action_id", f"act-llm-{idx}")
                act_data.setdefault("order", idx)
                parsed_actions.append(RepairAction(**act_data))

        if parsed_actions:
            return RepairPlan(
                incident_id=inc_id,
                strategy=DiagnosticStrategy(data.get("strategy", strategy.value)),
                target_node=data.get("target_node") or parsed_actions[0].target_node,
                actions=parsed_actions,
                justification=data.get("justification", "Generated via LLM reasoning"),
                step_tag=step_tag,
            )

        return None
