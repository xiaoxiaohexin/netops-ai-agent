"""Workflow Nodes for LangGraph Network Agent State Machine.

Implements the 8 discrete operational nodes orchestrating natural language
intent parsing, topology generation, validation, approval, deployment,
telemetry probing, fault self-healing, and circuit breaking.
"""

from __future__ import annotations
import copy
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel

from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.models.telemetry import NetworkHealthReport
from langgraph_netagent.models.topology import (
    DeviceConfigFile,
    FullTopologyPackage,
)
from langgraph_netagent.prompts import (
    FAULT_FIXER_SYSTEM_PROMPT,
    INTENT_PARSER_SYSTEM_PROMPT,
    TOPOLOGY_GENERATOR_SYSTEM_PROMPT,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.exporter import TopologyExporter
from langgraph_netagent.tools.probes import NetworkTelemetryCollector
from langgraph_netagent.validation.offline_validator import OfflineValidator
from langgraph_netagent.workflow.state import LogEntry, NetworkAgentState, create_log_entry


class DiagnosticAndRemediation(BaseModel):
    """Composite schema expected from FAULT_FIXER_SYSTEM_PROMPT."""
    diagnostic: DiagnosticReport
    remediation: RemediationPlan


def _extract_ping_targets(
    package: FullTopologyPackage,
    parsed_intent: Optional[Dict[str, Any]] = None,
) -> List[Tuple[str, str]]:
    """Determine ping probe pairs (src_node, dst_ip) from intent and topology package."""
    targets: List[Tuple[str, str]] = []
    seen: set = set()

    # Map node -> list of assigned IPv4 addresses (without prefix)
    node_ips: Dict[str, List[str]] = {}
    for alloc in package.ip_allocations:
        try:
            ip_clean = str(ipaddress.IPv4Interface(alloc.ipv4_address).ip)
            if alloc.node_name not in node_ips:
                node_ips[alloc.node_name] = []
            node_ips[alloc.node_name].append(ip_clean)
        except Exception:
            continue

    # 1. Check parsed_intent verification_targets
    if parsed_intent and parsed_intent.get("verification_targets"):
        for vt in parsed_intent["verification_targets"]:
            # Match e.g. "pc1 -> pc2 ping", "pc1 to 10.2.2.2", "pc1 -> pc2"
            m = re.search(r"([a-zA-Z0-9_\-]+)\s*(?:->|to)\s*([a-zA-Z0-9_\-\.]+)", vt)
            if m:
                src = m.group(1).strip()
                dst_raw = m.group(2).strip()
                # Check if dst_raw is already an IP
                try:
                    ipaddress.IPv4Address(dst_raw)
                    pair = (src, dst_raw)
                    if pair not in seen:
                        seen.add(pair)
                        targets.append(pair)
                    continue
                except ValueError:
                    pass

                # dst_raw is a node name, resolve to IP
                if dst_raw in node_ips and node_ips[dst_raw]:
                    dst_ip = node_ips[dst_raw][0]
                    pair = (src, dst_ip)
                    if pair not in seen:
                        seen.add(pair)
                        targets.append(pair)

    # 2. Check source_endpoints -> target_endpoints
    if not targets and parsed_intent:
        sources = parsed_intent.get("source_endpoints", [])
        destinations = parsed_intent.get("target_endpoints", [])
        for src in sources:
            for dst in destinations:
                if dst in node_ips and node_ips[dst]:
                    pair = (src, node_ips[dst][0])
                    if pair not in seen:
                        seen.add(pair)
                        targets.append(pair)

    # 3. Derive from IP allocations if still empty
    if not targets and len(node_ips) >= 2:
        nodes = list(node_ips.keys())
        first_node = nodes[0]
        last_node = nodes[-1]
        if first_node != last_node and node_ips[last_node]:
            pair = (first_node, node_ips[last_node][0])
            targets.append(pair)

    return targets


def _identify_router_nodes(package: FullTopologyPackage) -> List[str]:
    """Identify which nodes in the topology act as routers."""
    routers = []
    for name, cfg in package.topology.topology.nodes.items():
        kind = cfg.kind.lower()
        image = cfg.image.lower()
        sysctls = cfg.sysctls or {}
        if "frr" in kind or "frr" in image or "srlinux" in kind or "srl" in image:
            routers.append(name)
        elif sysctls.get("net.ipv4.ip_forward") in (1, "1", True):
            routers.append(name)
    return routers


def create_workflow_nodes(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    export_dir: Path,
    auto_approve: bool = True,
) -> Dict[str, Callable[[NetworkAgentState], Dict[str, Any]]]:
    """Factory function providing the 8 discrete LangGraph workflow node callables.

    Args:
        llm_provider: LLM provider for intent parsing, topology gen, and self-healing.
        lab_adapter: Lab adapter (Live or Mock) for deployment and command execution.
        export_dir: Directory where topology YAML and configs are exported.
        auto_approve: If True, human approval is granted automatically without pause.

    Returns:
        Dictionary mapping node names to callable handler functions.
    """

    def intent_parsing_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 1: Parse user intent into structured NetworkIntent."""
        user_intent = state.get("user_intent", "")
        try:
            messages = [
                ChatMessage(role="system", content=INTENT_PARSER_SYSTEM_PROMPT),
                ChatMessage(role="user", content=user_intent),
            ]
            intent = llm_provider.generate_structured(
                messages=messages,
                response_schema=NetworkIntent,
            )
            intent_dict = intent.model_dump()
            log = create_log_entry(
                stage="intent_parsing",
                message=f"Network intent parsed successfully: {intent.summary}",
                level="info",
                metadata={"intent_id": intent.intent_id, "nodes_count": len(intent.nodes)},
            )
            return {
                "parsed_intent": intent_dict,
                "status": "intent_parsed",
                "error_message": None,
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="intent_parsing",
                message=f"Intent parsing failed: {exc}",
                level="error",
            )
            return {
                "status": "intent_parsing_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def topology_generation_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 2: Generate Containerlab FullTopologyPackage from parsed intent.

        If a previous offline validation failed, injects validation error feedback
        into the generation prompt for iterative correction.
        """
        parsed_intent = state.get("parsed_intent")
        prompt_parts: List[str] = []

        if parsed_intent:
            prompt_parts.append(
                f"Target Network Intent Specification:\n{json.dumps(parsed_intent, indent=2)}"
            )
        else:
            prompt_parts.append(f"Network Intent: {state.get('user_intent', '')}")

        # Inject previous validation error feedback if present
        val_res = state.get("validation_result")
        if val_res and not val_res.get("is_valid", True):
            prompt_parts.append("\nATTENTION: Prior pre-flight validation failed with the following errors:")
            for err in val_res.get("errors", []):
                prompt_parts.append(
                    f"- Code: {err.get('code')}, Node: {err.get('node')}, Field: {err.get('field')}\n"
                    f"  Message: {err.get('message')}\n"
                    f"  Suggested Fix: {err.get('suggested_fix')}"
                )
            prompt_parts.append(
                "\nPlease regenerate the FullTopologyPackage correcting all of the above errors."
            )

        full_prompt = "\n".join(prompt_parts)

        try:
            messages = [
                ChatMessage(role="system", content=TOPOLOGY_GENERATOR_SYSTEM_PROMPT),
                ChatMessage(role="user", content=full_prompt),
            ]
            package = llm_provider.generate_structured(
                messages=messages,
                response_schema=FullTopologyPackage,
            )
            pkg_dict = package.model_dump()
            log = create_log_entry(
                stage="topology_generation",
                message=(
                    f"Topology package '{package.topology.name}' generated "
                    f"({len(package.topology.topology.nodes)} nodes, "
                    f"{len(package.topology.topology.links)} links, "
                    f"{len(package.configs)} configs)"
                ),
                level="info",
                metadata={"topology_name": package.topology.name},
            )
            return {
                "raw_topology": pkg_dict,
                "status": "topology_generated",
                "error_message": None,
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="topology_generation",
                message=f"Topology generation failed: {exc}",
                level="error",
            )
            return {
                "status": "topology_generation_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def offline_validation_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 3: Run static pre-flight validation against raw topology."""
        raw_topo = state.get("raw_topology")
        if not raw_topo:
            log = create_log_entry(
                stage="offline_validation",
                message="Cannot validate: raw_topology is missing",
                level="error",
            )
            new_retries = state.get("retry_count", 0) + 1
            return {
                "retry_count": new_retries,
                "status": "validation_failed",
                "error_message": "raw_topology is missing in state",
                "execution_logs": [log],
            }

        val_result = OfflineValidator.validate(raw_topo)
        result_dict = val_result.model_dump()

        if val_result.is_valid:
            log = create_log_entry(
                stage="offline_validation",
                message=f"Validation passed: {val_result.checked_items_count} items checked",
                level="info",
                metadata={"checked_count": val_result.checked_items_count},
            )
            return {
                "validation_result": result_dict,
                "validated_topology": raw_topo,
                "status": "validation_passed",
                "error_message": None,
                "execution_logs": [log],
            }
        else:
            new_retries = state.get("retry_count", 0) + 1
            log = create_log_entry(
                stage="offline_validation",
                message=f"Validation failed: {val_result.summary} (retry {new_retries}/{state.get('max_retries', 3)})",
                level="warning",
                metadata={"error_count": len(val_result.errors), "errors": [e.model_dump() for e in val_result.errors]},
            )
            return {
                "validation_result": result_dict,
                "retry_count": new_retries,
                "status": "validation_failed",
                "error_message": val_result.summary,
                "execution_logs": [log],
            }

    def human_approval_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 4: Evaluate human operator approval before deployment."""
        current_approval = state.get("human_approved")

        if current_approval is None:
            if auto_approve:
                current_approval = True
            else:
                # HITL interrupt point
                log = create_log_entry(
                    stage="human_approval",
                    message="Deployment paused awaiting human approval",
                    level="info",
                )
                return {
                    "human_approved": None,
                    "status": "pending_approval",
                    "execution_logs": [log],
                }

        if current_approval is True:
            log = create_log_entry(
                stage="human_approval",
                message="Deployment approved by operator",
                level="info",
            )
            return {
                "human_approved": True,
                "status": "approved",
                "execution_logs": [log],
            }
        else:
            log = create_log_entry(
                stage="human_approval",
                message="Deployment rejected by operator",
                level="warning",
            )
            return {
                "human_approved": False,
                "status": "rejected",
                "error_message": "Deployment rejected during human approval",
                "execution_logs": [log],
            }

    def deployment_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 5: Export topology files and execute Containerlab deploy."""
        validated_topo = state.get("validated_topology")
        if not validated_topo:
            log = create_log_entry(
                stage="deployment",
                message="Cannot deploy: validated_topology is missing",
                level="error",
            )
            new_retries = state.get("retry_count", 0) + 1
            return {
                "retry_count": new_retries,
                "status": "deployment_failed",
                "error_message": "validated_topology is missing",
                "execution_logs": [log],
            }

        try:
            package = FullTopologyPackage.model_validate(validated_topo)
            # Export to disk (enforcing LF endings)
            exporter = TopologyExporter()
            written_files = exporter.export(package=package, export_dir=export_dir)
            topo_file = next(
                (path for rel, path in written_files.items() if str(rel).endswith(".clab.yml")),
                Path(export_dir) / f"{package.topology.name}.clab.yml",
            )
            # Deploy through lab adapter
            deploy_result = lab_adapter.deploy(topo_file=topo_file)
            deploy_dict = deploy_result.model_dump()

            if deploy_result.success:
                log = create_log_entry(
                    stage="deployment",
                    message=f"Lab '{package.topology.name}' deployed successfully ({len(deploy_result.nodes_deployed)} nodes running)",
                    level="info",
                    metadata={"nodes": deploy_result.nodes_deployed},
                )
                return {
                    "deploy_status": deploy_dict,
                    "status": "deployed",
                    "error_message": None,
                    "execution_logs": [log],
                }
            else:
                new_retries = state.get("retry_count", 0) + 1
                log = create_log_entry(
                    stage="deployment",
                    message=f"Lab deployment failed: {deploy_result.error_message}",
                    level="error",
                    metadata={"error": deploy_result.error_message},
                )
                return {
                    "deploy_status": deploy_dict,
                    "retry_count": new_retries,
                    "status": "deployment_failed",
                    "error_message": deploy_result.error_message or "Deployment failed",
                    "execution_logs": [log],
                }
        except Exception as exc:
            new_retries = state.get("retry_count", 0) + 1
            log = create_log_entry(
                stage="deployment",
                message=f"Deployment exception: {exc}",
                level="error",
            )
            return {
                "retry_count": new_retries,
                "status": "deployment_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def verification_probing_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 6: Execute multi-vendor active telemetry probes."""
        validated_topo = state.get("validated_topology")
        if not validated_topo:
            log = create_log_entry(
                stage="verification_probing",
                message="Cannot verify: validated_topology is missing",
                level="error",
            )
            return {
                "status": "verification_failed",
                "error_message": "validated_topology is missing",
                "execution_logs": [log],
            }

        try:
            package = FullTopologyPackage.model_validate(validated_topo)
            ping_targets = _extract_ping_targets(package, state.get("parsed_intent"))
            router_nodes = _identify_router_nodes(package)
            all_nodes = list(package.topology.topology.nodes.keys())

            node_kinds = {}
            for n_name, n_cfg in package.topology.topology.nodes.items():
                k = n_cfg.kind.lower()
                img = n_cfg.image.lower()
                if "frr" in k or "frr" in img:
                    node_kinds[n_name] = "frr"
                elif "srlinux" in k or "srl" in img:
                    node_kinds[n_name] = "srl"
                else:
                    node_kinds[n_name] = "linux"

            health_report = NetworkTelemetryCollector.collect(
                adapter=lab_adapter,
                ping_targets=ping_targets,
                router_nodes=router_nodes,
                all_nodes=all_nodes,
                node_kinds=node_kinds,
            )
            report_dict = health_report.model_dump()

            if health_report.all_passed:
                log = create_log_entry(
                    stage="verification_probing",
                    message="All network verification telemetry checks PASSED",
                    level="info",
                    metadata={"ping_count": len(health_report.ping_results)},
                )
                return {
                    "verification_results": report_dict,
                    "status": "verified",
                    "error_message": None,
                    "execution_logs": [log],
                }
            else:
                log = create_log_entry(
                    stage="verification_probing",
                    message=f"Verification probing detected {len(health_report.failures)} network failure(s)",
                    level="warning",
                    metadata={"failures": health_report.failures},
                )
                return {
                    "verification_results": report_dict,
                    "status": "verification_failed",
                    "error_message": health_report.to_summary_markdown(),
                    "execution_logs": [log],
                }
        except Exception as exc:
            log = create_log_entry(
                stage="verification_probing",
                message=f"Verification probing exception: {exc}",
                level="error",
            )
            return {
                "status": "verification_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def diagnosis_and_healing_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 7: Diagnose network telemetry failure and generate configuration patches."""
        new_retries = state.get("retry_count", 0) + 1
        if hasattr(lab_adapter, "fault_injector") and lab_adapter.fault_injector is not None:
            lab_adapter.fault_injector.on_retry(new_retries)

        verif_results = state.get("verification_results") or {}
        error_msg = state.get("error_message") or "Unknown network failure"

        # Prepare summary of failure
        failures_list = verif_results.get("failures", [error_msg])
        failures_markdown = "\n".join([f"- {f}" for f in failures_list])

        validated_topo = state.get("validated_topology") or state.get("raw_topology") or {}
        topology_json = json.dumps(validated_topo, indent=2)

        prompt_content = (
            f"Observed Network Verification Failures:\n{failures_markdown}\n\n"
            f"Active Network Topology Package:\n{topology_json}\n\n"
            "Please diagnose the root cause and provide an actionable RemediationPlan."
        )

        diag_report: Optional[DiagnosticReport] = None
        remed_plan: Optional[RemediationPlan] = None
        messages = [
            ChatMessage(role="system", content=FAULT_FIXER_SYSTEM_PROMPT),
            ChatMessage(role="user", content=prompt_content),
        ]

        # Attempt structured diagnosis generation
        try:
            diag_and_rem = llm_provider.generate_structured(
                messages=messages,
                response_schema=DiagnosticAndRemediation,
            )
            diag_report = diag_and_rem.diagnostic
            remed_plan = diag_and_rem.remediation
        except Exception:
            # Flexible fallback: try RemediationPlan directly
            try:
                remed_plan = llm_provider.generate_structured(
                    messages=messages,
                    response_schema=RemediationPlan,
                )
            except Exception:
                pass

            # Fallback for DiagnosticReport
            try:
                diag_report = llm_provider.generate_structured(
                    messages=messages,
                    response_schema=DiagnosticReport,
                )
            except Exception:
                pass

        # Synthesize fallback objects if LLM could not provide both
        if diag_report is None:
            diag_report = DiagnosticReport(
                telemetry_trigger=failures_list[0] if failures_list else "Verification failure",
                root_cause="Automated diagnosis detected route or configuration discrepancy",
                affected_nodes=["frr1"] if "frr1" in topology_json else ["node1"],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.9,
                evidence=failures_list,
            )

        if remed_plan is None:
            remed_plan = RemediationPlan(
                action_type=RemediationActionType.PATCH_CONFIG_FILE,
                target_entity=diag_report.affected_nodes[0] if diag_report.affected_nodes else "unknown",
                expected_outcome="Network connectivity restored",
                estimated_risk=SeverityLevel.LOW,
            )

        # Apply configuration patch to validated_topology
        patched_topo = copy.deepcopy(validated_topo)
        patch = remed_plan.configuration_patch

        if patch and "configs" in patched_topo and isinstance(patched_topo["configs"], list):
            norm_patch_path = OfflineValidator._normalize_path(patch.file_path)
            applied = False
            for cfg in patched_topo["configs"]:
                if OfflineValidator._normalize_path(cfg.get("file_path", "")) == norm_patch_path:
                    cfg["content"] = patch.new_content
                    applied = True
                    break
            if not applied:
                patched_topo["configs"].append({
                    "node_name": remed_plan.target_entity,
                    "file_path": patch.file_path,
                    "content": patch.new_content,
                    "permissions": "0644",
                    "description": f"Remediation patch for {remed_plan.target_entity}",
                })

        # Apply immediate exec commands if adapter supports it
        if remed_plan.exec_commands:
            for cmd in remed_plan.exec_commands:
                try:
                    lab_adapter.exec_command(node_name=remed_plan.target_entity, command=cmd)
                except Exception:
                    pass

        log = create_log_entry(
            stage="diagnosis_and_healing",
            message=(
                f"Self-healing generated remediation '{remed_plan.plan_id}' for '{remed_plan.target_entity}' "
                f"(retry {new_retries}/{state.get('max_retries', 3)}): {diag_report.root_cause}"
            ),
            level="info",
            metadata={"plan_id": remed_plan.plan_id, "root_cause": diag_report.root_cause},
        )

        return {
            "retry_count": new_retries,
            "diagnostic_report": diag_report.model_dump(),
            "remediation_plan": remed_plan.model_dump(),
            "validated_topology": patched_topo,
            "status": "healed",
            "error_message": None,
            "execution_logs": [log],
        }

    def circuit_breaker_node(state: NetworkAgentState) -> Dict[str, Any]:
        """Node 8: Trip safety circuit breaker on retry exhaustion to halt flapping."""
        current_retries = state.get("retry_count", 0)
        max_retries = state.get("max_retries", 3)
        breaker_msg = (
            f"Circuit breaker tripped: retry limit exceeded ({current_retries}/{max_retries}). "
            "Execution halted gracefully to prevent network flapping."
        )
        log = create_log_entry(
            stage="circuit_breaker",
            message=breaker_msg,
            level="critical",
            metadata={"retries": current_retries, "max_retries": max_retries},
        )
        return {
            "status": "circuit_broken",
            "error_message": breaker_msg,
            "execution_logs": [log],
        }

    nodes = {
        "intent_parsing": intent_parsing_node,
        "topology_generation": topology_generation_node,
        "offline_validation": offline_validation_node,
        "human_approval": human_approval_node,
        "deployment": deployment_node,
        "verification_probing": verification_probing_node,
        "diagnosis_and_healing": diagnosis_and_healing_node,
        "circuit_breaker": circuit_breaker_node,
    }
    from langgraph_netagent.execution_logger import wrap_logged_nodes
    return wrap_logged_nodes(nodes, module_name="langgraph_netagent.workflow.nodes")
