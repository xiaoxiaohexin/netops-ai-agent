"""Day-2 Operations Workflow Nodes for LangGraph Network Agent.

Implements the discrete operational nodes for Day-2 live network operations:
read_baseline -> probe_matrix -> hop_pruning -> llm_diagnosis ->
generate_patch -> dry_run_check -> human_approval -> hot_patch ->
re_verify -> (loop or END)
"""

from __future__ import annotations
import copy
import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple
import warnings

from pydantic import BaseModel

from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage
from langgraph_netagent.models.diagnostic import (
    DiagnosticReport,
    ErrorCategory,
    SeverityLevel,
)
from langgraph_netagent.models.remediation import (
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.prompts.day2_prompts import (
    DAY2_DIAGNOSIS_SYSTEM_PROMPT,
    DAY2_REMEDIATION_SYSTEM_PROMPT,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.baseline import BaselineCollector
from langgraph_netagent.tools.dry_run import DryRunChecker
from langgraph_netagent.tools.probes import (
    InterfaceProbe,
    NetworkTelemetryCollector,
    PingProbe,
    RouteTableProbe,
)
from langgraph_netagent.workflow.day2_state import (
    Day2OpsState,
    create_log_entry,
)


class DiagnosticAndRemediation(BaseModel):
    """Composite schema for combined diagnosis + remediation LLM output."""
    diagnostic: DiagnosticReport
    remediation: RemediationPlan


def create_day2_nodes(
    llm_provider: BaseLLMProvider,
    lab_adapter: BaseNetworkLabAdapter,
    lab_name: Optional[str] = None,
    auto_approve: bool = False,
) -> Dict[str, Callable[[Day2OpsState], Dict[str, Any]]]:
    """Factory function providing Day-2 LangGraph workflow node callables.

    Args:
        llm_provider: LLM provider for diagnosis and remediation generation.
        lab_adapter: Live Containerlab adapter for command execution.
        lab_name: Optional lab name for baseline collection.
        auto_approve: If True, human approval is granted automatically.

    Returns:
        Dictionary mapping node names to callable handler functions.
    """
    warnings.warn(
        "Day2 linear nodes are deprecated; please use harmonized operational workflow",
        DeprecationWarning,
        stacklevel=2,
    )

    def read_baseline_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 1: Read live baseline from running Containerlab network.

        Collects: container states, running configs, IP addresses, route tables.
        """
        try:
            baseline = BaselineCollector.collect(
                adapter=lab_adapter,
                lab_name=lab_name,
            )
            if baseline.get("error"):
                log = create_log_entry(
                    stage="read_baseline",
                    message=f"Baseline collection failed: {baseline['error']}",
                    level="error",
                )
                return {
                    "baseline": baseline,
                    "status": "baseline_failed",
                    "error_message": baseline["error"],
                    "execution_logs": [log],
                }

            node_count = len(baseline.get("nodes", {}))
            log = create_log_entry(
                stage="read_baseline",
                message=f"Baseline collected: {node_count} nodes, path={baseline.get('topology_path')}",
                level="info",
                metadata={
                    "node_count": node_count,
                    "topology_path": baseline.get("topology_path"),
                },
            )
            return {
                "baseline": baseline,
                "topology_path": baseline.get("topology_path"),
                "node_kinds": baseline.get("node_kinds"),
                "status": "baseline_ready",
                "error_message": None,
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="read_baseline",
                message=f"Baseline collection exception: {exc}",
                level="error",
            )
            return {
                "status": "baseline_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def probe_matrix_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 2: Execute full probe matrix across all network segments.

        Probes: ping end-to-end, route tables on routers, interface states on all nodes.
        """
        topology_path = state.get("topology_path") or []
        node_kinds = state.get("node_kinds") or {}

        if not topology_path:
            log = create_log_entry(
                stage="probe_matrix",
                message="Cannot probe: topology_path is empty",
                level="error",
            )
            return {
                "status": "probe_failed",
                "error_message": "No topology path available",
                "execution_logs": [log],
            }

        # Build ping targets: first PC -> last PC (end-to-end)
        ping_targets: List[Tuple[str, str]] = []
        pcs = [n for n in topology_path if node_kinds.get(n) == "linux"]
        routers = [n for n in topology_path if node_kinds.get(n) in ("frr", "srl")]

        # Get destination IPs from baseline
        baseline = state.get("baseline") or {}
        nodes_data = baseline.get("nodes", {})

        # End-to-end pings between PCs
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
                all_nodes=topology_path,
                node_kinds=node_kinds,
            )
            report_dict = health_report.model_dump()

            if health_report.all_passed:
                log = create_log_entry(
                    stage="probe_matrix",
                    message=f"All probes PASSED ({len(health_report.ping_results)} pings, {len(routers)} route tables)",
                    level="info",
                )
            else:
                log = create_log_entry(
                    stage="probe_matrix",
                    message=f"Probe failures detected: {len(health_report.failures)} issue(s)",
                    level="warning",
                    metadata={"failures": health_report.failures},
                )

            return {
                "probe_results": report_dict,
                "status": "probed",
                "error_message": None if health_report.all_passed else health_report.to_summary_markdown(),
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="probe_matrix",
                message=f"Probe matrix exception: {exc}",
                level="error",
            )
            return {
                "status": "probe_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def hop_pruning_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 3: Narrow down suspect devices by hop-by-hop segment probing.

        For each consecutive pair in topology_path, runs a segment ping
        to identify which specific hop(s) are failing.
        """
        topology_path = state.get("topology_path") or []
        node_kinds = state.get("node_kinds") or {}
        baseline = state.get("baseline") or {}
        nodes_data = baseline.get("nodes", {})

        if len(topology_path) < 2:
            log = create_log_entry(
                stage="hop_pruning",
                message="Cannot prune: topology_path has < 2 nodes",
                level="error",
            )
            return {
                "suspect_devices": topology_path,
                "status": "pruning_skipped",
                "execution_logs": [log],
            }

        segments: List[Dict[str, Any]] = []
        suspects: List[str] = []

        # Probe each consecutive hop
        for i in range(len(topology_path) - 1):
            src = topology_path[i]
            dst = topology_path[i + 1]

            # Get an IP of dst that src should be able to reach
            dst_ips = _extract_link_ips(nodes_data, src, dst)
            if not dst_ips:
                dst_ips = _extract_data_ips(nodes_data.get(dst, {}))

            segment_ok = True
            segment_detail = {"src": src, "dst": dst, "ips_tested": [], "passed": True}

            for dst_ip in dst_ips[:1]:  # Test first reachable IP
                try:
                    ping_result = PingProbe.run(
                        adapter=lab_adapter,
                        src_node=src,
                        dst_ip=dst_ip,
                        count=2,
                        timeout=2,
                    )
                    segment_detail["ips_tested"].append(dst_ip)
                    if not ping_result.is_reachable:
                        segment_ok = False
                        segment_detail["passed"] = False
                        segment_detail["error"] = ping_result.error_message
                except Exception as e:
                    segment_ok = False
                    segment_detail["passed"] = False
                    segment_detail["error"] = str(e)

            segments.append(segment_detail)
            if not segment_ok:
                # Both sides of a failed segment are suspects
                if src not in suspects:
                    suspects.append(src)
                if dst not in suspects:
                    suspects.append(dst)

        # If no segment-level failures but end-to-end fails, suspect routers AND end hosts
        if not suspects:
            suspects = [n for n in topology_path if node_kinds.get(n) in ("frr", "srl")]
            for n in topology_path:
                if n not in suspects:
                    suspects.append(n)

        log = create_log_entry(
            stage="hop_pruning",
            message=f"Hop pruning complete: {len(suspects)} suspect(s) from {len(segments)} segments",
            level="info",
            metadata={"suspects": suspects, "segments": segments},
        )

        return {
            "suspect_devices": suspects,
            "affected_segments": segments,
            "status": "pruned",
            "execution_logs": [log],
        }

    def llm_diagnosis_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 4: LLM-powered root cause diagnosis.

        Feeds probe failures + suspect devices + baseline to LLM for diagnosis.
        """
        probe_results = state.get("probe_results") or {}
        suspects = state.get("suspect_devices") or []
        segments = state.get("affected_segments") or []
        baseline = state.get("baseline") or {}
        topology_path = state.get("topology_path") or []

        # Build context for LLM
        failures = probe_results.get("failures", [])
        failures_md = "\n".join([f"- {f}" for f in failures])

        # Extract relevant baseline info for suspect devices and endpoint hosts involved in failures
        devices_to_include = list(suspects)
        for f in failures:
            for n in topology_path:
                if n in f and n not in devices_to_include:
                    devices_to_include.append(n)

        suspect_baseline = {}
        for s in devices_to_include:
            if s in baseline.get("nodes", {}):
                node_info = baseline["nodes"][s]
                suspect_baseline[s] = {
                    "kind": node_info.get("kind"),
                    "running_config": node_info.get("running_config", "")[:2000],
                    "route_table": node_info.get("route_table", "")[:1000],
                    "ip_addr": node_info.get("ip_addr", "")[:1000],
                }

        diag_schema = json.dumps(DiagnosticReport.model_json_schema(), indent=2)
        prompt = (
            f"## Probe Failures\n{failures_md}\n\n"
            f"## Suspect Devices (from hop-by-hop pruning)\n{json.dumps(suspects)}\n\n"
            f"## Segment Analysis\n{json.dumps(segments, indent=2)}\n\n"
            f"## Device Baseline & Routing Tables\n{json.dumps(suspect_baseline, indent=2)}\n\n"
            f"## Topology Path\n{json.dumps(topology_path)}\n\n"
            f"## Required Output JSON Schema\n```json\n{diag_schema}\n```\n\n"
            "Diagnose the root cause. Return ONLY a valid JSON object matching the schema above."
        )

        try:
            messages = [
                ChatMessage(role="system", content=DAY2_DIAGNOSIS_SYSTEM_PROMPT),
                ChatMessage(role="user", content=prompt),
            ]
            diag_report = llm_provider.generate_structured(
                messages=messages,
                response_schema=DiagnosticReport,
            )
        except Exception as exc:
            # Fallback: synthesize diagnosis from probe data
            import logging
            logging.getLogger(__name__).warning("LLM diagnosis exception: %s", exc)
            diag_report = DiagnosticReport(
                telemetry_trigger=failures[0] if failures else "Verification failure",
                root_cause="Automated diagnosis: route or configuration discrepancy on suspect device(s)",
                affected_nodes=suspects or ["unknown"],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                severity=SeverityLevel.HIGH,
                confidence_score=0.7,
                evidence=failures,
            )

        log = create_log_entry(
            stage="llm_diagnosis",
            message=f"Diagnosis: {diag_report.root_cause} (suspects: {diag_report.affected_nodes})",
            level="info",
            metadata={"report_id": diag_report.report_id},
        )

        return {
            "diagnostic_report": diag_report.model_dump(),
            "status": "diagnosed",
            "execution_logs": [log],
        }

    def generate_patch_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 5: Generate remediation plan with exec commands and config patches.

        Uses LLM to generate actionable fix based on diagnosis.
        """
        diag = state.get("diagnostic_report") or {}
        baseline = state.get("baseline") or {}
        topology_path = state.get("topology_path") or []

        # Extract target device config for context
        target = diag.get("affected_nodes", ["unknown"])[0] if diag.get("affected_nodes") else "unknown"
        target_node = baseline.get("nodes", {}).get(target, {})
        target_config = target_node.get("running_config", "")[:3000]
        target_routes = target_node.get("route_table", "")[:1000]
        target_ips = target_node.get("ip_addr", "")[:1000]

        remed_schema = json.dumps(RemediationPlan.model_json_schema(), indent=2)
        prompt = (
            f"## Diagnostic Report\n{json.dumps(diag, indent=2)}\n\n"
            f"## Target Device Info\n"
            f"Device: {target} (Kind: {target_node.get('kind', 'unknown')})\n"
            f"IP Addresses:\n```\n{target_ips}\n```\n"
            f"Route Table:\n```\n{target_routes}\n```\n"
            f"Running Config:\n```\n{target_config}\n```\n\n"
            f"## Topology Path\n{json.dumps(topology_path)}\n\n"
            f"## Required Output JSON Schema\n```json\n{remed_schema}\n```\n\n"
            "Generate an executable RemediationPlan JSON. Prefer runtime exec_commands for speed. "
            "Include rollback_steps. Return ONLY a valid JSON object matching the schema above."
        )

        try:
            messages = [
                ChatMessage(role="system", content=DAY2_REMEDIATION_SYSTEM_PROMPT),
                ChatMessage(role="user", content=prompt),
            ]
            remed_plan = llm_provider.generate_structured(
                messages=messages,
                response_schema=RemediationPlan,
            )
        except Exception as exc:
            # Fallback: minimal remediation plan
            import logging
            logging.getLogger(__name__).warning("LLM remediation exception: %s", exc)
            remed_plan = RemediationPlan(
                action_type=RemediationActionType.EXEC_RUNTIME_COMMAND,
                target_entity=target,
                expected_outcome="Network connectivity restored",
                estimated_risk=SeverityLevel.LOW,
            )

        log = create_log_entry(
            stage="generate_patch",
            message=f"Remediation plan '{remed_plan.plan_id}' for '{remed_plan.target_entity}': "
                    f"{len(remed_plan.exec_commands)} commands, "
                    f"risk={remed_plan.estimated_risk.value}",
            level="info",
            metadata={"plan_id": remed_plan.plan_id},
        )

        return {
            "remediation_plan": remed_plan.model_dump(),
            "status": "patch_generated",
            "execution_logs": [log],
        }

    def dry_run_check_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 6: Dry-run safety validation before execution.

        Checks: command safety, IP validity, config syntax, target existence.
        """
        remed_plan = state.get("remediation_plan") or {}
        baseline = state.get("baseline")

        passed, errors = DryRunChecker.check(
            remediation_plan=remed_plan,
            baseline=baseline,
        )

        if passed:
            log = create_log_entry(
                stage="dry_run_check",
                message="Dry-run passed: remediation plan is safe to execute",
                level="info",
            )
        else:
            log = create_log_entry(
                stage="dry_run_check",
                message=f"Dry-run issues: {len(errors)} finding(s)",
                level="warning",
                metadata={"errors": errors},
            )

        return {
            "dry_run_passed": passed,
            "dry_run_errors": errors if errors else None,
            "retry_count": state.get("retry_count", 0) + (0 if passed else 1),
            "status": "dry_run_passed" if passed else "dry_run_failed",
            "execution_logs": [log],
        }

    def human_approval_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 7: Human-in-the-loop approval gate.

        Displays remediation plan diff and risk assessment.
        In auto_approve mode, grants approval automatically.
        """
        if auto_approve:
            log = create_log_entry(
                stage="human_approval",
                message="Auto-approved: remediation plan cleared for execution",
                level="info",
            )
            return {
                "human_approved": True,
                "status": "approved",
                "execution_logs": [log],
            }

        current = state.get("human_approved")
        if current is True:
            log = create_log_entry(
                stage="human_approval",
                message="Operator approved remediation",
                level="info",
            )
            return {
                "human_approved": True,
                "status": "approved",
                "execution_logs": [log],
            }
        elif current is False:
            log = create_log_entry(
                stage="human_approval",
                message="Operator REJECTED remediation",
                level="warning",
            )
            return {
                "human_approved": False,
                "status": "rejected",
                "execution_logs": [log],
            }
        else:
            # Pending - display plan for review
            remed = state.get("remediation_plan") or {}
            log = create_log_entry(
                stage="human_approval",
                message=f"Awaiting approval for plan '{remed.get('plan_id', 'unknown')}' "
                        f"on '{remed.get('target_entity', 'unknown')}' "
                        f"({len(remed.get('exec_commands', []))} commands, "
                        f"risk={remed.get('estimated_risk', 'unknown')})",
                level="info",
            )
            return {
                "status": "pending_approval",
                "execution_logs": [log],
            }

    def hot_patch_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 8: Execute remediation commands on live network.

        Runs exec_commands via docker exec on the target container.
        """
        remed = state.get("remediation_plan") or {}
        target = remed.get("target_entity", "")
        exec_cmds = remed.get("exec_commands", [])

        results: List[Dict[str, Any]] = []
        all_ok = True

        for cmd in exec_cmds:
            # Strip any redundant 'docker exec <node>' prefix if LLM included it
            clean_cmd = re.sub(r"^docker\s+exec\s+(?:-it\s+)?[\w\-\.]+\s+", "", cmd).strip()
            try:
                cmd_result = lab_adapter.exec_command(
                    node_name=target,
                    command=clean_cmd,
                    timeout=15,
                )
                results.append({
                    "command": cmd,
                    "exit_code": cmd_result.exit_code,
                    "stdout": cmd_result.stdout[:500],
                    "stderr": cmd_result.stderr[:500],
                    "success": cmd_result.success,
                })
                if not cmd_result.success:
                    all_ok = False
            except Exception as e:
                results.append({
                    "command": cmd,
                    "exit_code": -1,
                    "stdout": "",
                    "stderr": str(e),
                    "success": False,
                })
                all_ok = False

        if all_ok:
            log = create_log_entry(
                stage="hot_patch",
                message=f"Hot-patch applied: {len(exec_cmds)} command(s) executed on '{target}'",
                level="info",
                metadata={"target": target, "commands_count": len(exec_cmds)},
            )
        else:
            log = create_log_entry(
                stage="hot_patch",
                message=f"Hot-patch partial failure on '{target}': check results",
                level="warning",
                metadata={"results": results},
            )

        return {
            "patch_result": {
                "target": target,
                "all_ok": all_ok,
                "results": results,
            },
            "status": "patched" if all_ok else "patch_failed",
            "execution_logs": [log],
        }

    def re_verify_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 9: Re-run probe matrix after hot-patch to confirm fix.

        Same logic as probe_matrix_node but stores in re_verify_results.
        """
        topology_path = state.get("topology_path") or []
        node_kinds = state.get("node_kinds") or {}
        baseline = state.get("baseline") or {}
        nodes_data = baseline.get("nodes", {})

        pcs = [n for n in topology_path if node_kinds.get(n) == "linux"]
        routers = [n for n in topology_path if node_kinds.get(n) in ("frr", "srl")]

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
                all_nodes=topology_path,
                node_kinds=node_kinds,
            )
            report_dict = health_report.model_dump()

            if health_report.all_passed:
                log = create_log_entry(
                    stage="re_verify",
                    message="Re-verification PASSED: fix confirmed",
                    level="info",
                )
            else:
                new_retries = state.get("retry_count", 0) + 1
                log = create_log_entry(
                    stage="re_verify",
                    message=f"Re-verification FAILED: {len(health_report.failures)} issue(s) remain "
                            f"(retry {new_retries}/{state.get('max_retries', 3)})",
                    level="warning",
                    metadata={"failures": health_report.failures},
                )
                return {
                    "re_verify_results": report_dict,
                    "retry_count": new_retries,
                    "status": "re_verify_failed",
                    "error_message": health_report.to_summary_markdown(),
                    "execution_logs": [log],
                }

            return {
                "re_verify_results": report_dict,
                "status": "re_verified",
                "error_message": None,
                "execution_logs": [log],
            }
        except Exception as exc:
            log = create_log_entry(
                stage="re_verify",
                message=f"Re-verification exception: {exc}",
                level="error",
            )
            return {
                "status": "re_verify_failed",
                "error_message": str(exc),
                "execution_logs": [log],
            }

    def circuit_breaker_node(state: Day2OpsState) -> Dict[str, Any]:
        """Node 10: Safety circuit breaker on retry exhaustion."""
        retries = state.get("retry_count", 0)
        max_r = state.get("max_retries", 3)
        msg = (
            f"Circuit breaker tripped: retry limit exceeded ({retries}/{max_r}). "
            "Manual intervention required."
        )
        log = create_log_entry(
            stage="circuit_breaker",
            message=msg,
            level="critical",
            metadata={"retries": retries, "max_retries": max_r},
        )
        return {
            "status": "circuit_broken",
            "error_message": msg,
            "execution_logs": [log],
        }

    def end_healthy_node(state: Day2OpsState) -> Dict[str, Any]:
        """Terminal node: network is healthy, no action needed."""
        log = create_log_entry(
            stage="end_healthy",
            message="Network healthy: all probes passed, no remediation needed",
            level="info",
        )
        return {
            "status": "healthy",
            "execution_logs": [log],
        }

    def end_fixed_node(state: Day2OpsState) -> Dict[str, Any]:
        """Terminal node: fault was detected, diagnosed, patched, and verified."""
        plan_id = (state.get("remediation_plan") or {}).get("plan_id", "unknown")
        log = create_log_entry(
            stage="end_fixed",
            message=f"Network fixed: remediation '{plan_id}' verified successfully",
            level="info",
        )
        return {
            "status": "fixed",
            "execution_logs": [log],
        }

    def end_rejected_node(state: Day2OpsState) -> Dict[str, Any]:
        """Terminal node: operator rejected the remediation plan."""
        log = create_log_entry(
            stage="end_rejected",
            message="Workflow ended: operator rejected remediation plan",
            level="warning",
        )
        return {
            "status": "rejected",
            "execution_logs": [log],
        }

    return {
        "read_baseline": read_baseline_node,
        "probe_matrix": probe_matrix_node,
        "hop_pruning": hop_pruning_node,
        "llm_diagnosis": llm_diagnosis_node,
        "generate_patch": generate_patch_node,
        "dry_run_check": dry_run_check_node,
        "human_approval": human_approval_node,
        "hot_patch": hot_patch_node,
        "re_verify": re_verify_node,
        "circuit_breaker": circuit_breaker_node,
        "end_healthy": end_healthy_node,
        "end_fixed": end_fixed_node,
        "end_rejected": end_rejected_node,
    }


# ---------------------------------------------------------------------------
# Helper functions for IP extraction from baseline data
# ---------------------------------------------------------------------------

def _extract_data_ips(node_data: Dict[str, Any]) -> List[str]:
    """Extract data-plane IPv4 addresses from a node's ip_addr output.

    Filters out loopback (127.x) and management (172.20.20.x, 172.100.100.x) addresses.
    """
    import re
    ips: List[str] = []
    ip_text = node_data.get("ip_addr", "")
    if not ip_text or ip_text.startswith("ERROR"):
        return ips

    mgmt_ip = str(node_data.get("mgmt_ipv4", "")).split("/")[0]

    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", ip_text):
        ip = match.group(1)
        # Skip loopback and specific management addresses
        if (
            not ip.startswith("127.")
            and ip != mgmt_ip
            and not ip.startswith("172.20.20.")
            and not ip.startswith("172.100.100.")
        ):
            ips.append(ip)
    return ips


def _extract_link_ips(
    nodes_data: Dict[str, Dict[str, Any]],
    src: str,
    dst: str,
) -> List[str]:
    """Try to find an IP of dst that is on the same subnet as src.

    This is a best-effort heuristic for segment probing.
    """
    import ipaddress
    import re

    src_data = nodes_data.get(src, {})
    dst_data = nodes_data.get(dst, {})

    src_mgmt = str(src_data.get("mgmt_ipv4", "")).split("/")[0]
    dst_mgmt = str(dst_data.get("mgmt_ipv4", "")).split("/")[0]

    src_nets = []
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", src_data.get("ip_addr", "")):
        try:
            iface = ipaddress.IPv4Interface(match.group(1))
            ip_str = str(iface.ip)
            if not ip_str.startswith("127.") and ip_str != src_mgmt and not ip_str.startswith("172.20.20."):
                src_nets.append(iface.network)
        except ValueError:
            continue

    dst_ips = []
    for match in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+/\d+)", dst_data.get("ip_addr", "")):
        try:
            iface = ipaddress.IPv4Interface(match.group(1))
            ip_str = str(iface.ip)
            if not ip_str.startswith("127.") and ip_str != dst_mgmt and not ip_str.startswith("172.20.20."):
                # Check if on same subnet as any src interface
                for sn in src_nets:
                    if iface.ip in sn:
                        dst_ips.append(str(iface.ip))
                        break
        except ValueError:
            continue

    return dst_ips
