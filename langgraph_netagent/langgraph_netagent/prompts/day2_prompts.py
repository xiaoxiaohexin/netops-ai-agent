"""Day-2 Operations LLM Prompt Templates.

Prompts for live network fault diagnosis and remediation generation,
designed for Day-2 operations where the topology is already deployed.
"""

from typing import Any, Dict, List, Optional

DAY2_DIAGNOSIS_SYSTEM_PROMPT = """You are a Day-2 Network Operations SRE Agent. Your mission is to analyze live probe failures from a Containerlab network and diagnose the root cause.

Context:
- The network is already deployed and was previously working.
- You are given: (1) probe failures, (2) suspect devices identified by hop-by-hop pruning, (3) current running configs and baseline.

Analysis Process (RACE Framework):
1. **Reasoning**: What failure pattern do the probes show? (e.g., total blackhole vs partial loss, which segments fail)
2. **Action**: What specific checks should be performed on suspect devices?
3. **Context**: What does the baseline config tell you about the expected state?
4. **Evidence**: What concrete CLI output supports your diagnosis?

Device-Specific Knowledge:
- FRR (FRRouting): Use `vtysh -c 'show ip route'`, `vtysh -c 'show interface'`. Config file: /etc/frr/frr.conf
- Nokia SR Linux: Use `sr_cli 'show network-instance default route-table'`, `sr_cli 'show interface'`
- Linux PC: Use `ip route show`, `ip addr show`, check default gateway

Common Fault Categories:
- routing_misconfig: Missing or wrong static/dynamic routes
- interface_down: Admin or oper-state down on a critical interface
- ip_subnet_mismatch: IP addresses on different subnets across a link
- gateway_unreachable: Default gateway IP not responding
- config_syntax_error: Invalid configuration preventing daemon startup

Output Format:
Return a JSON object strictly matching this schema:
{
  "telemetry_trigger": "String describing the failure that triggered diagnosis",
  "root_cause": "Clear root cause statement",
  "affected_nodes": ["node1", "node2"],
  "error_category": "routing_misconfig|interface_down|ip_subnet_mismatch|gateway_unreachable|firewall_filter_drop|arp_resolution_fail|unknown",
  "severity": "low|medium|high|critical",
  "confidence_score": 0.95,
  "evidence": ["cli evidence 1", "cli evidence 2"]
}
Do NOT include markdown commentary outside the JSON block.
"""

DAY2_REMEDIATION_SYSTEM_PROMPT = """You are a Day-2 Network Remediation Specialist. Based on a DiagnosticReport, generate an executable RemediationPlan.

Constraints:
- This is a LIVE network. Commands execute directly inside the target node. Do NOT include 'docker exec' or 'ssh' prefixes.
- Prefer runtime commands (vtysh, sr_cli, ip route, ip link) over config file patches for speed.
- If config file patches are needed, provide the FULL corrected config content.
- Always include rollback steps in case verification fails.

Device-Specific Fix Commands:
- FRR: `vtysh -c 'configure terminal' -c 'ip route <prefix> <nexthop>'`
- FRR interface: `vtysh -c 'configure terminal' -c 'interface <iface>' -c 'no shutdown'`
- SRL: `sr_cli 'enter candidate' '/network-instance default static-routes route <prefix> next-hop-group <nhg>' 'commit now'`
- Linux route: `ip route replace <prefix> via <gateway> dev <iface>`
- Linux interface: `ip link set dev <iface> up`

Risk Assessment:
- LOW: Adding a missing route, bringing up an interface
- MEDIUM: Changing an existing route's next-hop
- HIGH: Modifying BGP/OSPF configuration, changing IP addresses
- CRITICAL: Restarting daemons or containers

Output Format:
Return a JSON object strictly matching this schema:
{
  "action_type": "exec_runtime_command",
  "target_entity": "<target_node_name>",
  "exec_commands": ["<command_string_1>", "<command_string_2>"],
  "rollback_steps": [
    {
      "step_order": 1,
      "description": "Revert step 1",
      "action": "EXEC_COMMAND",
      "target_node": "<target_node_name>",
      "payload": "<revert_command_string>"
    }
  ],
  "expected_outcome": "Expected network state after applying fix",
  "estimated_risk": "low"
}
Do NOT nest commands inside objects; `exec_commands` must be an array of strings.
"""

DAY2_HOP_ANALYSIS_PROMPT = """Given the following probe failures and topology path, identify which specific hop(s) are causing the failure.

Topology Path: {topology_path}
Failed Probes: {failed_probes}
Segment Probe Results: {segment_results}

For each suspect device, explain WHY it is suspected based on the segment probe results.
Return a JSON object with:
- "suspect_devices": list of device names
- "analysis": string explaining the reasoning
- "recommended_checks": list of specific commands to run on each suspect device
"""

DAY2_DYNAMIC_TOPOLOGY_SECTION = """## Discovered Network Topology
- Routers: {routers}
- Subnets: {subnets}
- Virtual IPs (VIPs): {vips}
- Active Links: {active_links}
"""

DAY2_DYNAMIC_DIAGNOSIS_USER_PROMPT = """{topology_section}

## Enriched Diagnostic Context
{enriched_context}

## Retrieved SOP Playbooks
{sop_playbooks}

## Dual-Retrieval Vendor Knowledge
{dual_knowledge}

## Telemetry Failures (5-Tuple)
{failure_5tuples}

## Isolated Discrepancies
{discrepancies}

Generate an actionable DiagnosticReport and RemediationPlan for target '{target_node}'."""


def format_dynamic_topology_prompt(
    discovered_topology: Any,
    max_bytes: int = 500,
) -> str:
    """Format a concise markdown summary of the discovered network topology within budget.

    Includes summary of router nodes, interface paths/peerings, subnets, and VIPs.
    """
    if not discovered_topology:
        return ""

    routers: List[str] = []
    subnets: List[str] = []
    vips: List[str] = []
    links_summary: List[str] = []

    if hasattr(discovered_topology, "find_router_nodes"):
        routers = discovered_topology.find_router_nodes()
        subnets = getattr(discovered_topology, "subnets", [])
        vips = getattr(discovered_topology, "vips", [])
        links = getattr(discovered_topology, "links", [])
        for lnk in links[:4]:
            l_node = getattr(lnk, "local_node", "")
            l_iface = getattr(lnk, "local_iface", "")
            r_node = getattr(lnk, "remote_node", "")
            r_iface = getattr(lnk, "remote_iface", "")
            if l_node and r_node:
                links_summary.append(f"{l_node}:{l_iface}<->{r_node}:{r_iface}")
    elif isinstance(discovered_topology, dict):
        routers = discovered_topology.get("routers", []) or [
            n for n, d in (discovered_topology.get("nodes") or {}).items()
            if isinstance(d, dict) and d.get("role") in ("router", "egress", "gateway", "leaf", "spine")
        ]
        subnets = discovered_topology.get("subnets", [])
        vips = discovered_topology.get("vips", [])
        raw_links = discovered_topology.get("links", [])
        for lnk in raw_links[:4]:
            if isinstance(lnk, dict):
                ep = lnk.get("endpoints", [])
                if len(ep) >= 2:
                    links_summary.append(f"{ep[0]}<->{ep[1]}")
                elif "local_node" in lnk and "remote_node" in lnk:
                    links_summary.append(f"{lnk['local_node']}:{lnk.get('local_iface', '')}<->{lnk['remote_node']}:{lnk.get('remote_iface', '')}")

    lines = [
        "## Discovered Network Topology",
        f"- Routers: {', '.join(routers[:6]) if routers else 'none'}",
        f"- Subnets: {', '.join(subnets[:6]) if subnets else 'none'}",
    ]
    if vips:
        lines.append(f"- Virtual IPs (VIPs): {', '.join(vips[:4])}")
    if links_summary:
        lines.append(f"- Active Links: {', '.join(links_summary[:4])}")

    result = "\n".join(lines)
    encoded = result.encode("utf-8")
    if len(encoded) > max_bytes:
        truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
        return truncated.rsplit("\n", 1)[0]
    return result

