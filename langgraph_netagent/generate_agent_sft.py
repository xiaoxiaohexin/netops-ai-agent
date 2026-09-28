# -*- coding: utf-8 -*-
"""Generate SFT dataset aligned with the NetOps Agent workflow.

Reuses the project's own Pydantic schemas, system prompts, MockEngine and
FaultInjector so every generated sample is 100% schema-compliant and matches
the runtime Agent behavior. Output format mirrors data/sft_samples.jsonl:
{"messages": [{"role":"system",...},{"role":"user",...},{"role":"assistant",...}]}

Workflow nodes covered:
  1. intent     : natural language -> NetworkIntent
  2. topology   : NetworkIntent    -> FullTopologyPackage
  3. validation : FullTopologyPackage -> ValidationResult (valid + invalid)
  4. fixer      : failed telemetry + topology -> DiagnosticReport + RemediationPlan
"""
from __future__ import annotations

import ipaddress
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from langgraph_netagent.models.intent import NetworkIntent, NodeIntent, LinkIntent
from langgraph_netagent.models.topology import (
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    ContainerlabLinkEndpoint,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.models.validation import (
    ValidationErrorDetail,
    ValidationResult,
    ValidationSeverity,
)
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.tools.mock_engine import MockEngine
from langgraph_netagent.tools.fault_injector import FaultInjector, FaultRule, FaultType
from langgraph_netagent.tools.probes import NetworkTelemetryCollector
from langgraph_netagent.prompts.intent_prompts import INTENT_PARSER_SYSTEM_PROMPT
from langgraph_netagent.prompts.topology_prompts import TOPOLOGY_GENERATOR_SYSTEM_PROMPT
from langgraph_netagent.prompts.validation_prompts import SYNTAX_VALIDATOR_SYSTEM_PROMPT
from langgraph_netagent.prompts.fixer_prompts import FAULT_FIXER_SYSTEM_PROMPT

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "langgraph_netagent", "data", "sft_agent_workflow.jsonl")
SEED = 42


# --------------------------------------------------------------------------
# 1. Topology template variants
# --------------------------------------------------------------------------
def build_variant(variant_id: int, template: str, rng: random.Random):
    """Build a concrete network variant (nodes, links, IPs) from a template."""
    pool = [
        ("10.1", "1"), ("10.2", "2"), ("10.3", "3"), ("10.4", "4"),
        ("10.5", "5"), ("10.6", "6"), ("10.7", "7"), ("10.8", "8"),
    ]
    rng.shuffle(pool)

    def next_subnet(idx: int) -> str:
        a, b = pool[idx % len(pool)]
        return f"{a}.{b}.0/24"

    subnets = [next_subnet(i) for i in range(8)]

    if template == "host-frr-srl-host":
        nodes = [
            ("pc1", "host", "linux"),
            ("frr1", "router", "frr"),
            ("srl1", "router", "nokia_srlinux"),
            ("pc2", "host", "linux"),
        ]
        # links: (n1, if1, n2, if2, subnet)
        links = [
            ("pc1", "eth1", "frr1", "eth1", subnets[0]),
            ("frr1", "eth2", "srl1", "e1-1", subnets[1]),
            ("srl1", "e1-2", "pc2", "eth1", subnets[2]),
        ]
        protocols = ["static"]
        host_subnets = {("pc1", "eth1"): subnets[0], ("pc2", "eth1"): subnets[2]}
    elif template == "host-frr-host":
        nodes = [("pc1", "host", "linux"), ("frr1", "router", "frr"), ("pc2", "host", "linux")]
        links = [
            ("pc1", "eth1", "frr1", "eth1", subnets[0]),
            ("frr1", "eth2", "pc2", "eth1", subnets[1]),
        ]
        protocols = ["static"]
        host_subnets = {("pc1", "eth1"): subnets[0], ("pc2", "eth1"): subnets[1]}
    elif template == "host-srl-host":
        nodes = [("pc1", "host", "linux"), ("srl1", "router", "nokia_srlinux"), ("pc2", "host", "linux")]
        links = [
            ("pc1", "eth1", "srl1", "e1-1", subnets[0]),
            ("srl1", "e1-2", "pc2", "eth1", subnets[1]),
        ]
        protocols = ["static"]
        host_subnets = {("pc1", "eth1"): subnets[0], ("pc2", "eth1"): subnets[1]}
    elif template == "host-frr-frr-host":
        nodes = [
            ("pc1", "host", "linux"),
            ("frr1", "router", "frr"),
            ("frr2", "router", "frr"),
            ("pc2", "host", "linux"),
        ]
        links = [
            ("pc1", "eth1", "frr1", "eth1", subnets[0]),
            ("frr1", "eth2", "frr2", "eth1", subnets[1]),
            ("frr2", "eth2", "pc2", "eth1", subnets[2]),
        ]
        protocols = ["ospf"] if variant_id % 2 == 0 else ["static"]
        host_subnets = {("pc1", "eth1"): subnets[0], ("pc2", "eth1"): subnets[2]}
    else:  # host-frr-srl-frr-host
        nodes = [
            ("pc1", "host", "linux"),
            ("frr1", "router", "frr"),
            ("srl1", "router", "nokia_srlinux"),
            ("frr2", "router", "frr"),
            ("pc2", "host", "linux"),
        ]
        links = [
            ("pc1", "eth1", "frr1", "eth1", subnets[0]),
            ("frr1", "eth2", "srl1", "e1-1", subnets[1]),
            ("srl1", "e1-2", "frr2", "eth1", subnets[2]),
            ("frr2", "eth2", "pc2", "eth1", subnets[3]),
        ]
        protocols = ["static"]
        host_subnets = {("pc1", "eth1"): subnets[0], ("pc2", "eth1"): subnets[3]}

    # Assign IPs: host always takes .2, router always takes .1
    ip_map = {}  # (node, iface) -> cidr
    roles_map = {n: r for (n, r, _k) in nodes}
    for (n1, i1, n2, i2, subnet) in links:
        net = ipaddress.IPv4Network(subnet)
        base = int(net.network_address)
        if roles_map[n1] == "host":
            ip_map[(n1, i1)] = f"{ipaddress.IPv4Address(base + 2)}/{net.prefixlen}"
            ip_map[(n2, i2)] = f"{ipaddress.IPv4Address(base + 1)}/{net.prefixlen}"
        else:
            ip_map[(n1, i1)] = f"{ipaddress.IPv4Address(base + 1)}/{net.prefixlen}"
            ip_map[(n2, i2)] = f"{ipaddress.IPv4Address(base + 2)}/{net.prefixlen}"

    return nodes, links, ip_map, protocols


# --------------------------------------------------------------------------
# 2. Config file generation
# --------------------------------------------------------------------------
def gen_setup_sh(node: str, iface: str, ip_cidr: str, gw: str) -> str:
    return (
        "#!/bin/sh\nset -e\n"
        f"while ! ip link show {iface} >/dev/null 2>&1; do sleep 1; done\n"
        f"ip link set dev {iface} up\n"
        f"ip addr add {ip_cidr} dev {iface} 2>/dev/null || ip addr replace {ip_cidr} dev {iface}\n"
        f"ip route replace default via {gw} dev {iface}\n"
    )


def gen_frr_conf(hostname: str, iface_ips, static_routes, ospf: bool) -> str:
    lines = [
        "frr version 8.4",
        "frr defaults traditional",
        f"hostname {hostname}",
        "service integrated-vtysh-config",
        "!",
        "ip forwarding",
        "!",
    ]
    for (iface, ip_cidr) in iface_ips:
        lines += [f"interface {iface}", f" ip address {ip_cidr}", "!"]
    if ospf:
        lines += [
            "router ospf",
            " ospf router-id 1.1.1.1",
        ]
        for (iface, _ip) in iface_ips:
            net = str(ipaddress.IPv4Interface(_ip).network)
            lines.append(f" network {net} area 0")
        lines.append("!")
    for (pfx, nh) in static_routes:
        lines.append(f"ip route {pfx} {nh}")
        lines.append("!")
    lines += ["line vty", "!"]
    return "\n".join(lines)


def gen_frr_daemons(ospf: bool) -> str:
    return (
        "zebra=yes\nbgpd=no\n"
        f"ospfd={'yes' if ospf else 'no'}\n"
        "ospf6d=no\nripd=no\nripngd=no\nisisd=no\nfabricd=no\n"
        "staticd=yes\n"
    )


def gen_srl_cfg(hostname: str, iface_ips, static_routes) -> str:
    lines = [f"set / system name {hostname}"]
    for (iface, ip_cidr) in iface_ips:
        lines += [
            f"set / interface {iface} admin-state enable",
            f"set / interface {iface} subinterface 0 admin-state enable",
            f"set / interface {iface} subinterface 0 ipv4 admin-state enable",
            f"set / interface {iface} subinterface 0 ipv4 address {ip_cidr}",
        ]
    lines += [
        "set / network-instance default type default",
        "set / network-instance default admin-state enable",
    ]
    for (iface, _ip) in iface_ips:
        lines.append(f"set / network-instance default interface {iface}.0")
    for idx, (pfx, nh) in enumerate(static_routes):
        lines += [
            f"set / network-instance default next-hop-groups group nh-g{idx} admin-state enable",
            f"set / network-instance default next-hop-groups group nh-g{idx} nexthop 1 ip-address {nh}",
            f"set / network-instance default static-routes route {pfx} admin-state enable",
            f"set / network-instance default static-routes route {pfx} next-hop-group nh-g{idx}",
        ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# 3. Intent / Package builders (schema-native)
# --------------------------------------------------------------------------
def build_intent(variant_id: int, template: str, nodes, links, ip_map, protocols, rng: random.Random) -> NetworkIntent:
    node_objs = []
    for (name, role, kind) in nodes:
        subnets = sorted({ipaddress.IPv4Interface(ip_map[(name, iface)]).network for (n, iface) in ip_map if n == name}, key=str)
        node_objs.append(NodeIntent(name=name, role=role, device_kind=kind, subnets=[str(s) for s in subnets]))
    link_objs = []
    for (n1, i1, n2, i2, subnet) in links:
        link_objs.append(LinkIntent(source_node=n1, target_node=n2, subnet=subnet))
    hosts = [n for (n, r, _k) in nodes if r == "host"]
    raw = describe_intent(variant_id, template, nodes, links, ip_map, protocols)
    return NetworkIntent(
        raw_intent=raw,
        summary=f"Lab with {len(hosts)} hosts and {sum(1 for n in nodes if n[1]=='router')} routers using {protocols[0]} routing.",
        nodes=node_objs,
        links=link_objs,
        protocols=protocols,
        source_endpoints=[hosts[0]],
        target_endpoints=[hosts[-1]],
        verification_targets=[f"{hosts[0]} -> {hosts[-1]} ping"],
    )


def describe_intent(variant_id, template, nodes, links, ip_map, protocols) -> str:
    """Generate a natural-language request describing the topology."""
    host_roles = {n: r for (n, r, _k) in nodes}
    kinds = {n: k for (n, _r, k) in nodes}
    router_names = [n for (n, r, _k) in nodes if r == "router"]
    hosts = [n for n in host_roles if host_roles[n] == "host"]
    p1, p2 = hosts[0], hosts[-1]
    sub1 = ip_map[(p1, "eth1")].split("/")[0] + "/24"
    sub2 = ip_map[(p2, "eth1")].split("/")[0] + "/24"
    inter_sub = ip_map[(links[0][1] if False else links[0][3] if False else links[1][3], links[1][4])][0] if False else None

    # Compute interconnect subnets between routers
    inter_subs = []
    for (n1, i1, n2, i2, subnet) in links:
        if host_roles[n1] == "router" and host_roles[n2] == "router":
            inter_subs.append(subnet)

    kind_desc = {
        "frr": "an FRR router",
        "nokia_srlinux": "a Nokia SR Linux router",
        "linux": "a Linux host",
    }
    router_phrases = ", ".join(kind_desc[kinds[r]] for r in router_names)
    proto_phrase = protocols[0]

    tpls = [
        f"Build a Containerlab network lab connecting {p1} and {p2} via {router_phrases}. "
        f"{p1.upper()} subnet is {sub1}, {p2.upper()} subnet is {sub2}"
        + (f", router interconnect is {inter_subs[0]}" if inter_subs else "")
        + f". Use {proto_phrase} routing.",
        f"Deploy a {proto_phrase} routed lab with end hosts {p1} ({sub1}) and {p2} ({sub2}) "
        f"interconnected through {router_phrases}. Verify end-to-end reachability.",
        f"Create a multi-node Containerlab topology: {p1} -- {router_phrases} -- {p2}, "
        f"with {p1} on {sub1}, {p2} on {sub2}"
        + (f" and transit link {inter_subs[0]}" if inter_subs else "")
        + f". Routing protocol: {proto_phrase}.",
    ]
    return tpls[variant_id % len(tpls)]


def build_package(intent: NetworkIntent) -> FullTopologyPackage:
    """Build FullTopologyPackage from a NetworkIntent (schema-native)."""
    node_cfgs = {}
    configs = []
    ip_allocs = []
    iface_ips: dict = {}
    roles = {n.name: n.role for n in intent.nodes}
    kinds_map = {n.name: n.device_kind for n in intent.nodes}
    kinds = kinds_map  # alias used below
    # Per-node interface counter (stable, host=ethN, SR Linux=e1-N)
    iface_counter: dict = {}

    def next_iface(node: str) -> str:
        c = iface_counter.get(node, 0) + 1
        iface_counter[node] = c
        return f"e1-{c}" if kinds_map.get(node) == "nokia_srlinux" else f"eth{c}"

    link_objs = []
    for lk in intent.links:
        src, dst, sub = lk.source_node, lk.target_node, lk.subnet
        net = ipaddress.IPv4Network(sub)
        base = int(net.network_address)
        i1, i2 = next_iface(src), next_iface(dst)
        if roles.get(src) == "host":
            ip_a, ip_b = base + 2, base + 1
        else:
            ip_a, ip_b = base + 1, base + 2
        iface_ips[(src, i1)] = f"{ipaddress.IPv4Address(ip_a)}/{net.prefixlen}"
        iface_ips[(dst, i2)] = f"{ipaddress.IPv4Address(ip_b)}/{net.prefixlen}"
        link_objs.append((src, i1, dst, i2))

    # Determine router role
    static_routes = {n: [] for n in roles}  # node -> [(pfx, nh)]
    ospf_nodes = set()

    # Compute routes on routers
    for n, role in roles.items():
        if role != "router":
            continue
        my_ifaces = {i: c for (nn, i), c in iface_ips.items() if nn == n}
        for other, role2 in roles.items():
            if role2 == "router" or other == n:
                continue
            other_ifaces = {i: c for (nn, i), c in iface_ips.items() if nn == other}
            # host subnets owned by other host -> need route via neighbor router
            target_subnets = [str(ipaddress.IPv4Interface(c).network) for c in other_ifaces.values()]
            for ts in target_subnets:
                if any(ts == str(ipaddress.IPv4Interface(c).network) for c in my_ifaces.values()):
                    continue
                # find next-hop: peer router interface IP in my connected subnet that leads toward other
                nh = None
                for (n1, i1, n2, i2) in link_objs:
                    if n1 == n and n2 == other:
                        nh = iface_ips[(n2, i2)].split("/")[0]
                    elif n2 == n and n1 == other:
                        nh = iface_ips[(n1, i1)].split("/")[0]
                # multi-hop: route toward next router in chain
                if nh is None:
                    for (n1, i1, n2, i2) in link_objs:
                        if n1 == n and roles.get(n2) == "router":
                            nh = iface_ips[(n2, i2)].split("/")[0]
                        elif n2 == n and roles.get(n1) == "router":
                            nh = iface_ips[(n1, i1)].split("/")[0]
                if nh:
                    static_routes[n].append((ts, nh))

    # OSPF: no static routes needed between routers
    if any(p == "ospf" for p in intent.protocols):
        for n, role in roles.items():
            if role == "router" and kinds.get(n) == "frr":
                ospf_nodes.add(n)
        for n in ospf_nodes:
            static_routes[n] = []

    # Build node configs
    for n, role in roles.items():
        kind = kinds.get(n)
        my_ifaces = [(i, c) for (nn, i), c in iface_ips.items() if nn == n]
        if kind == "nokia_srlinux":
            node_cfgs[n] = ContainerlabNodeConfig(
                kind="nokia_srlinux", image="ghcr.io/nokia/srlinux", binds=[], exec=[],
                sysctls={}, startup_config="config/srl/srl.cfg", env={}, labels={},
            )
        elif role == "router":
            node_cfgs[n] = ContainerlabNodeConfig(
                kind="linux", image="frrouting/frr:latest",
                binds=[f"config/frr/{n}.conf:/etc/frr/frr.conf", f"config/frr/daemons:/etc/frr/daemons"],
                exec=[], sysctls={"net.ipv4.ip_forward": 1}, startup_config=None, env={}, labels={},
            )
        else:
            node_cfgs[n] = ContainerlabNodeConfig(
                kind="linux", image="alpine:latest",
                binds=[f"config/{n}/setup.sh:/setup.sh"], exec=["sh /setup.sh"],
                sysctls={}, startup_config=None, env={}, labels={},
            )

    # Generate config files
    for n, role in roles.items():
        kind = kinds.get(n)
        my_ifaces = [(i, c) for (nn, i), c in iface_ips.items() if nn == n]
        if kind == "nokia_srlinux":
            srl_routes = static_routes.get(n, [])
            content = gen_srl_cfg(n, my_ifaces, srl_routes)
            configs.append(DeviceConfigFile(node_name=n, file_path="config/srl/srl.cfg", content=content, permissions="0644", description="SR Linux interface and route config"))
        elif role == "router":
            ospf = n in ospf_nodes
            content = gen_frr_conf(n, my_ifaces, static_routes.get(n, []), ospf)
            configs.append(DeviceConfigFile(node_name=n, file_path=f"config/frr/{n}.conf", content=content, permissions="0644", description="FRR router interface and route config"))
            configs.append(DeviceConfigFile(node_name=n, file_path="config/frr/daemons", content=gen_frr_daemons(ospf), permissions="0644", description="FRR daemons enablement"))
        else:
            ip_cidr = my_ifaces[0][1]
            net = ipaddress.IPv4Interface(ip_cidr).network
            gw = str(ipaddress.IPv4Address(int(net.network_address) + 1))
            content = gen_setup_sh(n, my_ifaces[0][0], ip_cidr, gw)
            configs.append(DeviceConfigFile(node_name=n, file_path=f"config/{n}/setup.sh", content=content, permissions="0755", description="host network interface setup"))

    # IP allocations
    for (nn, ii), cidr in iface_ips.items():
        net = ipaddress.IPv4Interface(cidr).network
        gw = None
        if roles.get(nn) == "host":
            gw = str(ipaddress.IPv4Address(int(net.network_address) + 1))
        peer = None
        peer_if = None
        for (n1, i1, n2, i2) in link_objs:
            if n1 == nn and i1 == ii:
                peer, peer_if = n2, i2
            elif n2 == nn and i2 == ii:
                peer, peer_if = n1, i1
        ip_allocs.append(IPAllocation(node_name=nn, interface_name=ii, ipv4_address=cidr, gateway_ipv4=gw, peer_node=peer, peer_interface=peer_if))

    # Links
    cl_links = [ContainerlabLinkEndpoint(endpoints=[f"{a}:{b}", f"{c}:{d}"]) for (a, b, c, d) in link_objs]
    topo_file = ContainerlabTopologyFile(
        name="lab",
        mgmt=ContainerlabMgmtConfig(),
        topology=ContainerlabTopologyDefinition(nodes=node_cfgs, links=cl_links),
    )
    return FullTopologyPackage(topology=topo_file, configs=configs, ip_allocations=ip_allocs)


# --------------------------------------------------------------------------
# 4. Validation sample builders
# --------------------------------------------------------------------------
def build_validation_valid(pkg: FullTopologyPackage, n_checked: int) -> ValidationResult:
    return ValidationResult(
        is_valid=True, validator_name="offline_syntax_validator", errors=[], warnings=[],
        summary=f"All {len(pkg.topology.topology.nodes)} nodes, {len(pkg.topology.topology.links)} links, and {len(pkg.configs)} config files passed syntax and connectivity checks with zero violations.",
        checked_items_count=n_checked,
    )


def build_validation_invalid(pkg: FullTopologyPackage, defect: str, rng: random.Random) -> ValidationResult:
    errors = []
    summary = ""
    if defect == "unknown_node":
        node = rng.choice(list(pkg.topology.topology.nodes.keys()))
        errors.append(ValidationErrorDetail(
            code="UNKNOWN_NODE_IN_LINK", message=f"Link endpoint references node '{node}_ghost' which is not defined in topology.nodes.",
            node=node, field="topology.links", severity=ValidationSeverity.ERROR,
            suggested_fix="Remove or correct the link endpoint to reference an existing node.",
        ))
        summary = f"Validation failed: 1 link endpoint refers to undefined node."
    elif defect == "dup_ip":
        alloc = pkg.ip_allocations[0]
        errors.append(ValidationErrorDetail(
            code="IP_OVERLAP", message=f"Duplicate IP address {alloc.ipv4_address} assigned to multiple interfaces.",
            node=alloc.node_name, field="ip_allocations", severity=ValidationSeverity.ERROR,
            suggested_fix="Assign a unique IPv4 address to each interface.",
        ))
        summary = "Validation failed: duplicate IP address detected across interfaces."
    elif defect == "host_no_gateway":
        host_alloc = next(a for a in pkg.ip_allocations if a.gateway_ipv4 is not None)
        errors.append(ValidationErrorDetail(
            code="HOST_MISSING_GATEWAY", message=f"End host {host_alloc.node_name} has no default gateway configured.",
            node=host_alloc.node_name, field=host_alloc.interface_name, severity=ValidationSeverity.ERROR,
            suggested_fix="Configure a default route pointing to the directly connected router interface.",
        ))
        summary = "Validation failed: end host missing default gateway."
    return ValidationResult(
        is_valid=False, validator_name="offline_syntax_validator", errors=errors, warnings=[],
        summary=summary, checked_items_count=len(pkg.topology.topology.nodes) + len(pkg.topology.topology.links) + len(pkg.configs),
    )


# --------------------------------------------------------------------------
# 5. Diagnostic / Remediation sample builders (via MockEngine + FaultInjector)
# --------------------------------------------------------------------------
FAULT_SCENARIOS = [
    ("missing_route", ErrorCategory.ROUTING_MISCONFIG, SeverityLevel.HIGH),
    ("interface_down", ErrorCategory.INTERFACE_DOWN, SeverityLevel.HIGH),
    ("ping_drop", ErrorCategory.GATEWAY_UNREACHABLE, SeverityLevel.MEDIUM),
]


def build_fixer_sample(pkg: FullTopologyPackage, rng: random.Random):
    """Deploy package into MockEngine, inject a fault, collect telemetry, and emit diagnosis."""
    fault_name, _cat, _sev = rng.choice(FAULT_SCENARIOS)
    fi = FaultInjector()
    engine = MockEngine(fault_injector=fi)
    adapter = engine  # MockEngine exposes exec_command; wrap minimal
    engine.load_topology_package(pkg)

    hosts = [a.node_name for a in pkg.ip_allocations if a.gateway_ipv4 is not None]
    routers = [n for n, c in pkg.topology.topology.nodes.items() if c.sysctls.get("net.ipv4.ip_forward") == 1 or c.kind == "nokia_srlinux"]
    src, dst = hosts[0], hosts[-1]
    dst_ip = next(a.ipv4_address.split("/")[0] for a in pkg.ip_allocations if a.node_name == dst)
    # required routes on routers: host subnets
    required = {}
    host_subnets = {}
    for a in pkg.ip_allocations:
        if a.gateway_ipv4 is not None:
            host_subnets[a.node_name] = str(ipaddress.IPv4Interface(a.ipv4_address).network)
    for r in routers:
        required[r] = [host_subnets[h] for h in host_subnets if h != src or True]

    # inject fault
    injected = {}
    if fault_name == "missing_route" and len(routers) < 2:
        # a single router has no transit route to drop; fall back to interface_down
        fault_name = "interface_down"
    if fault_name == "missing_route":
        router = rng.choice(routers)
        pfx = host_subnets[dst]
        injected["router"], injected["pfx"] = router, pfx
        fi.add_rule(FaultRule(fault_type=FaultType.MISSING_ROUTE, target_node=router, target_ip_or_prefix=pfx))
    elif fault_name == "interface_down":
        node = rng.choice(routers + hosts)
        iface = next(a.interface_name for a in pkg.ip_allocations if a.node_name == node)
        injected["node"], injected["iface"] = node, iface
        fi.add_rule(FaultRule(fault_type=FaultType.INTERFACE_DOWN, target_node=node, target_interface=iface))
    else:  # ping_drop
        fi.add_rule(FaultRule(fault_type=FaultType.PING_DROP, target_node=src, target_ip_or_prefix=dst_ip))

    # collect telemetry
    kinds = {n: ("frr" if c.image.startswith("frrouting") else "nokia_srlinux" if c.kind == "nokia_srlinux" else "linux") for n, c in pkg.topology.topology.nodes.items()}
    report = NetworkTelemetryCollector.collect(
        adapter=adapter, ping_targets=[(src, dst_ip)], router_nodes=routers,
        all_nodes=list(pkg.topology.topology.nodes.keys()), node_kinds=kinds, required_routes=required,
    )

    # build user text (telemetry evidence)
    ping = report.ping_results[0]
    user_lines = [
        f"Verification probe failed: ping from {src} ({ping.src_node}) to {dst} ({dst_ip}) failed with {ping.loss_pct:.0f}% packet loss.",
        "Probe Output:",
        ping.raw_output.strip() or f"{ping.transmitted} packets transmitted, {ping.received} received, {ping.loss_pct}% packet loss",
    ]
    for rn in routers:
        rt = report.route_tables.get(rn)
        if rt:
            user_lines.append(f"\nRouter {rn} {'ip route' if kinds.get(rn)=='frr' else 'route'} dump:")
            user_lines.append(rt.raw_output.strip() or "\n".join(f"{r.destination} via {r.next_hop}" for r in rt.routes))
    user_text = "\n".join(user_lines)

    # Build diagnostic + remediation
    missing_prefixes = [f for f in report.failures if "Missing route" in f]
    roles = {a.node_name: ("host" if a.gateway_ipv4 is not None else "router") for a in pkg.ip_allocations}
    if fault_name == "missing_route" or missing_prefixes:
        router = injected.get("router") or routers[0]
        pfx = injected.get("pfx") or host_subnets[dst]
        nh = None
        for a in pkg.ip_allocations:
            if a.node_name == router and a.peer_node and roles.get(a.peer_node) == "router":
                peer_alloc = next((x for x in pkg.ip_allocations if x.node_name == a.peer_node and x.interface_name == a.peer_interface), None)
                if peer_alloc:
                    nh = peer_alloc.ipv4_address.split("/")[0]
                    break
        affected = [router, src, dst]
        root_cause = f"Router {router} is missing a route for destination network {pfx}. Packets forwarded from {src} are dropped due to no route to host."
        evidence = [
            f"Ping to {dst_ip} has 100% loss",
            f"{router} route table lacks prefix {pfx}",
            "Destination prefix absent in FIB",
        ]
        details = {"missing_prefix": pfx, "required_next_hop": nh}
        # config patch: add static route to frr.conf or srl.cfg
        cfg_file = next(c for c in pkg.configs if c.node_name == router and (c.file_path.endswith(".conf") or c.file_path.endswith(".cfg")))
        old_content = cfg_file.content
        if cfg_file.file_path.endswith(".conf"):
            new_content = old_content.rstrip("\n") + f"\nip route {pfx} {nh}\n!\n"
        else:
            new_content = old_content.rstrip("\n") + f"\nset / network-instance default static-routes route {pfx} admin-state enable\nset / network-instance default static-routes route {pfx} next-hop-group nh-g9\n"
        cpatch = ConfigurationPatch(file_path=cfg_file.file_path, patch_type="FULL_REPLACE", new_content=new_content, backup_content=old_content)
        exec_cmds = [f"docker exec clab-lab-{router} vtysh -c 'configure terminal' -c 'ip route {pfx} {nh}'"]
        rollback = [
            RollbackStep(step_order=1, description=f"Remove injected static route from {router} runtime", action="EXEC_COMMAND", target_node=router, payload=f"docker exec clab-lab-{router} vtysh -c 'configure terminal' -c 'no ip route {pfx} {nh}'"),
            RollbackStep(step_order=2, description="Restore previous config file without static route", action="RESTORE_FILE", target_node=router, payload=cfg_file.file_path),
        ]
        action_type = RemediationActionType.PATCH_CONFIG_FILE
        expected = f"{router} installs {pfx} via {nh} in routing table; ping from {src} to {dst_ip} succeeds with 0% packet loss"
        err_cat, sev = ErrorCategory.ROUTING_MISCONFIG, SeverityLevel.HIGH
    elif fault_name == "interface_down":
        node = injected.get("node") or next((a.node_name for a in pkg.ip_allocations if not a.node_name in hosts), routers[0])
        iface = injected.get("iface") or next(a.interface_name for a in pkg.ip_allocations if a.node_name == node)
        affected = [node, src, dst]
        root_cause = f"Interface {node}:{iface} is administratively/operationally DOWN, breaking the forwarding path between {src} and {dst}."
        evidence = [f"Interface {node}:{iface} state DOWN", f"Ping {src} -> {dst_ip} fails"]
        details = {"interface": f"{node}:{iface}", "required_state": "UP"}
        cpatch = None
        exec_cmds = [f"docker exec clab-lab-{node} ip link set dev {iface} up"]
        rollback = [RollbackStep(step_order=1, description=f"Bring interface {iface} back down", action="EXEC_COMMAND", target_node=node, payload=f"docker exec clab-lab-{node} ip link set dev {iface} down")]
        action_type = RemediationActionType.EXEC_RUNTIME_COMMAND
        expected = f"Interface {node}:{iface} transitions to UP; ping from {src} to {dst_ip} recovers"
        err_cat, sev = ErrorCategory.INTERFACE_DOWN, SeverityLevel.HIGH
    else:
        affected = [src, dst]
        root_cause = f"Forwarding path from {src} to {dst} ({dst_ip}) is broken: next-hop resolution or gateway reachability failed along the path."
        evidence = [f"Ping {src} -> {dst_ip}: {ping.loss_pct:.0f}% packet loss", "No healthy forwarding path found"]
        details = {"source": src, "destination": dst_ip, "loss_pct": ping.loss_pct}
        cpatch = None
        exec_cmds = [f"docker exec clab-lab-{src} ip route get {dst_ip}"]
        rollback = []
        action_type = RemediationActionType.EXEC_RUNTIME_COMMAND
        expected = f"Restore reachability so ping from {src} to {dst_ip} succeeds"
        err_cat, sev = ErrorCategory.GATEWAY_UNREACHABLE, SeverityLevel.MEDIUM

    diag = DiagnosticReport(
        telemetry_trigger=f"ping from {src} to {dst} ({dst_ip}) {ping.loss_pct:.0f}% packet loss",
        root_cause=root_cause, affected_nodes=affected, error_category=err_cat, severity=sev,
        confidence_score=0.95, evidence=evidence, details=details,
    )
    plan = RemediationPlan(
        action_type=action_type, target_entity=affected[0] if affected else routers[0],
        configuration_patch=cpatch, exec_commands=exec_cmds, rollback_steps=rollback,
        expected_outcome=expected, estimated_risk=SeverityLevel.LOW, requires_human_approval=False,
    )
    return user_text, diag, plan


# --------------------------------------------------------------------------
# 6. Assembler
# --------------------------------------------------------------------------
def msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def main():
    rng = random.Random(SEED)
    templates = ["host-frr-srl-host", "host-frr-host", "host-srl-host", "host-frr-frr-host", "host-frr-srl-frr-host"]
    variants_per_template = 4
    samples = []
    variant_id = 0

    for tpl in templates:
        for _v in range(variants_per_template):
            variant_id += 1
            nodes, links, ip_map, protocols = build_variant(variant_id, tpl, rng)
            intent = build_intent(variant_id, tpl, nodes, links, ip_map, protocols, rng)
            pkg = build_package(intent)

            # 1. intent sample
            samples.append({"messages": [
                msg("system", INTENT_PARSER_SYSTEM_PROMPT),
                msg("user", intent.raw_intent),
                msg("assistant", intent.model_dump_json()),
            ]})

            # 2. topology sample
            samples.append({"messages": [
                msg("system", TOPOLOGY_GENERATOR_SYSTEM_PROMPT),
                msg("user", f"Transform this network intent into a FullTopologyPackage:\n{intent.model_dump_json()}"),
                msg("assistant", pkg.model_dump_json()),
            ]})

            # 3. validation valid
            n_checked = len(pkg.topology.topology.nodes) + len(pkg.topology.topology.links) + len(pkg.configs)
            vr = build_validation_valid(pkg, n_checked)
            samples.append({"messages": [
                msg("system", SYNTAX_VALIDATOR_SYSTEM_PROMPT),
                msg("user", f"Audit this topology package for syntax, IP overlaps, and node link integrity:\n{pkg.model_dump_json()}"),
                msg("assistant", vr.model_dump_json()),
            ]})

            # 4. validation invalid (2 defects)
            for defect in ["unknown_node", "dup_ip"][:1 + variant_id % 2]:
                vri = build_validation_invalid(pkg, defect, rng)
                samples.append({"messages": [
                    msg("system", SYNTAX_VALIDATOR_SYSTEM_PROMPT),
                    msg("user", f"Audit this topology package for syntax, IP overlaps, and node link integrity:\n{pkg.model_dump_json()}"),
                    msg("assistant", vri.model_dump_json()),
                ]})

            # 5. fixer sample
            user_text, diag, plan = build_fixer_sample(pkg, rng)
            combined = json.dumps({"diagnostic": json.loads(diag.model_dump_json()), "remediation": json.loads(plan.model_dump_json())}, ensure_ascii=False)
            samples.append({"messages": [
                msg("system", FAULT_FIXER_SYSTEM_PROMPT),
                msg("user", user_text),
                msg("assistant", combined),
            ]})

    with open(OUT_PATH, "w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    # stats
    from collections import Counter
    sys_prompts = [s["messages"][0]["content"] for s in samples]
    node_names = {
        INTENT_PARSER_SYSTEM_PROMPT[:20]: "intent",
        TOPOLOGY_GENERATOR_SYSTEM_PROMPT[:20]: "topology",
        SYNTAX_VALIDATOR_SYSTEM_PROMPT[:20]: "validation",
        FAULT_FIXER_SYSTEM_PROMPT[:20]: "fixer",
    }
    counts = Counter(node_names[p[:20]] for p in sys_prompts)
    print("输出:", OUT_PATH)
    print("总条数:", len(samples))
    print("节点分布:", dict(counts))
    print("大小: {:.1f} MB".format(os.path.getsize(OUT_PATH) / 1024 / 1024))


if __name__ == "__main__":
    main()
