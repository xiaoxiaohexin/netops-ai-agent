#!/usr/bin/env python3
"""NetOps AI Agent Real-Time Stress Test Reaction Monitor.

Continuously observes and records:
1. Agent Process Health (PID, CPU%, Memory MB, Uptime, Lifecycle).
2. Gateway Firewall ACL State & Diffs (`clab-clos5-ext-router` iptables rules, packet/byte drop counters).
3. Bottleneck QoS & Buffer Telemetry (TC Qdisc overlimits, dropped packets, buffer backlog rate).
4. Protected Service Health (Ping loss, RTT, HTTP 200 response latency to target VIPs).
5. Incident Correlation & MTTR Engine (Attack detection -> Rule deployment -> Traffic stabilization).

Outputs:
- Timeline Text Log:   attack_logs/agent_reaction_monitor.log
- Metrics JSONL:       attack_logs/agent_reaction_metrics.jsonl
- Final Summary JSON:  attack_logs/stress_test_summary.json
"""

import argparse
import datetime
import json
import os
import platform
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Terminal ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_RED = "\033[31m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_BLUE = "\033[34m"
COLOR_MAGENTA = "\033[35m"
COLOR_CYAN = "\033[36m"
COLOR_WHITE = "\033[37m"


def strip_wsl_noise(text: str) -> str:
    """Filter out WSL2 startup diagnostic notices."""
    if not text:
        return ""
    clean_lines = []
    for line in text.splitlines():
        l_str = line.strip()
        l_condensed = "".join(l_str.split())
        if (
            l_str.startswith("wsl:")
            or l_str.startswith("w s l :")
            or "localhost" in l_condensed.lower()
            or ("wsl" in l_condensed.lower() and "nat" in l_condensed.lower())
        ):
            continue
        clean_lines.append(line)
    return "\n".join(clean_lines).strip()


class RealTimeAgentMonitor:
    """Multi-dimensional monitor observing Agent reactions during stress testing."""

    def __init__(
        self,
        interval: float = 2.0,
        target_vip: str = "203.0.113.10",
        target_vip_secondary: str = "203.0.113.40",
        log_file: str = "attack_logs/agent_reaction_monitor.log",
        metrics_file: str = "attack_logs/agent_reaction_metrics.jsonl",
        report_file: str = "attack_logs/stress_test_summary.json",
        wsl_distro: str = "Ubuntu",
        max_duration: Optional[float] = None,
    ):
        self.interval = interval
        self.target_vip = target_vip
        self.target_vip_secondary = target_vip_secondary
        self.wsl_distro = wsl_distro
        self.max_duration = max_duration

        # Ensure output directory exists
        self.log_path = Path(log_file).resolve()
        self.metrics_path = Path(metrics_file).resolve()
        self.report_path = Path(report_file).resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

        self.log_fp = open(self.log_path, "a", encoding="utf-8")
        self.metrics_fp = open(self.metrics_path, "a", encoding="utf-8")

        # Baseline & Historical State
        self.start_time = time.time()
        self.cycle_count = 0
        self.is_running = True

        self.last_qdisc_overlimits: Optional[int] = None
        self.last_qdisc_dropped: Optional[int] = None
        self.last_iptables_rules: List[Dict[str, Any]] = []
        self.known_agent_pid: Optional[int] = None

        # Statistics & Incident Tracking
        self.stats: Dict[str, Any] = {
            "start_time": datetime.datetime.now().isoformat(),
            "total_cycles": 0,
            "total_incidents_detected": 0,
            "total_defense_rules_deployed": 0,
            "total_probes": 0,
            "successful_http_probes": 0,
            "successful_ping_probes": 0,
            "peak_tc_overlimits": 0,
            "peak_tc_dropped": 0,
            "peak_agent_cpu": 0.0,
            "peak_agent_memory_mb": 0.0,
            "incidents": [],
            "rule_change_events": [],
        }

        # Active Incident Tracking
        self.active_incident: Optional[Dict[str, Any]] = None

        # Signal Handlers
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        self.log_event("SYSTEM", "Termination signal received. Generating summary report...", level="WARN")
        self.is_running = False

    def log_event(self, category: str, message: str, level: str = "INFO", extra: Optional[Dict[str, Any]] = None) -> None:
        """Log event to stdout with color and append detailed structured record to file."""
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Color mapping
        level_colors = {
            "INFO": COLOR_GREEN,
            "WARN": COLOR_YELLOW,
            "ALERT": COLOR_MAGENTA,
            "CRITICAL": f"{COLOR_BOLD}{COLOR_RED}",
            "REMEDIATION": f"{COLOR_BOLD}{COLOR_CYAN}",
            "AGENT": COLOR_BLUE,
        }
        color = level_colors.get(level.upper(), COLOR_WHITE)
        console_line = f"{COLOR_WHITE}[{now_str}]{COLOR_RESET} {color}[{level:<7}]{COLOR_RESET} {COLOR_BOLD}[{category:<11}]{COLOR_RESET} {message}"
        print(console_line)

        # File log
        file_line = f"[{now_str}] [{level:<7}] [{category:<11}] {message}"
        if extra:
            file_line += f" | {json.dumps(extra, ensure_ascii=False)}"
        self.log_fp.write(file_line + "\n")
        self.log_fp.flush()

    def run_cmd_in_wsl(self, cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
        """Execute command inside WSL distro with explicit UTF-8 encoding."""
        try:
            full_cmd = ["wsl", "-d", self.wsl_distro, "sh", "-c", cmd]
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
            stdout = strip_wsl_noise(proc.stdout)
            stderr = strip_wsl_noise(proc.stderr)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            return 124, "", "WSL command timeout"
        except Exception as exc:
            return 1, "", str(exc)

    def get_agent_process_stats(self) -> Dict[str, Any]:
        """Query host process table for running NetOps Agent CLI."""
        info = {
            "running": False,
            "pid": None,
            "cpu_percent": 0.0,
            "memory_mb": 0.0,
            "uptime_sec": 0.0,
            "command_line": "",
        }
        try:
            import psutil
            for p in psutil.process_iter(["pid", "name", "cmdline", "create_time", "cpu_percent", "memory_info"]):
                try:
                    cmdline = " ".join(p.info["cmdline"] or [])
                    if "langgraph_netagent.cli" in cmdline or ("python" in p.info["name"].lower() and "langgraph_netagent" in cmdline):
                        info["running"] = True
                        info["pid"] = p.info["pid"]
                        info["cpu_percent"] = p.cpu_percent(interval=None)
                        mem_info = p.info.get("memory_info")
                        if mem_info:
                            info["memory_mb"] = round(mem_info.rss / (1024 * 1024), 2)
                        info["uptime_sec"] = round(time.time() - p.info["create_time"], 1)
                        info["command_line"] = cmdline
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except ImportError:
            # Fallback to PowerShell Get-Process on Windows
            if platform.system().lower() == "windows":
                ps_cmd = 'Get-WmiObject Win32_Process | Where-Object { $_.CommandLine -like "*langgraph_netagent*" } | Select-Object ProcessId, CommandLine, WorkingSetSize | ConvertTo-Json'
                ret = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, encoding="utf-8", errors="replace")
                if ret.returncode == 0 and ret.stdout.strip():
                    try:
                        data = json.loads(ret.stdout.strip())
                        if isinstance(data, list):
                            data = data[0]
                        info["running"] = True
                        info["pid"] = data.get("ProcessId")
                        wss = data.get("WorkingSetSize") or 0
                        info["memory_mb"] = round(wss / (1024 * 1024), 2)
                    except Exception:
                        pass
        return info

    def parse_iptables_forward_rules(self, node: str = "clab-clos5-ext-router") -> List[Dict[str, Any]]:
        """Parse iptables FORWARD table on target node to track drop rules and packet counters."""
        ret, out, _ = self.run_cmd_in_wsl(f"docker exec {node} iptables -L FORWARD -n -v --line-numbers 2>/dev/null")
        if ret != 0 or not out:
            return []

        rules = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Chain") or line.startswith("num"):
                continue
            parts = line.split()
            if len(parts) >= 9:
                num = parts[0]
                pkts = parts[1]
                bytes_cnt = parts[2]
                target = parts[3]
                prot = parts[4]
                opt = parts[5]
                in_if = parts[6]
                out_if = parts[7]
                src = parts[8]
                dst = parts[9] if len(parts) > 9 else "0.0.0.0/0"
                extra_opts = " ".join(parts[10:]) if len(parts) > 10 else ""

                try:
                    p_val = int(pkts)
                except ValueError:
                    p_val = 0
                try:
                    b_val = int(bytes_cnt)
                except ValueError:
                    b_val = 0

                rule_obj = {
                    "num": int(num) if num.isdigit() else 0,
                    "packets": p_val,
                    "bytes": b_val,
                    "target": target,
                    "protocol": prot,
                    "source": src,
                    "destination": dst,
                    "options": extra_opts,
                    "raw": line,
                }
                rules.append(rule_obj)
        return rules

    def get_tc_qdisc_stats(self, node: str = "clab-clos5-ext-router", dev: str = "eth1") -> Dict[str, Any]:
        """Extract TC qdisc overlimits, dropped packets, and backlog bytes on bottleneck router."""
        ret, out, _ = self.run_cmd_in_wsl(f"docker exec {node} tc -s qdisc show dev {dev} 2>/dev/null")
        stats = {
            "dropped": 0,
            "overlimits": 0,
            "backlog_bytes": 0,
            "backlog_pkts": 0,
            "raw": out.strip() if out else "",
        }
        if ret != 0 or not out:
            return stats

        drop_match = re.search(r"dropped\s+(\d+)", out)
        if drop_match:
            stats["dropped"] = int(drop_match.group(1))

        over_match = re.search(r"overlimits\s+(\d+)", out)
        if over_match:
            stats["overlimits"] = int(over_match.group(1))

        backlog_match = re.search(r"backlog\s+(\d+)[bB]\s+(\d+)[pP]", out)
        if backlog_match:
            stats["backlog_bytes"] = int(backlog_match.group(1))
            stats["backlog_pkts"] = int(backlog_match.group(2))

        return stats

    def probe_network_health(self) -> Dict[str, Any]:
        """Probe network reachability and HTTP service health across WAN border and DC fabric."""
        res = {
            "vip_ping_loss": 100.0,
            "vip_ping_rtt_avg": 0.0,
            "http_status": 0,
            "http_latency_ms": 0.0,
            "internal_ping_loss": 0.0,
            "internal_ping_rtt_avg": 0.0,
            "attacker_containment_loss": 100.0,
        }

        # 1. Ping primary VIP from border router
        cmd_ping = f"docker exec clab-clos5-ext-router ping -c 2 -W 1 {self.target_vip} 2>/dev/null"
        ret, out, _ = self.run_cmd_in_wsl(cmd_ping)
        if ret == 0:
            loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
            if loss_match:
                res["vip_ping_loss"] = float(loss_match.group(1))
            rtt_match = re.search(r"min/avg/max(?:/mdev)? = [\d\.]+/([\d\.]+)/", out)
            if rtt_match:
                res["vip_ping_rtt_avg"] = float(rtt_match.group(1))

        # 2. HTTP probe to primary VIP from border router
        cmd_http = f"docker exec clab-clos5-ext-router curl -s -o /dev/null -w '%{{http_code}} %{{time_total}}' --max-time 1.5 http://{self.target_vip} 2>/dev/null"
        ret_http, out_http, _ = self.run_cmd_in_wsl(cmd_http)
        if ret_http == 0 and out_http.strip():
            parts = out_http.strip().split()
            if len(parts) >= 2:
                try:
                    res["http_status"] = int(parts[0])
                    res["http_latency_ms"] = round(float(parts[1]) * 1000.0, 2)
                except ValueError:
                    pass

        # 3. Probe internal DC Fabric (h2 -> h1 172.16.1.2)
        cmd_int = "docker exec clab-clos5-h2 ping -c 2 -W 1 172.16.1.2 2>/dev/null"
        ret_int, out_int, _ = self.run_cmd_in_wsl(cmd_int)
        if ret_int == 0:
            loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out_int)
            if loss_match:
                res["internal_ping_loss"] = float(loss_match.group(1))
            rtt_match = re.search(r"min/avg/max = [\d\.]+/([\d\.]+)/", out_int)
            if rtt_match:
                res["internal_ping_rtt_avg"] = float(rtt_match.group(1))

        # 4. Probe attacker containment (attacker -> target VIP)
        cmd_att = f"docker exec clab-clos5-attacker ping -c 1 -W 1 {self.target_vip} 2>/dev/null"
        ret_att, out_att, _ = self.run_cmd_in_wsl(cmd_att)
        if "100% packet loss" in out_att or ret_att != 0:
            res["attacker_containment_loss"] = 100.0
        else:
            loss_m = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out_att)
            res["attacker_containment_loss"] = float(loss_m.group(1)) if loss_m else 0.0

        return res

    def inspect_and_correlate(self) -> None:
        """Sample one monitoring cycle, detect anomalies, compare diffs, and correlate actions."""
        self.cycle_count += 1
        now_ts = datetime.datetime.now().isoformat()
        cycle_start_time = time.time()

        # 1. Agent Process Status
        agent_stat = self.get_agent_process_stats()
        if agent_stat["running"]:
            if self.known_agent_pid != agent_stat["pid"]:
                self.known_agent_pid = agent_stat["pid"]
                self.log_event(
                    "AGENT",
                    f"NetOps Agent detected running (PID: {agent_stat['pid']}, Mem: {agent_stat['memory_mb']} MB)",
                    level="AGENT",
                )
            if agent_stat["cpu_percent"] > self.stats["peak_agent_cpu"]:
                self.stats["peak_agent_cpu"] = agent_stat["cpu_percent"]
            if agent_stat["memory_mb"] > self.stats["peak_agent_memory_mb"]:
                self.stats["peak_agent_memory_mb"] = agent_stat["memory_mb"]
        else:
            if self.known_agent_pid is not None:
                self.log_event("AGENT", f"Agent process (PID: {self.known_agent_pid}) stopped or terminated!", level="WARN")
                self.known_agent_pid = None

        # 2. Border Router Firewall Rules & Diffs
        current_rules = self.parse_iptables_forward_rules("clab-clos5-ext-router")
        drop_rules = [r for r in current_rules if r["target"] in ("DROP", "REJECT")]
        total_dropped_pkts = sum(r["packets"] for r in drop_rules)
        total_dropped_bytes = sum(r["bytes"] for r in drop_rules)

        # Check for Rule Additions / Removals
        prev_signatures = {f"{r['target']}:{r['source']}->{r['destination']}:{r['options']}" for r in self.last_iptables_rules}
        curr_signatures = {f"{r['target']}:{r['source']}->{r['destination']}:{r['options']}" for r in current_rules}

        new_rules = [r for r in current_rules if f"{r['target']}:{r['source']}->{r['destination']}:{r['options']}" not in prev_signatures]
        removed_rules = [r for r in self.last_iptables_rules if f"{r['target']}:{r['source']}->{r['destination']}:{r['options']}" not in curr_signatures]

        if new_rules:
            for nr in new_rules:
                self.stats["total_defense_rules_deployed"] += 1
                self.log_event(
                    "REMEDIATION",
                    f"Agent Hot-Patch deployed: {nr['target']} rule inserted! [Src: {nr['source']} -> Dst: {nr['destination']}] (Options: '{nr['options']}')",
                    level="REMEDIATION",
                    extra=nr,
                )
                self.stats["rule_change_events"].append({
                    "timestamp": now_ts,
                    "action": "ADD",
                    "rule": nr,
                })

                # If an active incident is ongoing, mark defense deployed
                if self.active_incident and not self.active_incident.get("defense_rule_deployed"):
                    deploy_latency = round(time.time() - self.active_incident["start_time_epoch"], 2)
                    self.active_incident["defense_rule_deployed"] = True
                    self.active_incident["defense_deploy_latency_sec"] = deploy_latency
                    self.active_incident["deployed_rule"] = nr
                    self.log_event(
                        "REMEDIATION",
                        f"Autonomous reaction verified: defense rule deployed within {deploy_latency}s of incident trigger!",
                        level="REMEDIATION",
                    )

        if removed_rules:
            for rr in removed_rules:
                self.log_event(
                    "REMEDIATION",
                    f"Rule removed/rolled back: {rr['target']} [Src: {rr['source']} -> Dst: {rr['destination']}]",
                    level="INFO",
                    extra=rr,
                )

        self.last_iptables_rules = current_rules

        # 3. Bottleneck QoS Telemetry (TC Qdisc on ext-router:eth1)
        tc_stats = self.get_tc_qdisc_stats("clab-clos5-ext-router", "eth1")
        overlimits = tc_stats["overlimits"]
        dropped = tc_stats["dropped"]

        delta_overlimits = 0
        delta_dropped = 0
        if self.last_qdisc_overlimits is not None:
            delta_overlimits = max(0, overlimits - self.last_qdisc_overlimits)
        if self.last_qdisc_dropped is not None:
            delta_dropped = max(0, dropped - self.last_qdisc_dropped)

        self.last_qdisc_overlimits = overlimits
        self.last_qdisc_dropped = dropped

        if overlimits > self.stats["peak_tc_overlimits"]:
            self.stats["peak_tc_overlimits"] = overlimits
        if dropped > self.stats["peak_tc_dropped"]:
            self.stats["peak_tc_dropped"] = dropped

        # 4. Service Availability & Latency Probes
        net_health = self.probe_network_health()
        self.stats["total_probes"] += 1
        if net_health["http_status"] == 200:
            self.stats["successful_http_probes"] += 1
        if net_health["vip_ping_loss"] < 50.0:
            self.stats["successful_ping_probes"] += 1

        # 5. Incident Detection & Correlation State Machine
        is_surge = (delta_overlimits > 2000) or (delta_dropped > 100) or (net_health["vip_ping_loss"] > 15.0)

        if is_surge and not self.active_incident:
            # New incident started
            self.stats["total_incidents_detected"] += 1
            incident_id = f"INC-{self.stats['total_incidents_detected']:03d}"
            self.active_incident = {
                "incident_id": incident_id,
                "start_time": now_ts,
                "start_time_epoch": time.time(),
                "initial_overlimits": overlimits,
                "initial_dropped": dropped,
                "defense_rule_deployed": False,
                "resolved": False,
            }
            self.log_event(
                "INCIDENT",
                f">>> Anomaly Triggered ({incident_id}): Buffer surge (Δoverlimits={delta_overlimits}/cycle, loss={net_health['vip_ping_loss']}%)",
                level="ALERT",
                extra={"delta_overlimits": delta_overlimits, "delta_dropped": delta_dropped},
            )

        elif self.active_incident and not is_surge and delta_overlimits < 500:
            # Surge has subsided and network stabilized
            incident_duration = round(time.time() - self.active_incident["start_time_epoch"], 2)
            self.active_incident["end_time"] = now_ts
            self.active_incident["total_duration_sec"] = incident_duration
            self.active_incident["resolved"] = True
            self.active_incident["final_overlimits"] = overlimits
            self.active_incident["total_incident_overlimits"] = overlimits - self.active_incident["initial_overlimits"]
            self.stats["incidents"].append(dict(self.active_incident))

            self.log_event(
                "INCIDENT",
                f"<<< Anomaly Resolved ({self.active_incident['incident_id']}): Network stabilized after {incident_duration}s. MTTR recorded.",
                level="INFO",
                extra=self.active_incident,
            )
            self.active_incident = None

        # 6. Live Status Line (Periodic heartbeat)
        agent_flag = f"{COLOR_GREEN}RUNNING (PID:{agent_stat['pid']}){COLOR_RESET}" if agent_stat["running"] else f"{COLOR_RED}STOPPED{COLOR_RESET}"
        http_flag = f"{COLOR_GREEN}200 OK ({net_health['http_latency_ms']}ms){COLOR_RESET}" if net_health["http_status"] == 200 else f"{COLOR_RED}FAIL ({net_health['http_status']}){COLOR_RESET}"
        surge_flag = f"{COLOR_BOLD}{COLOR_RED}[SURGE +{delta_overlimits}/s]{COLOR_RESET}" if delta_overlimits > 1000 else f"{COLOR_GREEN}[NORMAL]{COLOR_RESET}"

        status_msg = (
            f"Cycle #{self.cycle_count:<4} | Agent: {agent_flag} | "
            f"ext-router Drop Rules: {len(drop_rules)} (Hits: {total_dropped_pkts} pkts, {total_dropped_bytes}B) | "
            f"TC Overlimits: {overlimits:,} ({surge_flag}) | "
            f"Ping Loss: {net_health['vip_ping_loss']}% (RTT: {net_health['vip_ping_rtt_avg']}ms) | "
            f"HTTP: {http_flag}"
        )
        print(f"\r{COLOR_CYAN}[MONITOR]{COLOR_RESET} {status_msg}")

        # 7. Write Structured JSONL Metric Record
        metric_record = {
            "cycle": self.cycle_count,
            "timestamp": now_ts,
            "agent": agent_stat,
            "firewall": {
                "total_forward_rules": len(current_rules),
                "drop_rules_count": len(drop_rules),
                "total_dropped_packets": total_dropped_pkts,
                "total_dropped_bytes": total_dropped_bytes,
                "drop_rules": drop_rules,
            },
            "tc_qdisc": {
                "overlimits": overlimits,
                "dropped": dropped,
                "delta_overlimits": delta_overlimits,
                "delta_dropped": delta_dropped,
                "backlog_bytes": tc_stats["backlog_bytes"],
                "backlog_pkts": tc_stats["backlog_pkts"],
            },
            "network_health": net_health,
            "is_surge": is_surge,
            "active_incident": bool(self.active_incident),
        }
        self.metrics_fp.write(json.dumps(metric_record) + "\n")
        self.metrics_fp.flush()

    def run(self) -> None:
        """Main monitoring loop."""
        self.log_event("SYSTEM", "=" * 70, level="INFO")
        self.log_event("SYSTEM", ">>> NetOps AI Agent Real-Time Stress Test Monitor Started <<<", level="INFO")
        self.log_event("SYSTEM", f"Sampling Interval:     {self.interval}s", level="INFO")
        self.log_event("SYSTEM", f"Target VIP:            {self.target_vip} (HTTP / Ping)", level="INFO")
        self.log_event("SYSTEM", f"WSL Distro:            {self.wsl_distro}", level="INFO")
        self.log_event("SYSTEM", f"Timeline Log File:     {self.log_path}", level="INFO")
        self.log_event("SYSTEM", f"Metrics JSONL File:    {self.metrics_path}", level="INFO")
        self.log_event("SYSTEM", f"Summary Report File:   {self.report_path}", level="INFO")
        self.log_event("SYSTEM", "=" * 70, level="INFO")

        try:
            while self.is_running:
                loop_start = time.time()
                self.inspect_and_correlate()

                if self.max_duration and (time.time() - self.start_time) >= self.max_duration:
                    self.log_event("SYSTEM", f"Max monitoring duration ({self.max_duration}s) reached. Exiting.", level="INFO")
                    break

                elapsed = time.time() - loop_start
                sleep_time = max(0.1, self.interval - elapsed)
                time.sleep(sleep_time)

        except KeyboardInterrupt:
            self.log_event("SYSTEM", "Interrupted by user (Ctrl+C). Generating report...", level="WARN")

        finally:
            self.finish()

    def finish(self) -> None:
        """Close log files and generate stress test summary report."""
        total_duration = round(time.time() - self.start_time, 2)
        http_avail = (
            round((self.stats["successful_http_probes"] / max(1, self.stats["total_probes"])) * 100.0, 2)
        )
        ping_avail = (
            round((self.stats["successful_ping_probes"] / max(1, self.stats["total_probes"])) * 100.0, 2)
        )

        # Calculate Average MTTR
        resolved_incidents = [inc for inc in self.stats["incidents"] if inc.get("resolved")]
        avg_mttr = 0.0
        if resolved_incidents:
            avg_mttr = round(sum(inc.get("total_duration_sec", 0.0) for inc in resolved_incidents) / len(resolved_incidents), 2)

        summary = {
            "test_summary": {
                "start_time": self.stats["start_time"],
                "end_time": datetime.datetime.now().isoformat(),
                "total_duration_seconds": total_duration,
                "total_cycles_monitored": self.cycle_count,
            },
            "network_stability_metrics": {
                "http_service_availability_pct": http_avail,
                "ping_reachability_pct": ping_avail,
                "total_probes_dispatched": self.stats["total_probes"],
                "peak_buffer_overlimits": self.stats["peak_tc_overlimits"],
                "peak_buffer_dropped_packets": self.stats["peak_tc_dropped"],
            },
            "agent_autonomous_remediation_metrics": {
                "total_incidents_detected": self.stats["total_incidents_detected"],
                "total_incidents_resolved": len(resolved_incidents),
                "average_mttr_seconds": avg_mttr,
                "total_defense_rules_deployed": self.stats["total_defense_rules_deployed"],
                "peak_agent_cpu_pct": self.stats["peak_agent_cpu"],
                "peak_agent_memory_mb": self.stats["peak_agent_memory_mb"],
            },
            "incident_records": self.stats["incidents"],
            "rule_change_records": self.stats["rule_change_events"],
        }

        # Write Summary JSON
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        self.log_fp.close()
        self.metrics_fp.close()

        # Print Executive Report
        print("\n")
        print(f"{COLOR_BOLD}{'=' * 75}{COLOR_RESET}")
        print(f"{COLOR_BOLD}{COLOR_GREEN}          NETOPS AGENT STRESS TEST AUTONOMOUS REACTION REPORT{COLOR_RESET}")
        print(f"{COLOR_BOLD}{'=' * 75}{COLOR_RESET}")
        print(f"Total Test Duration:             {total_duration}s ({self.cycle_count} cycles)")
        print(f"HTTP Service Availability:       {http_avail}% (Success: {self.stats['successful_http_probes']}/{self.stats['total_probes']})")
        print(f"Ping Reachability:               {ping_avail}%")
        print(f"Peak Buffer Overlimits:          {self.stats['peak_tc_overlimits']:,}")
        print(f"Peak Dropped Packets:            {self.stats['peak_tc_dropped']:,}")
        print("---------------------------------------------------------------------------")
        print(f"Incidents Detected:              {self.stats['total_incidents_detected']}")
        print(f"Incidents Autonomous Resolved:   {len(resolved_incidents)}")
        print(f"Average MTTR (Resolution Time):  {avg_mttr}s")
        print(f"Total Defense Rules Applied:     {self.stats['total_defense_rules_deployed']}")
        print(f"Agent Peak CPU Footprint:        {self.stats['peak_agent_cpu']}%")
        print(f"Agent Peak Memory Footprint:     {self.stats['peak_agent_memory_mb']} MB")
        print(f"{COLOR_BOLD}{'=' * 75}{COLOR_RESET}")
        print(f"Detailed Timeline Log:           {self.log_path}")
        print(f"Metric Stream (JSONL):           {self.metrics_path}")
        print(f"Executive Summary (JSON):        {self.report_path}")
        print(f"{COLOR_BOLD}{'=' * 75}{COLOR_RESET}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Real-Time NetOps Agent Stress Test Monitor & Detailed Reaction Logger"
    )
    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=2.0,
        help="Sampling frequency in seconds (default: 2.0s)",
    )
    parser.add_argument(
        "--target-vip",
        default="203.0.113.10",
        help="Target primary VIP to probe (default: 203.0.113.10)",
    )
    parser.add_argument(
        "--target-vip-secondary",
        default="203.0.113.40",
        help="Target secondary VIP to probe (default: 203.0.113.40)",
    )
    parser.add_argument(
        "--log-file", "-l",
        default="attack_logs/agent_reaction_monitor.log",
        help="Timeline log file destination (default: attack_logs/agent_reaction_monitor.log)",
    )
    parser.add_argument(
        "--metrics-file", "-m",
        default="attack_logs/agent_reaction_metrics.jsonl",
        help="JSONL metric stream destination (default: attack_logs/agent_reaction_metrics.jsonl)",
    )
    parser.add_argument(
        "--report-file", "-r",
        default="attack_logs/stress_test_summary.json",
        help="Final executive summary report destination (default: attack_logs/stress_test_summary.json)",
    )
    parser.add_argument(
        "--wsl-distro",
        default="Ubuntu",
        help="WSL distribution running Containerlab (default: Ubuntu)",
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=None,
        help="Optional max monitoring duration in seconds (default: unlimited, run until Ctrl+C)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    monitor = RealTimeAgentMonitor(
        interval=args.interval,
        target_vip=args.target_vip,
        target_vip_secondary=args.target_vip_secondary,
        log_file=args.log_file,
        metrics_file=args.metrics_file,
        report_file=args.report_file,
        wsl_distro=args.wsl_distro,
        max_duration=args.duration,
    )
    monitor.run()
