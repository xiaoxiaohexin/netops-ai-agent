"""Agent Access Layer (AAL) for LangGraph NetAgent.

Decouples agent nodes from direct CLI execution by providing:
1. Structured tool call validation (`AALToolCall`).
2. Security whitelist / blacklist enforcement (blocking destructive commands, full interface flushes, reboots).
3. Read-only mode enforcement for Stage-1 context enrichment.
4. Parsing and normalization of unstructured CLI outputs into structured JSON.
5. Explicit step-tagging on every tool call for deterministic loop tracking.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Pattern, Tuple

from langgraph_netagent.models.operational import AALResponse, AALToolCall
from langgraph_netagent.tools.base import BaseNetworkLabAdapter, CommandResult


class AALSecurityError(Exception):
    """Raised when an agent tool call violates security safety policies."""
    pass


class AgentAccessLayer:
    """Agent Access Layer (AAL) mediating all tool interactions with network devices."""

    # Destructive commands that are strictly blocked by security policy
    BLOCKED_PATTERNS: List[Tuple[Pattern, str]] = [
        # Full interface flush or wipe
        (re.compile(r"\bip\s+(?:addr(?:ess)?|a)\s+flush\b", re.IGNORECASE), "Full interface address flush is blocked"),
        (re.compile(r"\bifconfig\s+\S+\s+(?:0\.0\.0\.0|down\s+delete)\b", re.IGNORECASE), "Interface zeroing is blocked"),
        # Reboot / system shutdown
        (re.compile(r"\b(reboot|poweroff|halt)\b", re.IGNORECASE), "Node reboot / poweroff is blocked"),
        (re.compile(r"(?<!\bno\s)\bshutdown\b(?!\s+-c\b)", re.IGNORECASE), "System shutdown is blocked"),
        (re.compile(r"\b(?:init|telinit)\s+[06]\b", re.IGNORECASE), "System runlevel transition is blocked"),
        (re.compile(r"\bsystemctl\s+(reboot|poweroff|halt|isolate\s+(?:poweroff|reboot|halt)\.target)\b", re.IGNORECASE), "Systemctl power operation is blocked"),
        # Destructive file deletions / disk formatting / wipefs / shred
        (re.compile(r"\brm\s+.*?(?:-[a-zA-Z]*[rR][a-zA-Z]*[fF]|-[a-zA-Z]*[fF][a-zA-Z]*[rR]|--recursive\s+--force|--force\s+--recursive|-[a-zA-Z]*[rR]\b\s+-[a-zA-Z]*[fF]\b|-[a-zA-Z]*[fF]\b\s+-[a-zA-Z]*[rR]\b)", re.IGNORECASE), "Recursive forceful file deletion (rm -rf) is blocked"),
        (re.compile(r"\brm\s+-[a-zA-Z]*[rR].*?(?:/\s*$|/\*|/(?:etc|var|usr|bin|sbin|lib|root|home|boot|dev|sys|proc)\b)", re.IGNORECASE), "System recursive deletion is blocked"),
        (re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\s+", re.IGNORECASE), "Filesystem format (mkfs) is blocked"),
        (re.compile(r"\b(?:wipefs|shred|sfdisk|fdisk|parted)\b", re.IGNORECASE), "Disk wipe / partition tampering is blocked"),
        (re.compile(r"\bdd\s+.*?(?:of=/dev/(?:sd|vd|nvme|null|zero|loop)|if=/dev/(?:zero|null|urandom)\s+of=)", re.IGNORECASE), "Direct disk overwrite (dd) is blocked"),
        (re.compile(r":\(\)\s*{\s*:\|:&\s*};\s*:", re.IGNORECASE), "Fork bomb attack is blocked"),
        (re.compile(r"\b([a-zA-Z_]\w*)\(\)\s*{\s*\1\s*\|\s*\1\s*&\s*};\s*\1\b", re.IGNORECASE), "Named fork bomb attack is blocked"),
        # Dangerous interface deletions
        (re.compile(r"\bip\s+(?:link|l)\s+(?:delete|del)\b", re.IGNORECASE), "Interface deletion (ip link delete) is blocked"),
        # Arbitrary code execution via piping to shell/interpreter or base64 decode execution
        (re.compile(r"\|\s*(?:sudo\s+)?(?:/(?:usr/)?(?:bin|sbin)/)?(?:ba|da|z)?sh\b|\|\s*(?:sudo\s+)?(?:python[0-9.]*|perl|ruby)\b", re.IGNORECASE), "Piping to shell/script interpreter is blocked"),
        (re.compile(r"\bbase64\s+(?:-d|--decode)\b", re.IGNORECASE), "Base64 decode execution is blocked"),
        (re.compile(r"(?:>|>>)\s*(?:/etc/(?:passwd|shadow|sudoers|group))\b", re.IGNORECASE), "Tampering with system authentication files is blocked"),
    ]

    # Mutating commands disallowed when read_only=True
    MUTATING_PATTERNS: List[Tuple[Pattern, str]] = [
        (re.compile(r"\bip\s+(?:route|r)\s+(?:add|replace|del(?:ete)?|change)\b", re.IGNORECASE), "Route modification in read-only mode"),
        (re.compile(r"\bip\s+(?:addr(?:ess)?|a)\s+(?:add|del(?:ete)?|change)\b", re.IGNORECASE), "IP address modification in read-only mode"),
        (re.compile(r"\bip\s+(?:link|l)\s+set\b", re.IGNORECASE), "Link state modification in read-only mode"),
        (re.compile(r"\bip\s+(?:rule|tables|tables-legacy|tables-nft)\b.*?(?:add|del|replace|-A|-D|-I|-R|-F|-X|-Z)\b", re.IGNORECASE), "Policy routing / iptables modification in read-only mode"),
        (re.compile(r"\biptables\s+.*?(?:-A|-D|-I|-R|-F|-X|-Z)\b", re.IGNORECASE), "iptables modification in read-only mode"),
        (re.compile(r"\bnft\s+.*?(?:add|delete|flush|insert|replace)\b", re.IGNORECASE), "nftables modification in read-only mode"),
        (re.compile(r"\b(?:ifconfig|ifup|ifdown)\s+\S+", re.IGNORECASE), "ifconfig/ifup/ifdown mutation in read-only mode"),
        (re.compile(r"\bvtysh\b.*?(?:-f\b|-c\s+['\"]?\s*(?:conf|router\b|interface\b|ip\s+r|no\b|write\b|copy\b|clear\b|set\b))", re.IGNORECASE), "FRR mutating configuration command in read-only mode"),
        (re.compile(r"(?:>|>>)", re.IGNORECASE), "File write redirect in read-only mode"),
        (re.compile(r"\bsed\s+-i\b", re.IGNORECASE), "In-place file editing in read-only mode"),
        (re.compile(r"\b(?:touch|tee|truncate|chmod|chown)\b", re.IGNORECASE), "File modification tool in read-only mode"),
        (re.compile(r"\b(?:cp|mv|rm)\b", re.IGNORECASE), "File copy/move/delete in read-only mode"),
    ]

    def __init__(
        self,
        lab_adapter: BaseNetworkLabAdapter,
        raise_on_security_violation: bool = False,
    ):
        self.lab_adapter = lab_adapter
        self.raise_on_security_violation = raise_on_security_violation
        self.execution_history: List[Dict[str, Any]] = []

    @classmethod
    def split_chained_commands(cls, command: str) -> List[str]:
        """Split chained or piped shell commands into individual subcommands."""
        subcmds = re.split(r"(?:;|\&\&|\|\||\||\n)+", command)
        return [c.strip() for c in subcmds if c.strip()]

    def validate_command_safety(self, command: str, read_only: bool = False) -> Tuple[bool, Optional[str]]:
        """Check whether a command passes security whitelist and read-only constraints.

        Returns:
            Tuple of (is_safe, error_reason)
        """
        cmd_clean = command.strip()
        subcmds = self.split_chained_commands(cmd_clean)
        commands_to_check = [cmd_clean] + subcmds if len(subcmds) > 1 else [cmd_clean]

        for cmd_item in commands_to_check:
            # Check blocked destructive patterns
            for pattern, reason in self.BLOCKED_PATTERNS:
                if pattern.search(cmd_item):
                    return False, f"SECURITY POLICY VIOLATION: {reason} (command: '{command}')"

            # Check read-only constraint
            if read_only:
                for pattern, reason in self.MUTATING_PATTERNS:
                    if pattern.search(cmd_item):
                        return False, f"READ-ONLY CONSTRAINT VIOLATION: {reason} (command: '{command}')"

        return True, None

    def execute(self, tool_call: AALToolCall) -> AALResponse:
        """Execute a validated, normalized tool call against the network adapter.

        Args:
            tool_call: Structured tool invocation specification.

        Returns:
            AALResponse with structured parsed JSON and raw outputs.
        """
        # Strip redundant "docker exec [-flags]* [node_name]" prefix if emitted by LLM
        clean_command = tool_call.command.strip()
        m_dock = re.match(r"^docker\s+exec\s+(?:-[a-zA-Z0-9_\-]+\s+)*[a-zA-Z0-9_\-]+\s+(.*)$", clean_command)
        if m_dock:
            clean_command = m_dock.group(1).strip()

        # 1. Enforce Safety Policy & Read-Only Constraints
        is_safe, error_reason = self.validate_command_safety(
            command=clean_command,
            read_only=tool_call.read_only,
        )

        if not is_safe:
            if self.raise_on_security_violation:
                raise AALSecurityError(error_reason)
            resp = AALResponse(
                success=False,
                exit_code=126,
                raw_stdout="",
                raw_stderr=error_reason or "Blocked",
                parsed_json={"blocked": True, "reason": error_reason},
                step_tag=tool_call.step_tag,
                is_blocked=True,
                error_message=error_reason,
            )
            self._record_history(tool_call, resp)
            return resp

        # 2. Execute via Lab Adapter
        try:
            cmd_result: CommandResult = self.lab_adapter.exec_command(
                node_name=tool_call.node_name,
                command=clean_command,
                timeout=tool_call.timeout,
            )
        except Exception as exc:
            resp = AALResponse(
                success=False,
                exit_code=-1,
                raw_stdout="",
                raw_stderr=str(exc),
                parsed_json={"error": str(exc)},
                step_tag=tool_call.step_tag,
                is_blocked=False,
                error_message=f"Execution error on node '{tool_call.node_name}': {exc}",
            )
            self._record_history(tool_call, resp)
            return resp

        # 3. Normalize unstructured CLI output to structured JSON
        parsed_json = self.normalize_cli_output(
            command=tool_call.command,
            raw_stdout=cmd_result.stdout,
            raw_stderr=cmd_result.stderr,
            exit_code=cmd_result.exit_code,
        )

        resp = AALResponse(
            success=cmd_result.success,
            exit_code=cmd_result.exit_code,
            raw_stdout=cmd_result.stdout,
            raw_stderr=cmd_result.stderr,
            parsed_json=parsed_json,
            step_tag=tool_call.step_tag,
            is_blocked=False,
            error_message=None if cmd_result.success else (cmd_result.stderr or "Command returned non-zero exit code"),
        )
        self._record_history(tool_call, resp)
        return resp

    def _record_history(self, call: AALToolCall, resp: AALResponse) -> None:
        self.execution_history.append({
            "step_tag": call.step_tag,
            "tool_name": call.tool_name,
            "node_name": call.node_name,
            "command": call.command,
            "read_only": call.read_only,
            "success": resp.success,
            "is_blocked": resp.is_blocked,
            "exit_code": resp.exit_code,
        })

    @classmethod
    def normalize_cli_output(
        cls,
        command: str,
        raw_stdout: str,
        raw_stderr: str = "",
        exit_code: int = 0,
    ) -> Dict[str, Any]:
        """Normalize raw CLI stdout/stderr into standard structured JSON."""
        cmd = command.strip().lower()

        # 1. Try to parse JSON output directly (e.g. vtysh json or sr_cli json)
        if "json" in cmd:
            try:
                data = json.loads(raw_stdout)
                return {"type": "json_telemetry", "data": data}
            except Exception:
                pass

        # 2. Parse `ip addr show` / `ip a`
        if "addr" in cmd or "ip a" in cmd:
            return cls._parse_ip_addr_show(raw_stdout)

        # 3. Parse `ip route show` / `vtysh show ip route`
        if "route" in cmd:
            return cls._parse_route_show(raw_stdout)

        # 4. Parse `ping`
        if "ping" in cmd:
            return cls._parse_ping_output(raw_stdout, exit_code)

        # 5. Parse running config / file dump
        if "running-config" in cmd or "cat " in cmd or "info flat" in cmd:
            return {
                "type": "configuration_dump",
                "line_count": len(raw_stdout.splitlines()),
                "content": raw_stdout,
            }

        # 6. Generic CLI output fallback
        return {
            "type": "cli_output",
            "command": command,
            "exit_code": exit_code,
            "lines": [line.strip() for line in raw_stdout.splitlines() if line.strip()],
            "stderr": raw_stderr,
        }

    @staticmethod
    def _parse_ip_addr_show(stdout: str) -> Dict[str, Any]:
        """Parse Linux `ip addr show` output into structured interfaces JSON."""
        interfaces: List[Dict[str, Any]] = []
        current_iface: Optional[Dict[str, Any]] = None

        for line in stdout.splitlines():
            # Interface header: e.g. "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP"
            # or "2: eth1@if41: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP"
            # or "3: eth1.100: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 ... state UP"
            m_hdr = re.match(
                r"(\d+):\s+([a-zA-Z0-9_\-\.@:]+):\s+<([^>]+)>\s+mtu\s+(\d+).*?state\s+([a-zA-Z]+)",
                line,
                re.IGNORECASE,
            )
            if m_hdr:
                if current_iface:
                    interfaces.append(current_iface)
                raw_name = m_hdr.group(2)
                clean_name = raw_name.split("@")[0]
                current_iface = {
                    "index": int(m_hdr.group(1)),
                    "name": clean_name,
                    "raw_name": raw_name,
                    "flags": m_hdr.group(3).split(","),
                    "mtu": int(m_hdr.group(4)),
                    "state": m_hdr.group(5).upper(),
                    "mac": None,
                    "ips": [],
                }
                continue

            if current_iface:
                # MAC address: e.g. "link/ether 00:16:3e:xx:xx:xx"
                m_mac = re.search(r"link/(?:ether|loopback)\s+([0-9a-fA-F:]{17})", line)
                if m_mac:
                    current_iface["mac"] = m_mac.group(1)

                # IP CIDR: e.g. "inet 10.1.1.2/24 scope global eth1" or "inet6 2001:db8::1/64 scope global"
                m_ip = re.search(r"inet6?\s+([0-9a-fA-F:\.]+/\d+)", line)
                if m_ip:
                    current_iface["ips"].append(m_ip.group(1))

        if current_iface:
            interfaces.append(current_iface)

        return {
            "type": "interface_inventory",
            "count": len(interfaces),
            "interfaces": interfaces,
        }

    @staticmethod
    def _parse_route_show(stdout: str) -> Dict[str, Any]:
        """Parse `ip route show` or `vtysh show ip route` into structured routes JSON."""
        routes: List[Dict[str, Any]] = []

        def _map_protocol(code_prefix: str) -> str:
            pfx = code_prefix.upper()
            if "S" in pfx:
                return "static"
            elif "C" in pfx:
                return "connected"
            elif "B" in pfx:
                return "bgp"
            elif "O" in pfx:
                return "ospf"
            elif "K" in pfx:
                return "kernel"
            return "other"

        for line in stdout.splitlines():
            clean = line.strip()
            if not clean or clean.startswith("Codes:") or clean.startswith("--"):
                continue

            # FRR format: e.g. "S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2" or "S>* 2001:db8:2::/64 ... eth2"
            m_frr = re.match(
                r"([A-Z]>[*]?)\s+([0-9a-fA-F:\.]+/\d+|default)\s+(?:\[.*?\]\s+)?via\s+([0-9a-fA-F:\.]+)(?:,\s*([a-zA-Z0-9_\-\.]+))?",
                clean,
            )
            if m_frr:
                routes.append({
                    "protocol": _map_protocol(m_frr.group(1)),
                    "destination": m_frr.group(2),
                    "next_hop": m_frr.group(3),
                    "interface": m_frr.group(4) or "",
                    "active": "*" in m_frr.group(1),
                    "raw": clean,
                })
                continue

            # FRR connected format: e.g. "C>* 10.1.1.0/24 is directly connected, eth1" or IPv6
            m_frr_conn = re.match(
                r"([A-Z]>[*]?)\s+([0-9a-fA-F:\.]+/\d+)\s+is directly connected,\s*([a-zA-Z0-9_\-\.]+)",
                clean,
            )
            if m_frr_conn:
                routes.append({
                    "protocol": "connected",
                    "destination": m_frr_conn.group(2),
                    "next_hop": None,
                    "interface": m_frr_conn.group(3),
                    "active": True,
                    "raw": clean,
                })
                continue

            # Linux default: e.g. "default via 10.1.1.1 dev eth1"
            m_linux_def = re.match(r"default\s+via\s+([0-9a-fA-F:\.]+)\s+dev\s+([a-zA-Z0-9_\-\.]+)", clean)
            if m_linux_def:
                routes.append({
                    "protocol": "static",
                    "destination": "0.0.0.0/0",
                    "next_hop": m_linux_def.group(1),
                    "interface": m_linux_def.group(2),
                    "active": True,
                    "raw": clean,
                })
                continue

            # Linux subnet route: e.g. "10.2.2.0/24 via 10.1.12.2 dev eth2" or IPv6
            m_linux_sub = re.match(r"([0-9a-fA-F:\.]+/\d+)\s+via\s+([0-9a-fA-F:\.]+)\s+dev\s+([a-zA-Z0-9_\-\.]+)", clean)
            if m_linux_sub:
                routes.append({
                    "protocol": "static",
                    "destination": m_linux_sub.group(1),
                    "next_hop": m_linux_sub.group(2),
                    "interface": m_linux_sub.group(3),
                    "active": True,
                    "raw": clean,
                })
                continue

            # Linux direct link: e.g. "10.1.1.0/24 dev eth1 proto kernel scope link" or IPv6
            m_linux_link = re.match(r"([0-9a-fA-F:\.]+/\d+)\s+dev\s+([a-zA-Z0-9_\-\.]+)", clean)
            if m_linux_link:
                routes.append({
                    "protocol": "connected",
                    "destination": m_linux_link.group(1),
                    "next_hop": None,
                    "interface": m_linux_link.group(2),
                    "active": True,
                    "raw": clean,
                })

        return {
            "type": "route_inventory",
            "count": len(routes),
            "routes": routes,
        }

    @staticmethod
    def _parse_ping_output(stdout: str, exit_code: int) -> Dict[str, Any]:
        """Parse ping command output into structured telemetry metrics."""
        transmitted = 0
        received = 0
        loss_pct = 100.0 if exit_code != 0 else 0.0
        rtt_avg = None

        # Packets stats e.g. "3 packets transmitted, 3 received, 0% packet loss"
        m_pkt = re.search(r"(\d+)\s+packets transmitted,\s*(\d+)\s+(?:packets\s+)?received,\s*(\d+(?:\.\d+)?)%\s+packet loss", stdout)
        if m_pkt:
            transmitted = int(m_pkt.group(1))
            received = int(m_pkt.group(2))
            loss_pct = float(m_pkt.group(3))

        # RTT stats e.g. "rtt min/avg/max/mdev = 0.1/0.2/0.3/0.05 ms"
        m_rtt = re.search(r"rtt\s+min/avg/max/(?:mdev|stddev)\s*=\s*[0-9\.]+/([0-9\.]+)/[0-9\.]+", stdout)
        if m_rtt:
            try:
                rtt_avg = float(m_rtt.group(1))
            except Exception:
                pass

        return {
            "type": "ping_telemetry",
            "exit_code": exit_code,
            "packets_transmitted": transmitted,
            "packets_received": received,
            "packet_loss_pct": loss_pct,
            "is_reachable": (received > 0 and loss_pct < 100.0 and exit_code == 0),
            "rtt_avg_ms": rtt_avg,
            "raw_summary": stdout.splitlines()[-2:] if stdout.splitlines() else [],
        }
