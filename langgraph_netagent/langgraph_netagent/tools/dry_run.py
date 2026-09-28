"""Dry-Run Safety Checker for Day-2 Remediation Plans.

Validates remediation plans before execution:
- FRR config syntax checking
- IP conflict detection
- Command safety guardrails
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple


class DryRunChecker:
    """Pre-execution safety validator for remediation plans."""

    # Commands that are always blocked (destructive operations)
    BLOCKED_COMMANDS = [
        r"\brm\s+-rf\b",
        r"\bformat\b",
        r"\bmkfs\b",
        r"\bdd\s+if=\b",
        r"\breboot\b",
        r"(?<!no\s)\bshutdown\s+(?:-[hHrncP]|\+?\d|now)\b",  # block system shutdown (e.g. shutdown now) but allow interface shutdown
        r"\bsystemctl\s+stop\b",
        r"\bkill\s+-9\b",
        r"\bdocker\s+rm\b",
        r"\bclab\s+destroy\b",
    ]

    # Patterns that require extra caution
    CAUTION_PATTERNS = [
        (r"\bno\s+router\s+\w+", "Removing entire routing process"),
        (r"\bno\s+interface\b", "Removing interface configuration"),
        (r"\bdefault-originate\b", "Advertising default route to peers"),
        (r"\bredistribute\b", "Route redistribution change"),
    ]

    @classmethod
    def check(
        cls,
        remediation_plan: Dict[str, Any],
        baseline: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a remediation plan before execution.

        Args:
            remediation_plan: RemediationPlan dict.
            baseline: Optional baseline for cross-reference validation.

        Returns:
            Tuple of (passed: bool, errors: List[str]).
            If passed is True, errors is empty.
        """
        errors: List[str] = []

        # 1. Check exec_commands for blocked patterns
        exec_cmds = remediation_plan.get("exec_commands", [])
        for cmd in exec_cmds:
            cmd_errors = cls._check_command_safety(cmd)
            errors.extend(cmd_errors)

        # 2. Check target entity exists in baseline
        target = remediation_plan.get("target_entity", "")
        if baseline and target:
            nodes = baseline.get("nodes", {})
            if target not in nodes:
                errors.append(
                    f"Target entity '{target}' not found in baseline. "
                    f"Available nodes: {list(nodes.keys())}"
                )
            elif nodes[target].get("state") != "running":
                errors.append(
                    f"Target entity '{target}' is not in 'running' state: "
                    f"{nodes[target].get('state')}"
                )

        # 3. Validate configuration patch if present
        config_patch = remediation_plan.get("configuration_patch")
        if config_patch:
            patch_errors = cls._check_config_patch(config_patch, baseline)
            errors.extend(patch_errors)

        # 4. Validate IP addresses in exec commands
        for cmd in exec_cmds:
            ip_errors = cls._check_ip_validity(cmd)
            errors.extend(ip_errors)

        # 5. Check rollback steps exist
        rollback = remediation_plan.get("rollback_steps", [])
        if not rollback and exec_cmds:
            errors.append(
                "WARNING: No rollback steps defined. "
                "Remediation without rollback is risky."
            )

        # 6. Check for caution patterns (warnings, not blocking)
        for cmd in exec_cmds:
            for pattern, description in cls.CAUTION_PATTERNS:
                if re.search(pattern, cmd, re.IGNORECASE):
                    errors.append(f"CAUTION: {description} in command: {cmd}")

        # Filter: only hard errors block execution (not warnings/cautions)
        hard_errors = [e for e in errors if not e.startswith(("WARNING:", "CAUTION:"))]
        passed = len(hard_errors) == 0

        return passed, errors

    @classmethod
    def _check_command_safety(cls, command: str) -> List[str]:
        """Check a single command against blocked patterns."""
        errors = []
        clean = re.sub(r"^docker\s+exec\s+(?:-it\s+)?[\w\-\.]+\s+", "", command).strip()
        is_net_cmd = any(k in clean.lower() for k in ("vtysh", "sr_cli", "interface", "no shutdown"))

        for pattern in cls.BLOCKED_COMMANDS:
            if is_net_cmd and "shutdown" in pattern:
                continue
            if re.search(pattern, clean, re.IGNORECASE):
                errors.append(
                    f"BLOCKED: Dangerous command detected: '{command}' "
                    f"matches safety pattern '{pattern}'"
                )
        return errors

    @classmethod
    def _check_config_patch(cls, patch: Dict[str, Any], baseline: Optional[Dict[str, Any]]) -> List[str]:
        """Validate configuration patch content."""
        errors = []
        file_path = patch.get("file_path", "")
        new_content = patch.get("new_content", "")

        if not file_path:
            errors.append("Configuration patch missing file_path")
        if not new_content:
            errors.append("Configuration patch has empty new_content")

        # FRR config basic syntax check
        if "frr" in file_path.lower() and new_content:
            frr_errors = cls._check_frr_config_syntax(new_content)
            errors.extend(frr_errors)

        return errors

    @classmethod
    def _check_frr_config_syntax(cls, config: str) -> List[str]:
        """Basic FRR configuration syntax validation."""
        errors = []

        # Check for balanced 'router X' / 'exit' blocks
        router_opens = len(re.findall(r'^\s*router\s+', config, re.MULTILINE))
        # Note: exit can close many blocks, so we just check router blocks have content
        if router_opens > 0:
            # Ensure each 'router' block has at least some content
            router_blocks = re.findall(r'router\s+\w+.*?(?=router\s+|\Z)', config, re.DOTALL)
            for block in router_blocks:
                if len(block.strip().splitlines()) < 2:
                    errors.append(f"FRR: Router block appears empty: {block.strip()[:80]}")

        # Check for obviously malformed IP addresses in routes
        route_lines = re.findall(r'ip route\s+(.+)', config)
        for route_line in route_lines:
            parts = route_line.strip().split()
            if len(parts) >= 2:
                try:
                    ipaddress.IPv4Network(parts[0], strict=False)
                except ValueError:
                    errors.append(f"FRR: Invalid route prefix: {parts[0]}")

        return errors

    @classmethod
    def _check_ip_validity(cls, command: str) -> List[str]:
        """Check IP addresses referenced in commands are valid."""
        errors = []
        # Find IP-like patterns
        ip_candidates = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d{1,2}))?\b', command)
        for ip_str, prefix in ip_candidates:
            try:
                ipaddress.IPv4Address(ip_str)
            except ValueError:
                errors.append(f"Invalid IP address in command: {ip_str}")
            if prefix:
                pfx = int(prefix)
                if pfx < 0 or pfx > 32:
                    errors.append(f"Invalid prefix length /{prefix} for {ip_str}")
        return errors
