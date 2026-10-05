"""Lab Isolation Guard enforcing strict container boundaries for Containerlab clos5 topology.

Enforces:
1. Target container naming boundary: only containers matching '^clab-clos5-[a-zA-Z0-9_\\-]+$'
   or recognized clos5 logical nodes (leaf1..4, spine1..4, superspine1..2, dc-egress,
   ext-router, h1..4, attacker, sflow-rt) are permitted.
2. Complete protection of host network interfaces: blocks operations targeting eth0, docker0,
   br-*, virbr*, veth*, or Windows NICs (vEthernet, Wi-Fi, Ethernet).
3. Protection of host routing tables and network namespaces: blocks nsenter, /proc/1/ns/net,
   ip netns, --net=host, and host network reconfiguration tools.
4. Defense against destructive system operations (reboot, shutdown, disk formatting).
"""

from __future__ import annotations

import re
from typing import Iterable, Optional, Set


class LabIsolationViolationError(Exception):
    """Raised when an operation violates Containerlab isolation boundaries."""
    pass


class LabIsolationGuard:
    """Enforces strict isolation rules restricting operations to clos5 containers."""

    # Default 18 logical nodes defined in canonical clos5 topology
    DEFAULT_CLOS5_NODES: Set[str] = {
        "leaf1", "leaf2", "leaf3", "leaf4",
        "spine1", "spine2", "spine3", "spine4",
        "superspine1", "superspine2",
        "dc-egress", "ext-router",
        "h1", "h2", "h3", "h4",
        "attacker", "sflow-rt",
    }

    # Allowed container name pattern: must be prefixed with clab-clos5-
    CONTAINER_NAME_PATTERN = re.compile(r"^clab-clos5-[a-zA-Z0-9_\-]+$")

    # Host interfaces strictly prohibited from mutation or targeting
    BLOCKED_HOST_INTERFACE_PATTERNS = [
        # WSL/Linux primary host NIC
        re.compile(r"\beth0\b", re.IGNORECASE),
        # Docker host bridge
        re.compile(r"\bdocker0\b", re.IGNORECASE),
        # Generic and Docker bridges (br-..., br_..., virbr...)
        re.compile(r"\bbr-[a-f0-9_\-]+\b", re.IGNORECASE),
        re.compile(r"\bbr_[a-zA-Z0-9_\-]+\b", re.IGNORECASE),
        re.compile(r"\bvirbr\d*\b", re.IGNORECASE),
        re.compile(r"\bveth[a-f0-9_\-]+\b", re.IGNORECASE),
        # Windows physical and virtual adapters
        re.compile(r"\bvEthernet\b", re.IGNORECASE),
        re.compile(r"\bWi-?Fi\b", re.IGNORECASE),
        re.compile(r"\bEthernet(?:\s+\d+)?\b", re.IGNORECASE),
        re.compile(r"\bLocal\s+Area\s+Connection\b", re.IGNORECASE),
        re.compile(r"\bWireless(?:\s+Network)?\b", re.IGNORECASE),
        re.compile(r"\bLoopback(?:\s+Adapter)?\b", re.IGNORECASE),
    ]

    # Patterns indicating attempts to target host namespaces or break container containment
    BLOCKED_HOST_ESCAPE_PATTERNS = [
        # Namespace escape tools
        re.compile(r"\bnsenter\b", re.IGNORECASE),
        re.compile(r"/proc/(?:1|\d+)/ns/net\b", re.IGNORECASE),
        re.compile(r"\bip\s+netns\b", re.IGNORECASE),
        re.compile(r"--net(?:work)?(?:\s+|=)host\b", re.IGNORECASE),
        re.compile(r"--pid(?:\s+|=)host\b", re.IGNORECASE),
        re.compile(r"--privileged\b", re.IGNORECASE),
        # Windows network manipulation tools targeting host
        re.compile(r"\bnetsh\b", re.IGNORECASE),
        re.compile(r"\bGet-NetAdapter\b", re.IGNORECASE),
        re.compile(r"\bSet-NetIPAddress\b", re.IGNORECASE),
        re.compile(r"\bNew-NetIPAddress\b", re.IGNORECASE),
        re.compile(r"\bipconfig\b", re.IGNORECASE),
        # Destructive host operations
        re.compile(r"(?:^|[;&|])\s*(?:sudo\s+)?(?:/(?:usr/)?(?:s)?bin/)?(?:reboot|poweroff|halt)\b", re.IGNORECASE),
        re.compile(r"(?:^|[;&|])\s*(?:sudo\s+)?(?:/(?:usr/)?(?:s)?bin/)?shutdown\b(?!\s+(?:bgp|neighbor|interface))", re.IGNORECASE),
        re.compile(r"\bshutdown\s+(?:-[hHrPck]+|now|\+\d+)\b", re.IGNORECASE),
        re.compile(r"\bsystemctl\s+(reboot|poweroff|halt)\b", re.IGNORECASE),
        re.compile(r"\brm\s+-[a-zA-Z]*[rR].*?/\s*$", re.IGNORECASE),
        re.compile(r"\bmkfs\b", re.IGNORECASE),
        re.compile(r"\b(?:wipefs|shred|fdisk|parted)\b", re.IGNORECASE),
    ]

    def __init__(
        self,
        lab_name: str = "clos5",
        allowed_nodes: Optional[Iterable[str]] = None,
    ):
        """Initialize LabIsolationGuard.

        Args:
            lab_name: Expected lab name (default 'clos5').
            allowed_nodes: Optional custom set of logical node names.
        """
        self.lab_name = lab_name
        self.allowed_nodes: Set[str] = (
            set(allowed_nodes) if allowed_nodes is not None else set(self.DEFAULT_CLOS5_NODES)
        )
        self.container_regex = re.compile(rf"^clab-{re.escape(lab_name)}-[a-zA-Z0-9_\-]+$")

    def is_valid_container_target(self, target: Optional[str]) -> bool:
        """Check if target is a valid clos5 container name or recognized logical node.

        Args:
            target: Container or node name string.

        Returns:
            True if valid and strictly within clos5 lab boundaries, False otherwise.
        """
        if not target or not isinstance(target, str):
            return False

        clean_target = target.strip()
        if not clean_target:
            return False

        # Strictly disallow explicit host indicators
        if clean_target.lower() in {"host", "localhost", "127.0.0.1", "::1", "root"}:
            return False

        # Check full container name matching regex: clab-clos5-<node>
        if self.container_regex.match(clean_target):
            # Also ensure suffix is a known node if allowed_nodes is non-empty
            suffix = clean_target[len(f"clab-{self.lab_name}-"):]
            if self.allowed_nodes and suffix not in self.allowed_nodes:
                return False
            return True

        # Check logical node name
        if clean_target in self.allowed_nodes:
            return True

        return False

    def assert_container_isolated(self, container_name: Optional[str]) -> None:
        """Assert that the specified container name satisfies clos5 lab isolation.

        Args:
            container_name: Target container or logical node name.

        Raises:
            LabIsolationViolationError: If target is not a valid clos5 container.
        """
        if not self.is_valid_container_target(container_name):
            raise LabIsolationViolationError(
                f"Lab isolation violation: target '{container_name}' is not an authorized "
                f"clos5 container. Must match '{self.container_regex.pattern}' or be one of "
                f"the permitted nodes: {sorted(self.allowed_nodes)}."
            )

    def resolve_container_name(self, node_or_container: str) -> str:
        """Resolve node or container name to canonical clab-clos5-<node> format.

        Args:
            node_or_container: Logical node name or full container name.

        Returns:
            Canonical container name string.

        Raises:
            LabIsolationViolationError: If node_or_container is unauthorized.
        """
        self.assert_container_isolated(node_or_container)
        clean = node_or_container.strip()
        if clean.startswith(f"clab-{self.lab_name}-"):
            return clean
        return f"clab-{self.lab_name}-{clean}"

    def validate_command_safety(self, command: str, container_name: Optional[str] = None) -> bool:
        """Check if a command is safe and does not target host resources.

        Args:
            command: The CLI command to execute.
            container_name: Optional target container name.

        Returns:
            True if command passes isolation checks, False if it targets host or escapes containment.
        """
        try:
            self.assert_command_safety(command, container_name=container_name)
            return True
        except LabIsolationViolationError:
            return False

    def assert_command_safety(self, command: str, container_name: Optional[str] = None) -> None:
        """Assert that command does not target host interfaces, namespaces, or tables.

        Args:
            command: The CLI command to validate.
            container_name: Optional target container name.

        Raises:
            LabIsolationViolationError: If command violates host isolation boundaries.
        """
        if not command or not isinstance(command, str):
            raise LabIsolationViolationError("Command string must be a non-empty string.")

        # If container_name is provided, ensure container is isolated
        if container_name is not None:
            self.assert_container_isolated(container_name)

        cmd_clean = command.strip()

        # 1. Check blocked host interface patterns
        for pattern in self.BLOCKED_HOST_INTERFACE_PATTERNS:
            if pattern.search(cmd_clean):
                raise LabIsolationViolationError(
                    f"Lab isolation violation: command targets protected host interface "
                    f"matching '{pattern.pattern}'. Command: '{cmd_clean}'."
                )

        # 2. Check namespace escapes and forbidden host tools
        for pattern in self.BLOCKED_HOST_ESCAPE_PATTERNS:
            if pattern.search(cmd_clean):
                raise LabIsolationViolationError(
                    f"Lab isolation violation: command contains prohibited host escape or system "
                    f"tampering pattern '{pattern.pattern}'. Command: '{cmd_clean}'."
                )
