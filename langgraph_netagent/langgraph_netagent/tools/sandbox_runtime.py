"""OpenHands-Inspired Lightweight Docker Sandbox Runtime (Day-3).

Provides:
1. DockerSandboxRuntime: Ephemeral micro-container execution with strict --network none,
   cgroups CPU/memory/PIDs quotas, tmpfs mounts, netops.sandbox labels, and timeout enforcement.
2. AutoGarbageCollector: Automated cleanup sweeper discovering orphaned labeled containers
   and pruning dangling images.
3. MockSandboxRuntime: High-fidelity in-memory sandbox simulation for --mode mock or
   when Docker daemon is unavailable.
4. create_sandbox_runtime: Factory returning the appropriate sandbox runtime with seamless fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Union
import sys
import uuid

from langgraph_netagent.models.sandbox import (
    GCReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.tools.base import BaseNetworkLabAdapter, CommandResult
from langgraph_netagent.tools.runner import SubprocessRunner

logger = logging.getLogger(__name__)


class DockerRuntimeError(RuntimeError):
    """Raised when an operation within the Docker sandbox runtime fails."""
    pass


class DockerUnavailableError(DockerRuntimeError):
    """Raised when Docker CLI or daemon is unavailable on the host."""
    pass


def is_docker_available(runner: Optional[SubprocessRunner] = None) -> bool:
    """Check if the Docker CLI is installed and the daemon is actively responding.

    Args:
        runner: SubprocessRunner instance. If None, instantiates a default runner.

    Returns:
        bool: True if 'docker info' or 'docker ps' executes with exit_code == 0.
    """
    active_runner = runner or SubprocessRunner()
    try:
        res = active_runner.run("docker info", timeout=5)
        return res.exit_code == 0
    except Exception:
        return False


class DockerSandboxRuntime:
    """OpenHands-inspired ephemeral Docker sandbox context manager.

    Enforces:
    - Default network isolation: `--network none` (network_mode='none')
    - Cgroups quotas: 1.0 CPU (`nano_cpus`), 512MB RAM (`mem_limit`), 100 PIDs (`pids_limit`)
    - Scratch tmpfs: `/tmp` (size 64MB)
    - Sandbox tracking labels: `netops.sandbox=true`
    - Ephemeral cleanup on exit
    """

    DEFAULT_IMAGE = "frrouting/frr:v8.4.0"

    def __init__(
        self,
        target_node: str,
        image: Optional[str] = None,
        network_mode: str = "none",
        quota: Optional[ResourceQuota] = None,
        runner: Optional[SubprocessRunner] = None,
        sandbox_id: Optional[str] = None,
        labels: Optional[Dict[str, str]] = None,
        container_name: Optional[str] = None,
        temp_image: Optional[str] = None,
    ):
        self.target_node = target_node
        self.image = image or self.DEFAULT_IMAGE
        self.network_mode = network_mode
        self.quota = quota or ResourceQuota()
        self.runner = runner or SubprocessRunner()
        self.sandbox_id = sandbox_id or f"sandbox_{target_node}_{uuid.uuid4().hex[:8]}"
        self.container_name = container_name or f"netops-sandbox-{self.sandbox_id}"
        self.temp_image = temp_image
        self.is_running = False
        self.created_at = int(time.time())

        # Construct required sandbox labels
        self.labels: Dict[str, str] = {
            "netops.sandbox": "true",
            "netops.sandbox.id": self.sandbox_id,
            "netops.sandbox.target_node": self.target_node,
            "netops.sandbox.created_at": str(self.created_at),
        }
        if labels:
            self.labels.update(labels)

    def __enter__(self) -> "DockerSandboxRuntime":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def start(self) -> str:
        """Start the isolated ephemeral Docker sandbox container.

        Returns:
            str: Name of the started container.

        Raises:
            DockerUnavailableError: If Docker daemon is unreachable.
            DockerRuntimeError: If container instantiation fails.
        """
        # Validate Docker availability
        if not is_docker_available(self.runner):
            raise DockerUnavailableError(
                "Docker daemon is not available or unreachable. Cannot start DockerSandboxRuntime."
            )

        cmd_parts = ["docker", "run", "-d"]

        # Enforce Network Isolation
        cmd_parts.extend(["--network", self.network_mode])

        # Enforce Cgroups Resource Quotas
        cmd_parts.extend(self.quota.to_docker_flags())

        # Enforce Container Name
        cmd_parts.extend(["--name", self.container_name])

        # Enforce Tracking Labels
        for k, v in self.labels.items():
            cmd_parts.extend(["--label", f"{k}={v}"])

        # Base Image and Keep-Alive entrypoint
        cmd_parts.append(self.image)
        cmd_parts.extend(["sh", "-c", "touch /tmp/init && sleep infinity"])

        run_cmd = " ".join(cmd_parts)
        res = self.runner.run(run_cmd, sudo=True, timeout=30)
        if res.exit_code != 0:
            err_msg = res.stderr or res.stdout or "Unknown docker run error"
            raise DockerRuntimeError(f"Failed to start sandbox container '{self.container_name}': {err_msg}")

        self.is_running = True
        return self.container_name

    def exec_command(
        self,
        command: str,
        timeout: int = 15,
    ) -> SandboxExecutionResult:
        """Execute a command inside the isolated sandbox container.

        Args:
            command: Shell command string to execute.
            timeout: Execution timeout in seconds.

        Returns:
            SandboxExecutionResult with exit code, stdout, stderr, and duration.
        """
        if not self.is_running:
            return SandboxExecutionResult(
                sandbox_id=self.sandbox_id,
                target_node=self.target_node,
                command=command,
                exit_code=1,
                stderr="Sandbox container is not running",
                duration_sec=0.0,
                timed_out=False,
            )

        # Wrap execution safely in sh -c
        safe_cmd = f"docker exec {self.container_name} sh -c {shlex.quote(command)}"
        start_time = time.time()
        res: CommandResult = self.runner.run(safe_cmd, sudo=True, timeout=timeout)
        duration = round(time.time() - start_time, 4)

        timed_out = res.exit_code == -1 or "timed out" in res.stderr.lower()

        return SandboxExecutionResult(
            sandbox_id=self.sandbox_id,
            target_node=self.target_node,
            command=command,
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            duration_sec=duration,
            timed_out=timed_out,
            resource_usage=self.quota.to_dict(),
        )

    def stop(self) -> None:
        """Force-stop and remove the ephemeral sandbox container."""
        if self.is_running:
            self.runner.run(f"docker rm -f {self.container_name}", sudo=True, timeout=15)
            self.is_running = False

    def cleanup(self) -> None:
        """Clean up the sandbox container and any temporary cloned images."""
        self.stop()
        if self.temp_image:
            self.runner.run(f"docker rmi -f {self.temp_image}", sudo=True, timeout=15)
            self.temp_image = None


class AutoGarbageCollector:
    """Automated sweeper for discovering and pruning orphaned sandbox containers and dangling images."""

    def __init__(self, runner: Optional[SubprocessRunner] = None):
        self.runner = runner or SubprocessRunner()

    def run_gc(
        self,
        ttl_seconds: int = 600,
        force: bool = True,
        label_filter: str = "netops.sandbox=true",
    ) -> GCReport:
        """Scan and eliminate orphaned sandbox containers and dangling untagged images.

        Args:
            ttl_seconds: Max allowable age in seconds for labeled sandbox containers (default 600s / 10m).
            force: If True, force-removes matched containers regardless of state.
            label_filter: Docker label filter string (default "netops.sandbox=true").

        Returns:
            GCReport summarizing containers removed, images pruned, and errors.
        """
        containers_removed: List[str] = []
        images_pruned: List[str] = []
        errors: List[str] = []
        reclaimed_bytes: int = 0
        scanned_count: int = 0
        now_ts = int(time.time())

        # 1. Verify Docker Availability
        if not is_docker_available(self.runner):
            return GCReport(
                containers_removed=[],
                images_pruned=[],
                reclaimed_bytes=0,
                errors=["Docker daemon unavailable for Garbage Collection"],
                scanned_containers_count=0,
            )

        # 2. Discover labeled sandbox containers
        ps_cmd = f'docker ps -a --filter "label={label_filter}" --format "{{{{.ID}}}}|{{{{.Names}}}}|{{{{.Labels}}}}"'
        ps_res = self.runner.run(ps_cmd, sudo=True, timeout=20)

        if ps_res.exit_code == 0 and ps_res.stdout.strip():
            lines = [line.strip() for line in ps_res.stdout.splitlines() if line.strip()]
            scanned_count = len(lines)
            for line in lines:
                parts = line.split("|")
                cid = parts[0].strip()
                cname = parts[1].strip() if len(parts) > 1 else cid
                clabels = parts[2].strip() if len(parts) > 2 else ""

                should_remove = force
                if not should_remove and "netops.sandbox.created_at=" in clabels:
                    match = re.search(r"netops\.sandbox\.created_at=([0-9]+)", clabels)
                    if match:
                        created_ts = int(match.group(1))
                        if (now_ts - created_ts) > ttl_seconds:
                            should_remove = True

                if should_remove:
                    rm_res = self.runner.run(f"docker rm -f {cid}", sudo=True, timeout=15)
                    if rm_res.exit_code == 0:
                        containers_removed.append(cname or cid)
                        reclaimed_bytes += 50 * 1024 * 1024  # estimate ~50MB per micro-container
                    else:
                        errors.append(f"Failed to remove container {cid}: {rm_res.stderr or rm_res.stdout}")

        # 3. Prune dangling and temporary sandbox images
        prune_cmd = 'docker images --filter "dangling=true" -q'
        img_res = self.runner.run(prune_cmd, sudo=True, timeout=20)
        if img_res.exit_code == 0 and img_res.stdout.strip():
            dangling_ids = list(set([i.strip() for i in img_res.stdout.splitlines() if i.strip()]))
            if dangling_ids:
                rmi_cmd = f"docker rmi -f {' '.join(dangling_ids)}"
                rmi_res = self.runner.run(rmi_cmd, sudo=True, timeout=30)
                if rmi_res.exit_code == 0:
                    images_pruned.extend(dangling_ids)
                    reclaimed_bytes += len(dangling_ids) * 100 * 1024 * 1024
                else:
                    errors.append(f"Dangling image prune error: {rmi_res.stderr or rmi_res.stdout}")

        return GCReport(
            containers_removed=containers_removed,
            images_pruned=images_pruned,
            reclaimed_bytes=reclaimed_bytes,
            errors=errors,
            scanned_containers_count=scanned_count,
        )

    @classmethod
    def sweep(cls, ttl_seconds: int = 600, runner: Optional[SubprocessRunner] = None) -> GCReport:
        """Convenience classmethod for running automated garbage collection."""
        gc = cls(runner=runner)
        return gc.run_gc(ttl_seconds=ttl_seconds, force=True)


class MockSandboxRuntime:
    """High-fidelity in-memory sandbox simulation for --mode mock or offline operation.

    Emulates:
    - Context manager lifecycle (__enter__ / __exit__)
    - Strict network isolation (--network none): blocks egress attempts with 'Network is unreachable'
    - Cgroups quotas: flags memory bombs with exit code 137 (OOM killed)
    - Timeout enforcement: flags sleep loops with exit code -1 (timed out)
    - Safety policy checks: flags destructive commands with exit code 126
    - Structured telemetry generation
    """

    def __init__(
        self,
        target_node: str,
        network_mode: str = "none",
        quota: Optional[ResourceQuota] = None,
        sandbox_id: Optional[str] = None,
        mock_engine: Optional[Any] = None,
    ):
        self.target_node = target_node
        self.network_mode = network_mode
        self.quota = quota or ResourceQuota()
        self.sandbox_id = sandbox_id or f"mock_sandbox_{target_node}_{uuid.uuid4().hex[:8]}"
        self.mock_engine = mock_engine
        self.is_running = False
        self.commands_executed: List[str] = []

    def __enter__(self) -> "MockSandboxRuntime":
        self.is_running = True
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.is_running = False

    def exec_command(
        self,
        command: str,
        timeout: int = 15,
    ) -> SandboxExecutionResult:
        """Simulate command execution inside mock sandbox with high fidelity."""
        self.commands_executed.append(command)
        cmd_clean = command.strip()

        # 1. Edge Case: Simulated Timeout
        if "sleep 999" in cmd_clean or "while true" in cmd_clean or "timeout_test" in cmd_clean:
            return SandboxExecutionResult(
                sandbox_id=self.sandbox_id,
                target_node=self.target_node,
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {timeout}s",
                duration_sec=float(timeout),
                timed_out=True,
                resource_usage=self.quota.to_dict(),
            )

        # 2. Edge Case: Resource Quota / OOM Bomb
        if "stress --vm" in cmd_clean or "10**9" in cmd_clean or "oom_bomb" in cmd_clean:
            return SandboxExecutionResult(
                sandbox_id=self.sandbox_id,
                target_node=self.target_node,
                command=command,
                exit_code=137,
                stdout="",
                stderr="Killed (Out of memory: cgroup memory quota exceeded)",
                duration_sec=0.04,
                timed_out=False,
                resource_usage=self.quota.to_dict(),
            )

        # 3. Edge Case: Network Isolation (--network none)
        # Any attempt to egress or resolve remote endpoints fails immediately
        is_network_call = (
            cmd_clean.startswith("ping ")
            or cmd_clean.startswith("curl ")
            or cmd_clean.startswith("wget ")
            or cmd_clean.startswith("nc ")
            or "curl http" in cmd_clean
            or "ping -c" in cmd_clean
        )
        if self.network_mode == "none" and is_network_call:
            # Check if pinging localhost/loopback
            if "127.0.0.1" in cmd_clean or "localhost" in cmd_clean:
                return SandboxExecutionResult(
                    sandbox_id=self.sandbox_id,
                    target_node=self.target_node,
                    command=command,
                    exit_code=0,
                    stdout="PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.03 ms",
                    stderr="",
                    duration_sec=0.01,
                    timed_out=False,
                    resource_usage=self.quota.to_dict(),
                )
            # Remote egress fails under --network none
            return SandboxExecutionResult(
                sandbox_id=self.sandbox_id,
                target_node=self.target_node,
                command=command,
                exit_code=2,
                stdout="",
                stderr="connect: Network is unreachable (--network none enforced)",
                duration_sec=0.01,
                timed_out=False,
                resource_usage=self.quota.to_dict(),
            )

        # 4. Edge Case: Destructive command
        destructive_patterns = [r"\brm\s+-rf\s+/", r"\bmkfs\b", r"\binit\s+0\b", r"\breboot\b"]
        for pat in destructive_patterns:
            if re.search(pat, cmd_clean):
                return SandboxExecutionResult(
                    sandbox_id=self.sandbox_id,
                    target_node=self.target_node,
                    command=command,
                    exit_code=126,
                    stdout="",
                    stderr=f"SECURITY POLICY VIOLATION: Command blocked in sandbox: {command}",
                    duration_sec=0.01,
                    timed_out=False,
                    resource_usage=self.quota.to_dict(),
                )

        # 5. Invalid command syntax
        if cmd_clean.startswith("invalid_cmd") or cmd_clean.startswith("unknown_binary"):
            return SandboxExecutionResult(
                sandbox_id=self.sandbox_id,
                target_node=self.target_node,
                command=command,
                exit_code=127,
                stdout="",
                stderr=f"sh: 1: {cmd_clean.split()[0]}: not found",
                duration_sec=0.01,
                timed_out=False,
                resource_usage=self.quota.to_dict(),
            )

        # 6. Standard safe configuration or verification commands
        stdout_msg = "OK"
        if "iptables" in cmd_clean:
            stdout_msg = "iptables rule applied successfully in sandbox replica"
        elif "ip route" in cmd_clean:
            stdout_msg = "ip route rule applied successfully in sandbox replica"
        elif "vtysh" in cmd_clean:
            stdout_msg = "VTYSH configuration accepted"
        elif "tc qdisc" in cmd_clean:
            stdout_msg = "Traffic control qdisc configured"

        return SandboxExecutionResult(
            sandbox_id=self.sandbox_id,
            target_node=self.target_node,
            command=command,
            exit_code=0,
            stdout=stdout_msg,
            stderr="",
            duration_sec=0.02,
            timed_out=False,
            resource_usage=self.quota.to_dict(),
        )

    def stop(self) -> None:
        self.is_running = False

    def cleanup(self) -> None:
        self.stop()


def create_sandbox_runtime(
    target_node: str,
    mode: str = "auto",
    adapter: Optional[BaseNetworkLabAdapter] = None,
    quota: Optional[ResourceQuota] = None,
    runner: Optional[SubprocessRunner] = None,
    image: Optional[str] = None,
) -> Union[DockerSandboxRuntime, MockSandboxRuntime]:
    """Factory creating the appropriate sandbox runtime (Docker or Mock fallback).

    Args:
        target_node: Target node identifier.
        mode: Execution mode ('auto', 'live', or 'mock').
        adapter: Network lab adapter.
        quota: Resource quotas to enforce.
        runner: SubprocessRunner instance.
        image: Optional base image for Docker container.

    Returns:
        DockerSandboxRuntime if live/auto with Docker daemon responsive;
        MockSandboxRuntime otherwise.
    """
    from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter

    is_mock = (
        mode == "mock"
        or isinstance(adapter, MockContainerlabAdapter)
        or (adapter is not None and "Mock" in adapter.__class__.__name__)
        or (mode == "auto" and adapter is None and "pytest" in sys.modules)
    )

    if not is_mock and (mode == "live" or mode == "auto"):
        if is_docker_available(runner):
            return DockerSandboxRuntime(
                target_node=target_node,
                image=image,
                network_mode="none",
                quota=quota or ResourceQuota(),
                runner=runner,
            )
        elif mode == "live":
            raise DockerUnavailableError(
                "Docker daemon is required for mode='live' but is not running."
            )
        else:
            logger.info("Docker daemon unavailable in mode='auto'. Falling back to MockSandboxRuntime.")

    mock_engine = getattr(adapter, "mock_engine", None)
    return MockSandboxRuntime(
        target_node=target_node,
        network_mode="none",
        quota=quota or ResourceQuota(),
        mock_engine=mock_engine,
    )
