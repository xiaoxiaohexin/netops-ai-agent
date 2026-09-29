"""Shadow Sandbox Validation & Pre-Flight Verification Subsystem for LangGraph NetAgent.

Provides:
1. ShadowSandboxManager.run_sandbox_validation: Backward-compatible method validating
   candidate remediation commands in an isolated replica, integrating auto-GC and quotas.
2. ShadowSandboxManager.run_preflight_verification: Produces certified PreflightSandboxPassReport
   with network isolation (--network none), cgroups quotas, deterministic signature, and auto-GC.
"""

from __future__ import annotations

import copy
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

from langgraph_netagent.models.operational import AALToolCall, ShadowSandboxResult
from langgraph_netagent.models.sandbox import (
    PreflightSandboxPassReport,
    ResourceQuota,
    SandboxExecutionResult,
)
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, VirtualNode
from langgraph_netagent.tools.sandbox_runtime import (
    AutoGarbageCollector,
    DockerSandboxRuntime,
    MockSandboxRuntime,
    create_sandbox_runtime,
)

logger = logging.getLogger(__name__)


class ShadowSandboxManager:
    """Manages the creation, command execution, and cleanup of shadow sandbox replicas."""

    @classmethod
    def run_sandbox_validation(
        cls,
        target_node: str,
        patch_commands: List[str],
        adapter: BaseNetworkLabAdapter,
        aal: AgentAccessLayer,
        step_tag: Optional[str] = None,
        timeout: int = 15,
        clone_timeout: int = 60,
        allow_empty: bool = True,
        quota: Optional[ResourceQuota] = None,
    ) -> ShadowSandboxResult:
        """Clone target node into an isolated sandbox replica and execute candidate patch.

        Maintains 100% backward compatibility for existing callers while incorporating
        automated garbage collection and resource quotas.

        Args:
            target_node: Name of live node to clone.
            patch_commands: Candidate configuration or remediation commands to test.
            adapter: Lab adapter (live or mock).
            aal: AgentAccessLayer instance for safety checks and normalized execution.
            step_tag: Iteration step tag for deterministic tracking.
            timeout: Command timeout in seconds.
            clone_timeout: Docker commit and container instantiation timeout.
            allow_empty: Whether an empty list of patch commands is considered passing.
            quota: Optional resource quotas to enforce.

        Returns:
            ShadowSandboxResult with detailed test logs and pass/fail verdict.
        """
        # 1. Startup Hook: Sweep orphaned sandboxes
        AutoGarbageCollector.sweep(ttl_seconds=600)

        sandbox_id = f"sandbox_{target_node}_{uuid.uuid4().hex[:6]}"
        tested_commands: List[str] = []
        output_logs: List[Dict[str, Any]] = []

        if not patch_commands:
            return ShadowSandboxResult(
                sandbox_id=sandbox_id,
                cloned_node=target_node,
                commands_tested=[],
                all_passed=allow_empty,
                output_logs=[{"info": "No commands to execute in sandbox"}] if allow_empty else [{"error": "No candidate remediation commands provided for sandbox validation"}],
                error_message=None if allow_empty else "Candidate remediation plan contains no execution commands",
            )

        # -------------------------------------------------------------
        # 2. Setup Sandbox Replica (Mock mode or Live Containerlab mode)
        # -------------------------------------------------------------
        from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter

        is_mock_engine = isinstance(adapter, MockContainerlabAdapter)
        is_live_clab = isinstance(adapter, LiveContainerlabAdapter)
        sandbox_node_name = sandbox_id
        live_sandbox_container: Optional[str] = None
        live_temp_image: Optional[str] = None
        all_passed = True
        first_error: Optional[str] = None
        effective_quota = quota or ResourceQuota()

        try:
            if is_mock_engine:
                v_graph = adapter.mock_engine.graph
                orig_node = v_graph.nodes.get(target_node)
                if not orig_node:
                    return ShadowSandboxResult(
                        sandbox_id=sandbox_id,
                        cloned_node=target_node,
                        commands_tested=[],
                        all_passed=False,
                        output_logs=[{"error": f"Target node '{target_node}' not found in virtual network topology"}],
                        error_message=f"Target node '{target_node}' not found in virtual network topology",
                    )
                cloned_node = VirtualNode(
                    name=sandbox_node_name,
                    kind=orig_node.kind,
                    image=orig_node.image,
                )
                cloned_node.interfaces = copy.deepcopy(orig_node.interfaces)
                cloned_node.routes = copy.deepcopy(orig_node.routes)
                cloned_node.default_gateway = orig_node.default_gateway
                cloned_node.state = "running"
                v_graph.add_node(cloned_node)

            elif is_live_clab:
                try:
                    live_container = adapter._resolve_container_name(target_node)
                    live_sandbox_container = f"clab-sandbox-{sandbox_id}"
                    live_temp_image = f"temp-img-{sandbox_id}"
                    c_res = adapter.runner.run(
                        f"docker commit {live_container} {live_temp_image}",
                        sudo=True,
                        timeout=clone_timeout,
                    )
                    if c_res.exit_code != 0:
                        return ShadowSandboxResult(
                            sandbox_id=sandbox_id,
                            cloned_node=target_node,
                            commands_tested=[],
                            all_passed=False,
                            output_logs=[{"error": f"Docker commit failed: {c_res.stderr or c_res.stdout}"}],
                            error_message=f"Live sandbox container cloning failed for '{target_node}': {c_res.stderr or c_res.stdout}",
                        )
                    quota_flags = " ".join(effective_quota.to_docker_flags())
                    r_cmd = (
                        f"docker run -d --privileged --network none {quota_flags} "
                        f"--label netops.sandbox=true --label netops.sandbox.id={sandbox_id} "
                        f"--name {live_sandbox_container} {live_temp_image} "
                        f'sh -c "touch /tmp/initialized; if [ -f /usr/lib/frr/docker-start ]; then /usr/lib/frr/docker-start; fi; sleep infinity"'
                    )
                    r_res = adapter.runner.run(
                        r_cmd,
                        sudo=True,
                        timeout=clone_timeout,
                    )
                    if r_res.exit_code != 0:
                        return ShadowSandboxResult(
                            sandbox_id=sandbox_id,
                            cloned_node=target_node,
                            commands_tested=[],
                            all_passed=False,
                            output_logs=[{"error": f"Docker run failed: {r_res.stderr or r_res.stdout}"}],
                            error_message=f"Live sandbox container instantiation failed for '{target_node}': {r_res.stderr or r_res.stdout}",
                        )
                    time.sleep(1.5)
                    adapter._node_to_container[sandbox_node_name] = live_sandbox_container
                except Exception as exc:
                    return ShadowSandboxResult(
                        sandbox_id=sandbox_id,
                        cloned_node=target_node,
                        commands_tested=[],
                        all_passed=False,
                        output_logs=[{"error": f"Live sandbox exception: {exc}"}],
                        error_message=f"Live sandbox replica creation failed for '{target_node}': {exc}",
                    )

            # -------------------------------------------------------------
            # 3. Execute candidate patch commands in Sandbox Replica via AAL
            # -------------------------------------------------------------
            for idx, cmd in enumerate(patch_commands, start=1):
                cmd_step_tag = f"{step_tag}_sandbox_{idx}" if step_tag else f"sandbox_step_{idx}"
                tool_call = AALToolCall(
                    tool_name="sandbox_exec",
                    node_name=sandbox_node_name,
                    command=cmd,
                    step_tag=cmd_step_tag,
                    read_only=False,
                    timeout=timeout,
                )

                tested_commands.append(cmd)
                aal_resp = aal.execute(tool_call)

                log_entry = {
                    "command": cmd,
                    "step_tag": cmd_step_tag,
                    "success": aal_resp.success,
                    "is_blocked": aal_resp.is_blocked,
                    "exit_code": aal_resp.exit_code,
                    "parsed_json": aal_resp.parsed_json,
                    "error_message": aal_resp.error_message,
                }
                output_logs.append(log_entry)

                if not aal_resp.success or aal_resp.is_blocked:
                    all_passed = False
                    first_error = aal_resp.error_message or f"Command failed with exit code {aal_resp.exit_code}"
                    break

        finally:
            # -------------------------------------------------------------
            # 4. Teardown Sandbox Replica & Run Post-Validation GC
            # -------------------------------------------------------------
            if is_mock_engine and sandbox_node_name in adapter.mock_engine.graph.nodes:
                del adapter.mock_engine.graph.nodes[sandbox_node_name]
            elif is_live_clab:
                try:
                    if live_sandbox_container:
                        adapter.runner.run(f"docker rm -f {live_sandbox_container}", sudo=True, timeout=15)
                    if live_temp_image:
                        adapter.runner.run(f"docker rmi -f {live_temp_image}", sudo=True, timeout=15)
                    adapter._node_to_container.pop(sandbox_node_name, None)
                except Exception:
                    pass

            # Teardown Hook: Sweep any remaining orphaned artifacts
            AutoGarbageCollector.sweep(ttl_seconds=600)

        return ShadowSandboxResult(
            sandbox_id=sandbox_id,
            cloned_node=target_node,
            commands_tested=tested_commands,
            all_passed=all_passed,
            output_logs=output_logs,
            error_message=first_error,
        )

    @classmethod
    def run_preflight_verification(
        cls,
        node_name: Optional[str] = None,
        commands: Optional[List[str]] = None,
        target_node: Optional[str] = None,
        adapter: Optional[BaseNetworkLabAdapter] = None,
        aal: Optional[AgentAccessLayer] = None,
        quota: Optional[ResourceQuota] = None,
        step_tag: Optional[str] = None,
        timeout: int = 15,
        target_platform: Optional[str] = None,
        run_gc: bool = True,
        allow_empty: bool = False,
    ) -> PreflightSandboxPassReport:
        """Execute pre-flight verification in isolated Docker sandbox runtime or Mock fallback.

        Enforces:
        - Strict network isolation (--network none)
        - CPU, memory, process quotas (via ResourceQuota)
        - Ephemeral cleanup via context manager
        - Deterministic cryptographic pass signature
        - Automatic garbage collection sweep

        Args:
            node_name: Target node identifier (or use target_node).
            commands: List of candidate commands to test.
            target_node: Alternative parameter for node name.
            adapter: Lab adapter (LiveContainerlabAdapter or MockContainerlabAdapter).
            aal: AgentAccessLayer instance for safety checks.
            quota: ResourceQuota to enforce.
            step_tag: Monotonic step tracking tag.
            timeout: Command execution timeout.
            target_platform: Target OS (e.g. 'linux_iptables', 'cisco_acl').
            run_gc: Whether to run Auto-GC on start and teardown.
            allow_empty: Whether empty command list counts as pass.

        Returns:
            PreflightSandboxPassReport certifying pre-flight validation status.
        """
        effective_node = target_node or node_name or "default_node"
        effective_commands = list(commands) if commands is not None else []
        effective_quota = quota or ResourceQuota()
        sandbox_id = f"sandbox_preflight_{effective_node}_{uuid.uuid4().hex[:8]}"

        if run_gc:
            AutoGarbageCollector.sweep(ttl_seconds=600)

        # Handle empty command list
        if not effective_commands:
            return PreflightSandboxPassReport(
                sandbox_id=sandbox_id,
                target_node=effective_node,
                commands_executed=[],
                all_passed=allow_empty,
                exit_codes=[],
                execution_duration_sec=0.0,
                network_isolated=True,
                resource_quotas=effective_quota.to_dict(),
                target_platform=target_platform,
                error_message=None if allow_empty else "No candidate commands provided for preflight verification",
                output_logs=[{"info": "No commands executed"}] if allow_empty else [{"error": "Empty command list"}],
            )

        start_time = time.time()
        tested_commands: List[str] = []
        exit_codes: List[int] = []
        output_logs: List[Dict[str, Any]] = []
        all_passed = True
        first_error: Optional[str] = None

        # Instantiate runtime (Docker or Mock fallback)
        runtime = create_sandbox_runtime(
            target_node=effective_node,
            mode="auto",
            adapter=adapter,
            quota=effective_quota,
        )

        try:
            with runtime:
                for idx, cmd in enumerate(effective_commands, start=1):
                    current_step_tag = f"{step_tag}_step_{idx}" if step_tag else f"preflight_step_{idx}"

                    # 1. Check AAL safety whitelist if AAL is provided
                    if aal is not None:
                        is_safe, error_reason = aal.validate_command_safety(cmd, read_only=False)
                        if not is_safe:
                            tested_commands.append(cmd)
                            exit_codes.append(126)
                            all_passed = False
                            first_error = error_reason or "Command blocked by security policy"
                            output_logs.append({
                                "command": cmd,
                                "step_tag": current_step_tag,
                                "exit_code": 126,
                                "is_blocked": True,
                                "error_message": first_error,
                            })
                            break

                    # 2. Execute command inside isolated sandbox runtime
                    exec_res: SandboxExecutionResult = runtime.exec_command(cmd, timeout=timeout)
                    tested_commands.append(cmd)
                    exit_codes.append(exec_res.exit_code)
                    output_logs.append({
                        "command": cmd,
                        "step_tag": current_step_tag,
                        "exit_code": exec_res.exit_code,
                        "stdout": exec_res.stdout,
                        "stderr": exec_res.stderr,
                        "duration_sec": exec_res.duration_sec,
                        "timed_out": exec_res.timed_out,
                    })

                    if exec_res.exit_code != 0 or exec_res.timed_out:
                        all_passed = False
                        first_error = exec_res.stderr or f"Command failed with exit code {exec_res.exit_code}"
                        break
        finally:
            if run_gc:
                AutoGarbageCollector.sweep(ttl_seconds=600)

        total_duration = round(time.time() - start_time, 4)

        return PreflightSandboxPassReport(
            sandbox_id=sandbox_id,
            target_node=effective_node,
            commands_executed=tested_commands,
            all_passed=all_passed,
            exit_codes=exit_codes,
            execution_duration_sec=total_duration,
            network_isolated=True,
            resource_quotas=effective_quota.to_dict(),
            target_platform=target_platform,
            output_logs=output_logs,
            error_message=first_error,
        )
