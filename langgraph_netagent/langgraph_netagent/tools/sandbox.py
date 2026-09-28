"""Shadow Sandbox Validation Mechanism for LangGraph NetAgent.

Clones problematic network nodes into an isolated shadow sandbox replica (or
simulated replica in mock mode) to execute candidate configuration patches
and remediation commands before they reach the human approval stage.
"""

from __future__ import annotations

import copy
import uuid
from typing import Any, Dict, List, Optional

from langgraph_netagent.models.operational import AALToolCall, ShadowSandboxResult
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter, CommandResult
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter, VirtualNode


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
    ) -> ShadowSandboxResult:
        """Clone target node into an isolated sandbox replica and execute candidate patch.

        Args:
            target_node: Name of live node to clone.
            patch_commands: Candidate configuration or remediation commands to test.
            adapter: Lab adapter (live or mock).
            aal: AgentAccessLayer instance for safety checks and normalized execution.
            step_tag: Iteration step tag for deterministic tracking.
            timeout: Command timeout.
            clone_timeout: Docker commit and container instantiation timeout.
            allow_empty: Whether an empty list of patch commands is considered passing.

        Returns:
            ShadowSandboxResult with detailed test logs and pass/fail verdict.
        """
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
        # 1. Setup Sandbox Replica (Mock mode or Live Containerlab mode)
        # -------------------------------------------------------------
        from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter

        is_mock_engine = isinstance(adapter, MockContainerlabAdapter)
        is_live_clab = isinstance(adapter, LiveContainerlabAdapter)
        sandbox_node_name = sandbox_id
        live_sandbox_container: Optional[str] = None
        live_temp_image: Optional[str] = None
        all_passed = True
        first_error: Optional[str] = None

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
                    r_cmd = f'docker run -d --privileged --name {live_sandbox_container} {live_temp_image} sh -c "touch /tmp/initialized; if [ -f /usr/lib/frr/docker-start ]; then /usr/lib/frr/docker-start; fi; sleep infinity"'
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
                    import time
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
            # 2. Execute candidate patch commands in Sandbox Replica via AAL
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
            # 3. Teardown Sandbox Replica
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

        return ShadowSandboxResult(
            sandbox_id=sandbox_id,
            cloned_node=target_node,
            commands_tested=tested_commands,
            all_passed=all_passed,
            output_logs=output_logs,
            error_message=first_error,
        )
