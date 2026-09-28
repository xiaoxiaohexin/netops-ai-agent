"""Unit Tests for Shadow Sandbox Validation Mechanism.

Verifies:
1. Problematic node cloning into an isolated replica.
2. Candidate patch execution in sandbox replica before human approval.
3. Successful patch verification in sandbox replica.
4. Blocked or failing commands detected in sandbox without mutating live container.
5. Sandbox replica cleanup and teardown.
"""

from pathlib import Path
import pytest

from langgraph_netagent.models.operational import ShadowSandboxResult
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.sandbox import ShadowSandboxManager


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


class TestShadowSandbox:
    """Verify shadow sandbox isolation and pre-approval validation."""

    def test_safe_patch_passes_in_sandbox(self, deployed_mock_adapter, aal):
        patch_commands = [
            "vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'",
        ]
        result: ShadowSandboxResult = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=patch_commands,
            adapter=deployed_mock_adapter,
            aal=aal,
            step_tag="test_step_1",
        )
        assert result.all_passed is True
        assert result.cloned_node == "frr1"
        assert len(result.commands_tested) == 1
        assert result.error_message is None

    def test_destructive_patch_fails_in_sandbox(self, deployed_mock_adapter, aal):
        """A destructive command blocked by AAL fails in the sandbox replica."""
        patch_commands = [
            "rm -rf /etc/frr/*",
        ]
        result: ShadowSandboxResult = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=patch_commands,
            adapter=deployed_mock_adapter,
            aal=aal,
            step_tag="test_step_fail",
        )
        assert result.all_passed is False
        assert "SECURITY POLICY VIOLATION" in (result.error_message or "")

    def test_sandbox_teardown_cleans_replica(self, deployed_mock_adapter, aal):
        """Verify replica is removed from VirtualNetworkGraph after validation."""
        initial_nodes = set(deployed_mock_adapter.mock_engine.graph.nodes.keys())
        ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=["vtysh -c 'show ip route'"],
            adapter=deployed_mock_adapter,
            aal=aal,
        )
        final_nodes = set(deployed_mock_adapter.mock_engine.graph.nodes.keys())
        # No orphan replica nodes left
        assert initial_nodes == final_nodes
        assert not any(n.startswith("sandbox_") for n in final_nodes)

    def test_empty_patch_passes(self, deployed_mock_adapter, aal):
        result = ShadowSandboxManager.run_sandbox_validation(
            target_node="frr1",
            patch_commands=[],
            adapter=deployed_mock_adapter,
            aal=aal,
        )
        assert result.all_passed is True
