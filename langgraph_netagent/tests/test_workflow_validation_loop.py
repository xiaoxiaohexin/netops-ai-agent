"""End-to-End Automated Tests for Pre-Flight Validation Correction Loop.

Verifies that syntax, IP collision, or link topology errors injected during initial
topology generation are caught by `offline_validation`, routed back to `topology_generation`
with contextual error feedback, repaired by the LLM, validated, and successfully completed.
"""

import copy
from pathlib import Path
import pytest

from langgraph_netagent.llm import MockLLMProvider
from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.graph import build_network_agent_graph, run_network_agent_workflow
from langgraph_netagent.workflow.state import create_initial_state


class TestWorkflowValidationLoop:
    """Test suite for offline pre-flight validation detection and iterative error feedback repair."""

    def test_validation_loop_duplicate_ip_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Test detection and LLM repair of duplicate IP collision across nodes."""
        mock_llm.register_canned_response(sample_network_intent)

        # 1st generation: inject duplicate IP in IP allocations
        broken_pkg = sample_topology_package.model_copy(deep=True)
        broken_pkg.ip_allocations.append(
            IPAllocation(
                node_name="frr1",
                interface_name="eth2",
                ipv4_address="10.1.1.2/24",  # Same IP as pc1!
            )
        )
        mock_llm.register_canned_response(broken_pkg)

        # 2nd generation: clean topology package with resolved IPs
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_dup_ip",
            auto_approve=True,
        )

        initial = create_initial_state("Connect hosts with initial IP collision", max_retries=3)
        final_state = app.invoke(initial)

        # Verified that workflow recovered and completed
        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["validation_result"]["is_valid"] is True
        assert final_state["verification_results"]["all_passed"] is True

        # Verify that the LLM was called with the validation error feedback
        second_gen_prompt = mock_llm.invocations[2][-1].content
        assert "ATTENTION: Prior pre-flight validation failed" in second_gen_prompt
        assert "DUPLICATE_IP" in second_gen_prompt or "IP_COLLISION" in second_gen_prompt or "duplicate" in second_gen_prompt.lower()

    def test_validation_loop_invalid_node_name_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Test detection and repair of RFC 1123 non-compliant node names."""
        mock_llm.register_canned_response(sample_network_intent)

        # 1st generation: inject node name with illegal symbols
        broken_pkg = sample_topology_package.model_copy(deep=True)
        broken_pkg.topology.topology.nodes["bad_node@illegal!"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        mock_llm.register_canned_response(broken_pkg)

        # 2nd generation: clean valid package
        mock_llm.register_canned_response(sample_topology_package)

        export_dir = tmp_path / "clab_bad_name"
        final_state = run_network_agent_workflow(
            user_intent="Connect hosts with invalid node names",
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=export_dir,
            max_retries=3,
            auto_approve=True,
        )

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["validation_result"]["is_valid"] is True

        # Check logs recorded warning for the failed validation attempt
        val_warnings = [
            log for log in final_state["execution_logs"]
            if log["stage"] == "offline_validation" and log["level"] == "warning"
        ]
        assert len(val_warnings) == 1
        assert "retry 1/3" in val_warnings[0]["message"]

    def test_validation_loop_unknown_endpoint_node_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Test detection and repair of link referencing a non-existent phantom node."""
        mock_llm.register_canned_response(sample_network_intent)

        # 1st generation: link references unknown node 'phantom_router'
        broken_pkg = sample_topology_package.model_copy(deep=True)
        broken_pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["pc1:eth2", "phantom_router:eth1"])
        )
        mock_llm.register_canned_response(broken_pkg)

        # 2nd generation: clean valid package
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_phantom_node",
            auto_approve=True,
        )

        initial = create_initial_state("Connect hosts with unknown link node", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        assert final_state["retry_count"] == 1
        assert final_state["validation_result"]["is_valid"] is True

    def test_validation_loop_multi_iteration_recovery(
        self,
        mock_llm: MockLLMProvider,
        mock_adapter: MockContainerlabAdapter,
        tmp_path: Path,
        sample_network_intent: NetworkIntent,
        sample_topology_package: FullTopologyPackage,
    ):
        """Test multi-round recovery: 1st fails duplicate IP, 2nd fails bad node name, 3rd succeeds."""
        mock_llm.register_canned_response(sample_network_intent)

        # Round 1: duplicate IP
        pkg_fail_1 = sample_topology_package.model_copy(deep=True)
        pkg_fail_1.ip_allocations.append(
            IPAllocation(node_name="frr1", interface_name="eth2", ipv4_address="10.1.1.2/24")
        )
        mock_llm.register_canned_response(pkg_fail_1)

        # Round 2: bad node name
        pkg_fail_2 = sample_topology_package.model_copy(deep=True)
        pkg_fail_2.topology.topology.nodes["bad_node#2"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        mock_llm.register_canned_response(pkg_fail_2)

        # Round 3: clean topology
        mock_llm.register_canned_response(sample_topology_package)

        app = build_network_agent_graph(
            llm_provider=mock_llm,
            lab_adapter=mock_adapter,
            export_dir=tmp_path / "clab_multi_round",
            auto_approve=True,
        )

        initial = create_initial_state("Multi-round validation correction test", max_retries=3)
        final_state = app.invoke(initial)

        assert final_state["status"] == "verified"
        # Consumed 2 validation retries
        assert final_state["retry_count"] == 2
        assert final_state["validation_result"]["is_valid"] is True
        assert final_state["verification_results"]["all_passed"] is True
