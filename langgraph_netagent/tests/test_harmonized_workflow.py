"""Milestone 5: Workflow Harmonization & Zero Regression Verification (Day-1/2/3) Tests.

Validates:
1. End-to-end integration test of the complete Day-1 -> Day-2 -> Day-3 pipeline:
   - Day-1: Baseline ingestion, asset inventory discovery, and vendor knowledge dual-retrieval index build.
   - Day-2: Telemetry extraction (5-tuple parsing & anomaly classification), Stage 1 read-only context enrichment via AAL (full autonomy), Stage 2 canonical intent generation with monotonic step_tag (bounded autonomy), circuit breaker loop prevention.
   - Day-3: Ephemeral isolated Docker sandbox validation emitting certified PreflightSandboxPassReport with SHA-256 signature, bounded autonomy HITL approval gate, live deployment, post-change re-verification probing, and automated reverse rollback on failure.
2. Non-breaking deprecation warnings for legacy Day-2 nodes without breaking execution:
   - create_day2_nodes, build_day2_graph, run_day2_workflow, create_day2_initial_state, and edge routing functions emit DeprecationWarning.
   - 100% backward compatibility preserved for existing code and tests.
3. Multi-day phase transitions and boundary enforcement:
   - Lifecycle state progression (day1 -> day2 -> day3).
   - Invariant verification and illegal phase shortcut prevention.
4. CLI options integration:
   - Execution with --harmonized, --watch, and --auto-approve flags.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from langgraph_netagent.cli import run_cli
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.intent import CanonicalIntent, IntentAction, TargetPlatform
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan, RollbackStep
from langgraph_netagent.models.sandbox import PreflightSandboxPassReport
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import CommandResult
from langgraph_netagent.workflow.day2_edges import (
    route_after_approval as day2_route_after_approval,
    route_after_dry_run as day2_route_after_dry_run,
    route_after_probe as day2_route_after_probe,
    route_after_re_verify as day2_route_after_re_verify,
)
from langgraph_netagent.workflow.day2_graph import build_day2_graph, run_day2_workflow
from langgraph_netagent.workflow.day2_nodes import create_day2_nodes
from langgraph_netagent.workflow.day2_state import create_day2_initial_state
from langgraph_netagent.workflow.harmonized_graph import (
    HarmonizedGraph,
    HarmonizedOperationalGraph,
    HarmonizedOpsState,
    HarmonizedState,
    OperationalPhase,
    build_harmonized_graph,
    create_harmonized_initial_state,
    create_harmonized_nodes,
    run_harmonized_workflow,
    validate_phase_transition,
    verify_phase_boundaries,
)
from tests.test_operational_workflow import MockOperationalLLMProvider, MockUMLAdapter


# ==============================================================================
# 1. End-to-End Three-Phase Workflow Integration Tests (Day-1 -> Day-2 -> Day-3)
# ==============================================================================

class TestHarmonizedWorkflowE2E:
    """Validate end-to-end multi-day lifecycle from discovery through healing."""

    def test_e2e_full_lifecycle_self_healing_success(self):
        """End-to-end integration test validating the complete Day-1 -> Day-2 -> Day-3 pipeline:

        anomaly detection -> canonical intent generation -> sandbox validation ->
        HITL approval -> live execution -> post-change verification.
        """
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=False)
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            max_retries=3,
            auto_approve=True,
        )

        # 1. Day-1 Assertions: Baseline & Dual-Retrieval Index
        assert result.get("baseline") is not None
        assert result.get("inventory_pool") is not None
        inv = result["inventory_pool"]
        assert "frr1" in inv.get("assets", [])
        assert result.get("vendor_knowledge_indexed") is True
        assert result.get("dual_retrieval_index_built") is True

        # 2. Day-2 Assertions: Anomaly & 2-Stage Diagnosis
        assert result.get("anomaly_classification") is not None
        assert result.get("current_step_tag") is not None
        assert "diag_iter_" in result["current_step_tag"]
        assert result.get("diagnostic_report") is not None
        assert result.get("remediation_plan") is not None

        # 3. Day-3 Assertions: Sandbox Validation, HITL Gate & Live Deployment
        assert result.get("sandbox_result") is not None
        assert result.get("sandbox_passed") is True
        assert result.get("preflight_report") is not None
        report_data = result["preflight_report"]
        if isinstance(report_data, dict):
            report_obj = PreflightSandboxPassReport.model_validate(report_data)
        else:
            report_obj = report_data
        assert report_obj.verify_clean_pass() is True
        assert len(report_obj.pass_signature) >= 32  # SHA-256 signature prefix
        assert report_obj.network_isolated is True

        assert result.get("human_approved") is True
        assert result.get("patch_result") is not None
        assert adapter.patched is True
        assert result.get("re_verify_results") is not None

        # 4. Final Lifecycle Status
        assert result["status"] == "fixed"
        assert result["operational_phase"] == "day3"
        history = result.get("phase_history", [])
        assert "day1" in history
        assert "day2" in history
        assert "day3" in history

    def test_e2e_healthy_network_path(self):
        """When network is healthy, workflow stays in Day-1/Day-2 and routes to end_healthy."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            auto_approve=True,
        )

        assert result["status"] == "healthy"
        assert result["operational_phase"] == "day2"
        assert result.get("vendor_knowledge_indexed") is True
        # Day-3 should never be entered on a healthy network
        assert "day3" not in result.get("phase_history", [])
        assert adapter.patched is False

    def test_e2e_hitl_rejection_halts_without_live_mutation(self):
        """Operator rejection at HITL gate halts at end_rejected without mutating live node."""
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=False)
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        init_state = create_harmonized_initial_state(max_retries=3, auto_approve=False)
        init_state["human_approved"] = False  # Explicit rejection

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            auto_approve=False,
            initial_state=init_state,
        )

        assert result["status"] == "rejected"
        assert result["operational_phase"] == "day3"
        assert result.get("sandbox_passed") is True  # Sandbox validated candidate plan
        assert adapter.patched is False  # Live node was NEVER touched!

    def test_e2e_circuit_breaker_trips_on_retry_exhaustion(self):
        """Circuit breaker halts workflow deterministically when retry count reaches max_retries."""
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=False)
        # Lab stays un-fixed after patch
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=False)

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            max_retries=2,
            auto_approve=True,
        )

        assert result["status"] == "circuit_broken"
        assert result.get("circuit_breaker_tripped") is True
        assert result.get("retry_count", 0) >= 2

    def test_e2e_re_verification_failure_triggers_automated_rollback(self):
        """Failure during post-change verification triggers automated reverse rollback via AAL."""
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=False)
        # Patch does not fix the issue, causing re-verification failure and triggering rollback
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=False)

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            max_retries=1,
            auto_approve=True,
        )

        # Confirm rollback was triggered during re-verification failure
        assert result.get("rollback_executed") is True
        assert len(result.get("rollback_results", [])) > 0
        assert result["status"] == "circuit_broken"

    def test_e2e_failing_sandbox_blocks_hitl_and_retries(self):
        """Sandbox trial failure blocks progression to HITL gate and forces retry loop."""
        # LLM emits an unsafe / blocked command
        llm = MockOperationalLLMProvider(target_node="frr1", failing_patch=True)
        adapter = MockUMLAdapter(healthy=False, fix_after_patch=True)

        result = run_harmonized_workflow(
            llm_provider=llm,
            lab_adapter=adapter,
            lab_name="uml-lab",
            max_retries=1,
            auto_approve=True,
        )

        # Candidate commands failed pre-flight verification, so live patch was blocked
        assert adapter.patched is False
        assert result["status"] == "circuit_broken"


# ==============================================================================
# 2. Legacy Day-2 Nodes Deprecation Verification
# ==============================================================================

class TestLegacyDay2Deprecation:
    """Validate non-breaking deprecation warnings on legacy Day-2 modules."""

    def test_create_day2_nodes_emits_deprecation_warning(self):
        """create_day2_nodes must emit DeprecationWarning while retaining 100% functionality."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            nodes = create_day2_nodes(
                llm_provider=llm,
                lab_adapter=adapter,
                auto_approve=True,
            )

        assert any(
            issubclass(w.category, DeprecationWarning)
            and "Day2 linear nodes are deprecated; please use harmonized operational workflow" in str(w.message)
            for w in recorded
        )
        assert len(nodes) == 13
        assert "read_baseline" in nodes
        assert "probe_matrix" in nodes

    def test_build_day2_graph_emits_deprecation_warning(self):
        """build_day2_graph must emit DeprecationWarning and compile cleanly."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            graph = build_day2_graph(
                llm_provider=llm,
                lab_adapter=adapter,
                auto_approve=True,
            )

        assert any(
            issubclass(w.category, DeprecationWarning)
            and "Day2 linear nodes are deprecated; please use harmonized operational workflow" in str(w.message)
            for w in recorded
        )
        assert graph is not None

    def test_run_day2_workflow_emits_deprecation_warning(self):
        """run_day2_workflow must emit DeprecationWarning and execute correctly."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            result = run_day2_workflow(
                llm_provider=llm,
                lab_adapter=adapter,
                auto_approve=True,
            )

        assert any(
            issubclass(w.category, DeprecationWarning)
            and "Day2 linear nodes are deprecated; please use harmonized operational workflow" in str(w.message)
            for w in recorded
        )
        assert result["status"] == "healthy"

    def test_create_day2_initial_state_emits_deprecation_warning(self):
        """create_day2_initial_state must emit DeprecationWarning and return valid state."""
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            state = create_day2_initial_state(max_retries=3, auto_approve=True)

        assert any(
            issubclass(w.category, DeprecationWarning)
            and "Day2 linear nodes are deprecated; please use harmonized operational workflow" in str(w.message)
            for w in recorded
        )
        assert state["status"] == "initialized"
        assert state["human_approved"] is True

    def test_day2_edges_emit_deprecation_warnings(self):
        """All legacy Day-2 routing functions must emit DeprecationWarning."""
        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always")
            state = create_day2_initial_state(max_retries=3, auto_approve=True)
            state["probe_results"] = {"all_passed": True}
            r_probe = day2_route_after_probe(state)
            state["dry_run_passed"] = True
            r_dry = day2_route_after_dry_run(state)
            r_app = day2_route_after_approval(state)
            state["re_verify_results"] = {"all_passed": True}
            r_rev = day2_route_after_re_verify(state)

        assert r_probe == "end_healthy"
        assert r_dry == "human_approval"
        assert r_app == "hot_patch"
        assert r_rev == "end_fixed"
        dep_warnings = [
            w for w in recorded
            if issubclass(w.category, DeprecationWarning)
            and "Day2 linear nodes are deprecated" in str(w.message)
        ]
        assert len(dep_warnings) >= 4


# ==============================================================================
# 3. Multi-Day Phase Transitions and Boundary Enforcement
# ==============================================================================

class TestPhaseTransitionsAndBoundaries:
    """Validate lifecycle transitions and boundary invariants."""

    def test_phase_transition_validation(self):
        """Validate allowable and forbidden phase transitions."""
        assert validate_phase_transition("day1", "day2") is True
        assert validate_phase_transition("day2", "day3") is True
        assert validate_phase_transition("day3", "day2") is True  # retry loop
        assert validate_phase_transition("day2", "circuit_breaker") is True
        assert validate_phase_transition("day3", "end_fixed") is True

        # Illegal direct jump: Day-1 cannot skip Day-2 to jump directly to Day-3
        assert validate_phase_transition("day1", "day3") is False

    def test_verify_phase_boundaries_clean_state(self):
        """Clean fully-healed state must report 0 boundary violations."""
        state = {
            "operational_phase": "day3",
            "phase_history": ["day1", "day2", "day3"],
            "preflight_report": {"all_passed": True},
            "sandbox_result": {"all_passed": True},
            "inventory_pool": {"assets": ["pc1", "frr1"]},
        }
        report = verify_phase_boundaries(state)
        assert report["valid"] is True
        assert len(report["violations"]) == 0

    def test_verify_phase_boundaries_detects_violations(self):
        """State with missing phases or missing preflight report must flag violations."""
        bad_state = {
            "operational_phase": "day3",
            "phase_history": ["day3"],  # Skipped day1 & day2
            "preflight_report": None,
            "sandbox_result": None,
        }
        report = verify_phase_boundaries(bad_state)
        assert report["valid"] is False
        assert len(report["violations"]) >= 2
        assert any("Day-1 and Day-2" in v for v in report["violations"])
        assert any("sandbox pass report" in v for v in report["violations"])

    def test_day1_dual_retrieval_index_built_on_baseline(self):
        """Day-1 baseline ingestion must build vendor dual-retrieval index."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)
        nodes = create_harmonized_nodes(llm_provider=llm, lab_adapter=adapter)

        state = create_harmonized_initial_state()
        res = nodes["baseline_ingestion"](state)

        assert res["operational_phase"] == "day1"
        assert res["vendor_knowledge_indexed"] is True
        assert res["dual_retrieval_index_built"] is True
        assert "day1" in res["phase_history"]
        assert len(res["inventory_pool"]["assets"]) >= 2

    def test_harmonized_graph_class_facade(self):
        """HarmonizedOperationalGraph and HarmonizedGraph provide class-level build and run APIs."""
        llm = MockOperationalLLMProvider()
        adapter = MockUMLAdapter(healthy=True)

        graph = HarmonizedOperationalGraph.build(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=True,
        )
        assert graph is not None

        result = HarmonizedGraph.run(
            llm_provider=llm,
            lab_adapter=adapter,
            auto_approve=True,
        )
        assert result["status"] == "healthy"
        assert result["operational_phase"] == "day2"


# ==============================================================================
# 4. CLI Harmonized Option Integration Tests
# ==============================================================================

class TestCLIHarmonizedIntegration:
    """Validate CLI execution with --harmonized flag."""

    def test_cli_runs_harmonized_workflow_success(self, tmp_path: Path):
        """netagent --harmonized --mode mock runs harmonized workflow to completion."""
        ret = run_cli([
            "--mode", "mock",
            "--harmonized",
            "--output-dir", str(tmp_path),
            "--intent", "Connect pc1 and pc2 via frr1 with static routing",
            "--max-retries", "2",
        ])
        assert ret == 0

    def test_cli_runs_harmonized_watch_mode(self, tmp_path: Path):
        """netagent --harmonized --watch --max-watch-cycles 1 runs watch cycle cleanly."""
        ret = run_cli([
            "--mode", "mock",
            "--harmonized",
            "--watch",
            "--watch-interval", "0.001",
            "--max-watch-cycles", "1",
            "--output-dir", str(tmp_path),
        ])
        assert ret == 0

    def test_cli_harmonized_no_auto_approve_rejection(self, tmp_path: Path):
        """netagent --harmonized --no-auto-approve exits with code 1 in non-interactive mode."""
        ret = run_cli([
            "--mode", "mock",
            "--harmonized",
            "--no-auto-approve",
            "--output-dir", str(tmp_path),
        ])
        assert ret == 1
