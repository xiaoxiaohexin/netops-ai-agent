"""Unit and Integration Tests for CLI Entrypoint (`netagent`).

Verifies command-line argument parsing, mock and live execution flags,
topo-only generation, output directory persistence, error handling, and exit codes.
"""

from pathlib import Path
import subprocess
import sys
from unittest.mock import patch
import pytest

from langgraph_netagent import __version__
from langgraph_netagent.cli import build_arg_parser, create_default_mock_llm, run_cli
from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.topology import FullTopologyPackage
from langgraph_netagent.tools.fault_injector import FaultRule, FaultType
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter


class TestCLIOptionsAndParser:
    """Test CLI argument parsing and default configuration."""

    def test_parser_defaults(self):
        parser = build_arg_parser()
        args = parser.parse_args([])
        assert args.mode == "auto"
        assert args.max_retries == 3
        assert args.auto_approve is True
        assert args.topo_only is False
        assert args.provider == "mock"
        assert args.output_dir == "./clab_output"
        assert "Connect pc1 and pc2" in args.intent

    def test_parser_custom_flags(self):
        parser = build_arg_parser()
        cmd = [
            "--intent", "Custom intent string",
            "--mode", "mock",
            "--max-retries", "5",
            "--no-auto-approve",
            "--output-dir", "./custom_out",
            "--topo-only",
            "--provider", "mock",
            "--verbose",
        ]
        args = parser.parse_args(cmd)
        assert args.intent == "Custom intent string"
        assert args.mode == "mock"
        assert args.max_retries == 5
        assert args.auto_approve is False
        assert args.output_dir == "./custom_out"
        assert args.topo_only is True
        assert args.provider == "mock"
        assert args.verbose is True

    def test_default_mock_llm_factory(self):
        provider = create_default_mock_llm("Connect host1 and host2 via router1")
        assert provider is not None
        # Verify it generates NetworkIntent and FullTopologyPackage cleanly
        intent = provider.generate_structured([], NetworkIntent)
        assert isinstance(intent, NetworkIntent)
        assert len(intent.nodes) >= 2

        pkg = provider.generate_structured([], FullTopologyPackage)
        assert isinstance(pkg, FullTopologyPackage)
        assert len(pkg.topology.topology.nodes) >= 2


class TestCLIExecutionPaths:
    """Test execution paths through run_cli."""

    def test_run_cli_topo_only_success(self, tmp_path: Path):
        ret = run_cli([
            "--mode", "mock",
            "--topo-only",
            "--output-dir", str(tmp_path),
            "--intent", "Connect pc1 and pc2 via frr1",
        ])
        assert ret == 0

        # Verify exported files exist on disk
        exported_files = list(tmp_path.rglob("*"))
        assert any(p.name.endswith(".clab.yml") for p in exported_files)
        assert any(p.name == "setup.sh" for p in exported_files)
        assert any(p.name == "frr.conf" for p in exported_files)

    def test_run_cli_full_workflow_happy_path(self, tmp_path: Path):
        ret = run_cli([
            "--mode", "mock",
            "--output-dir", str(tmp_path),
            "--intent", "Connect pc1 and pc2 via frr1 with static routing",
            "--max-retries", "2",
        ])
        assert ret == 0

        # Check artifacts
        topo_file = next(tmp_path.glob("*.clab.yml"), None)
        assert topo_file is not None
        content = topo_file.read_text(encoding="utf-8")
        assert "topology:" in content
        assert "pc1" in content
        assert "frr1" in content

    def test_run_cli_circuit_breaker_exit_code(self, tmp_path: Path):
        """When retries are exhausted, run_cli must return exit code 2."""
        # Patch MockContainerlabAdapter to inject permanent deployment failure
        original_init = MockContainerlabAdapter.__init__

        def broken_init(self, *args, **kwargs):
            original_init(self, *args, **kwargs)
            self.fault_injector.add_rule(
                FaultRule(
                    fault_type=FaultType.DEPLOY_FAILURE,
                    target_node=None,
                    cleared_on_remediation=False,
                )
            )

        with patch.object(MockContainerlabAdapter, "__init__", broken_init):
            ret = run_cli([
                "--mode", "mock",
                "--output-dir", str(tmp_path),
                "--max-retries", "1",
            ])
            assert ret == 2

    def test_run_cli_invalid_provider(self, tmp_path: Path):
        ret = run_cli([
            "--provider", "invalid_provider",
            "--output-dir", str(tmp_path),
        ])
        assert ret != 0

    def test_run_cli_rejection_exit_code(self, tmp_path: Path):
        """When auto-approval is disabled and operator rejects, returns 1."""
        ret = run_cli([
            "--mode", "mock",
            "--no-auto-approve",
            "--output-dir", str(tmp_path),
        ])
        # In non-interactive mode without approval, status is rejected or pending, returns 1
        assert ret == 1


class TestCLIProcessInvocation:
    """Test process-level execution using subprocess."""

    def test_python_module_cli_help(self):
        res = subprocess.run(
            [sys.executable, "-m", "langgraph_netagent.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0
        assert "LangGraph NetOps Autonomous Agent" in res.stdout
        assert "--topo-only" in res.stdout

    def test_python_module_cli_version(self):
        res = subprocess.run(
            [sys.executable, "-m", "langgraph_netagent.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert res.returncode == 0
        assert __version__ in res.stdout

    def test_python_module_cli_mock_topo_only(self, tmp_path: Path):
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "langgraph_netagent.cli",
                "--mode", "mock",
                "--topo-only",
                "--output-dir", str(tmp_path),
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert res.returncode == 0
        assert "TOPO-ONLY GENERATION COMPLETED" in res.stdout
