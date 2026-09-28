"""Unit and Integration Tests for CLI Continuous Monitoring Watch Loop (R1 / Milestone 4).

Validates:
1. CLI argument parsing for `--watch`, `-w`, `--watch-interval`, `--max-watch-cycles`.
2. Execution of `run_cli` with `--watch` and `--max-watch-cycles` exiting cleanly with code 0.
3. Graceful handling of `KeyboardInterrupt` (Ctrl+C) exiting with code 0.
4. Terminal handling of circuit breaker tripping with exit code 2.
5. Rejection handling when human approval is required but not granted with exit code 1.
6. Memory-safe log pruning when execution trace logs exceed 100 entries.
"""

from pathlib import Path
from unittest.mock import patch
import pytest

from langgraph_netagent.cli import build_arg_parser, run_cli
from langgraph_netagent.workflow.operational_state import create_operational_initial_state


# ---------------------------------------------------------------------------
# Tests: 1. CLI Argument Parsing
# ---------------------------------------------------------------------------

def test_cli_parser_watch_defaults():
    """Verify default values for watch CLI arguments."""
    parser = build_arg_parser()
    args = parser.parse_args([])
    assert args.watch is False
    assert args.watch_interval == 5.0
    assert args.max_watch_cycles is None


def test_cli_parser_watch_custom_flags():
    """Verify custom flags for continuous monitoring."""
    parser = build_arg_parser()
    cmd = ["--watch", "--watch-interval", "2.5", "--max-watch-cycles", "10"]
    args = parser.parse_args(cmd)
    assert args.watch is True
    assert args.watch_interval == 2.5
    assert args.max_watch_cycles == 10


def test_cli_parser_watch_short_flag():
    """Verify -w short flag activates watch mode."""
    parser = build_arg_parser()
    args = parser.parse_args(["-w", "--watch-interval", "0.5"])
    assert args.watch is True
    assert args.watch_interval == 0.5


# ---------------------------------------------------------------------------
# Tests: 2. CLI Watch Loop Execution with Max Cycles
# ---------------------------------------------------------------------------

def test_run_cli_watch_mode_max_cycles_success(tmp_path: Path):
    """Verify run_cli with --watch and --max-watch-cycles=2 executes and returns exit code 0."""
    ret = run_cli([
        "--mode", "mock",
        "--watch",
        "--watch-interval", "0.001",
        "--max-watch-cycles", "2",
        "--output-dir", str(tmp_path),
    ])
    assert ret == 0


# ---------------------------------------------------------------------------
# Tests: 3. Graceful KeyboardInterrupt (Ctrl+C) Termination
# ---------------------------------------------------------------------------

def test_run_cli_watch_mode_keyboard_interrupt(tmp_path: Path, capsys):
    """Verify KeyboardInterrupt is caught cleanly and exits with return code 0."""
    # Simulate operator pressing Ctrl+C during watch interval sleep
    with patch("time.sleep", side_effect=KeyboardInterrupt):
        ret = run_cli([
            "--mode", "mock",
            "--watch",
            "--watch-interval", "10.0",
            "--output-dir", str(tmp_path),
        ])
        assert ret == 0

    captured = capsys.readouterr()
    assert "[WATCH] Gracefully terminated by operator (Ctrl+C)" in captured.out


# ---------------------------------------------------------------------------
# Tests: 4. Circuit Breaker in Watch Loop
# ---------------------------------------------------------------------------

def test_run_cli_watch_mode_circuit_breaker(tmp_path: Path):
    """Verify circuit breaker tripped in watch loop exits with code 2."""
    broken_state = create_operational_initial_state()
    broken_state["status"] = "circuit_broken"
    broken_state["circuit_breaker_tripped"] = True
    broken_state["error_message"] = "Test circuit breaker limit reached"

    with patch(
        "langgraph_netagent.workflow.operational_graph.run_operational_workflow",
        return_value=broken_state,
    ):
        ret = run_cli([
            "--mode", "mock",
            "--watch",
            "--watch-interval", "0.001",
            "--max-watch-cycles", "3",
            "--output-dir", str(tmp_path),
        ])
        assert ret == 2


# ---------------------------------------------------------------------------
# Tests: 5. Rejection in Watch Loop
# ---------------------------------------------------------------------------

def test_run_cli_watch_mode_rejected_exit_code(tmp_path: Path):
    """Verify unapproved non-interactive watch run exits with code 1."""
    ret = run_cli([
        "--mode", "mock",
        "--watch",
        "--no-auto-approve",
        "--output-dir", str(tmp_path),
    ])
    assert ret == 1


# ---------------------------------------------------------------------------
# Tests: 6. Execution Logs Pruning in Extended Watch Loop
# ---------------------------------------------------------------------------

def test_run_cli_watch_mode_log_pruning(tmp_path: Path):
    """Verify execution_logs exceeding 100 entries are pruned to latest 50."""
    # State with 120 execution logs
    huge_state = create_operational_initial_state()
    huge_state["status"] = "healthy"
    huge_state["execution_logs"] = [
        {"stage": "test", "message": f"Log {i}", "level": "info", "timestamp": "2026-09-27T00:00:00Z"}
        for i in range(120)
    ]

    with patch(
        "langgraph_netagent.workflow.operational_graph.run_operational_workflow",
        return_value=huge_state,
    ):
        ret = run_cli([
            "--mode", "mock",
            "--watch",
            "--watch-interval", "0.001",
            "--max-watch-cycles", "1",
            "--output-dir", str(tmp_path),
        ])
        assert ret == 0
        # After run_cli pruning, huge_state["execution_logs"] must be truncated to 50
        assert len(huge_state["execution_logs"]) == 50
        assert huge_state["execution_logs"][-1]["message"] == "Log 119"
