"""Unit tests for EnvironmentDetector, Capabilities, and SubprocessRunner."""

from pathlib import Path
import subprocess
import pytest

from langgraph_netagent.tools import (
    EnvironmentCapabilities,
    EnvironmentDetector,
    ExecutionMode,
    SubprocessRunner,
    strip_ansi_codes,
    windows_to_wsl_path,
    wsl_to_windows_path,
)


class TestEnvironmentDetector:
    """Test suite for environment detection and capability probing."""

    def test_forced_mock_mode_argument(self) -> None:
        detector = EnvironmentDetector()
        caps = detector.detect(forced_mode="mock")
        assert caps.resolved_mode == ExecutionMode.MOCK
        assert "Forced to MOCK" in caps.reason

        caps_enum = detector.detect(forced_mode=ExecutionMode.MOCK)
        assert caps_enum.resolved_mode == ExecutionMode.MOCK

    def test_forced_mock_mode_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NETAGENT_MODE", "mock")
        detector = EnvironmentDetector()
        caps = detector.detect()
        assert caps.resolved_mode == ExecutionMode.MOCK
        assert "Forced to MOCK" in caps.reason

    def test_containerlab_mode_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("NETAGENT_MODE", raising=False)
        monkeypatch.setenv("CONTAINERLAB_MODE", "mock")
        detector = EnvironmentDetector()
        caps = detector.detect()
        assert caps.resolved_mode == ExecutionMode.MOCK

    def test_forced_live_strict_raises_when_missing_deps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (False, False))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: False)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: False)

        with pytest.raises(RuntimeError, match="Enforced LIVE mode but prerequisites missing"):
            detector.detect(forced_mode=ExecutionMode.LIVE, strict=True)

    def test_forced_live_non_strict_returns_live(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (False, False))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: False)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: False)

        caps = detector.detect(forced_mode=ExecutionMode.LIVE, strict=False)
        assert caps.resolved_mode == ExecutionMode.LIVE
        assert "Enforced LIVE mode but prerequisites missing" in caps.reason

    def test_auto_mode_resolves_mock_when_clab_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (True, True))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: False)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: True)

        caps = detector.detect(forced_mode="auto")
        assert caps.resolved_mode == ExecutionMode.MOCK
        assert "Containerlab ('clab') binary not found" in caps.reason

    def test_auto_mode_resolves_mock_when_docker_unresponsive(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (True, False))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: True)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: True)

        caps = detector.detect(forced_mode="auto")
        assert caps.resolved_mode == ExecutionMode.MOCK
        assert "Docker daemon not running" in caps.reason

    def test_auto_mode_resolves_mock_when_no_root(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (True, True))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: True)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: False)

        caps = detector.detect(forced_mode="auto")
        assert caps.resolved_mode == ExecutionMode.MOCK
        assert "Root or passwordless sudo privilege not available" in caps.reason

    def test_auto_mode_resolves_live_when_all_satisfied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        detector = EnvironmentDetector()
        monkeypatch.setattr(detector, "_probe_docker", lambda **kw: (True, True))
        monkeypatch.setattr(detector, "_probe_clab", lambda **kw: True)
        monkeypatch.setattr(detector, "_probe_root", lambda **kw: True)

        caps = detector.detect(forced_mode="auto")
        assert caps.resolved_mode == ExecutionMode.LIVE
        assert "Full Containerlab, Docker, and root capabilities detected" in caps.reason


class TestPathConversionAndRunner:
    """Test suite for path conversion, ANSI stripper, and SubprocessRunner."""

    def test_windows_to_wsl_path(self) -> None:
        assert windows_to_wsl_path("E:\\Containerlab\\lab.clab.yml") == "/mnt/e/Containerlab/lab.clab.yml"
        assert windows_to_wsl_path("C:/Users/zbr/repo/test.sh") == "/mnt/c/Users/zbr/repo/test.sh"
        assert windows_to_wsl_path("d:\\foo\\bar\\baz") == "/mnt/d/foo/bar/baz"
        # Linux paths remain untouched
        assert windows_to_wsl_path("/tmp/lab.clab.yml") == "/tmp/lab.clab.yml"

    def test_wsl_to_windows_path(self) -> None:
        assert wsl_to_windows_path("/mnt/e/Containerlab/lab.clab.yml") == "E:\\Containerlab\\lab.clab.yml"
        assert wsl_to_windows_path("/mnt/c/Users/repo") == "C:\\Users\\repo"
        assert wsl_to_windows_path("E:\\already\\windows") == "E:\\already\\windows"

    def test_strip_ansi_codes(self) -> None:
        colored = "\x1b[31mError:\x1b[0m Failed to connect"
        assert strip_ansi_codes(colored) == "Error: Failed to connect"

    def test_runner_timeout_expired(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = SubprocessRunner(use_wsl_bridge=False)

        def mock_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd="test", timeout=2)

        monkeypatch.setattr(subprocess, "run", mock_run)
        res = runner.run(command="sleep 10", timeout=2)
        assert res.exit_code == -1
        assert "timed out after 2s" in res.stderr
        assert not res.success

    def test_runner_exception_handling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        runner = SubprocessRunner(use_wsl_bridge=False)

        def mock_run(*args, **kwargs):
            raise OSError("Command not found")

        monkeypatch.setattr(subprocess, "run", mock_run)
        res = runner.run(command="nonexistent_command")
        assert res.exit_code == 1
        assert "Execution failed" in res.stderr
