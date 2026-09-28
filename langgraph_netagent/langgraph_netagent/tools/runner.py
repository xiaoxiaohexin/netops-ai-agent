"""Subprocess Execution Engine with Cross-Platform Windows/WSL2/Linux Bridging."""

from __future__ import annotations
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
from typing import List, Optional, Union
from langgraph_netagent.tools.base import CommandResult


_ANSI_ESCAPE_PATTERN = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi_codes(text: str) -> str:
    """Remove ANSI terminal escape color and formatting codes from text."""
    return _ANSI_ESCAPE_PATTERN.sub("", text)


def strip_wsl_noise(text: str) -> str:
    """Filter out WSL2 startup diagnostic notices (e.g. 'wsl: ... localhost ...')."""
    if not text:
        return ""
    clean_lines = []
    for line in text.splitlines():
        l_str = line.strip()
        l_condensed = "".join(l_str.split())
        if (
            l_str.startswith("wsl:")
            or l_str.startswith("w s l :")
            or "localhost" in l_condensed.lower()
            or ("wsl" in l_condensed.lower() and "nat" in l_condensed.lower())
        ):
            continue
        clean_lines.append(line)
    return "\n".join(clean_lines).strip()


def windows_to_wsl_path(path: Union[str, Path]) -> str:
    """Convert a Windows file path (e.g. 'E:\\Containerlab\\lab.clab.yml') to WSL path ('/mnt/e/Containerlab/lab.clab.yml')."""
    p_str = str(path).replace("\\", "/")
    # Match drive letter like 'E:/' or 'e:/' or 'E:'
    drive_match = re.match(r"^([a-zA-Z]):/(.*)$", p_str)
    if drive_match:
        drive = drive_match.group(1).lower()
        rest = drive_match.group(2)
        return f"/mnt/{drive}/{rest}"
    drive_colon_only = re.match(r"^([a-zA-Z]):(.*)$", p_str)
    if drive_colon_only:
        drive = drive_colon_only.group(1).lower()
        rest = drive_colon_only.group(2).lstrip("/")
        return f"/mnt/{drive}/{rest}"
    return p_str


def wsl_to_windows_path(wsl_path: str) -> str:
    """Convert a WSL mount path ('/mnt/e/...') to Windows path ('E:\\...')."""
    clean = wsl_path.strip().replace("\\", "/")
    mnt_match = re.match(r"^/mnt/([a-zA-Z])/(.*)$", clean)
    if mnt_match:
        drive = mnt_match.group(1).upper()
        rest = mnt_match.group(2).replace("/", "\\")
        return f"{drive}:\\{rest}"
    return wsl_path


class SubprocessRunner:
    """Cross-platform command execution runner with timeout protection and WSL root bridge support."""

    def __init__(
        self,
        use_wsl_bridge: Optional[bool] = None,
        wsl_distro: Optional[str] = None,
        default_timeout: int = 30,
    ):
        self.os_name = platform.system().lower()
        if use_wsl_bridge is None:
            self.use_wsl_bridge = (self.os_name == "windows")
        else:
            self.use_wsl_bridge = use_wsl_bridge
        if wsl_distro:
            self.wsl_distro = wsl_distro
        elif self.os_name == "windows":
            self.wsl_distro = os.environ.get("WSL_DISTRO", "Ubuntu")
        else:
            self.wsl_distro = None
        self.default_timeout = default_timeout

    def run(
        self,
        command: Union[str, List[str]],
        cwd: Optional[Union[str, Path]] = None,
        timeout: Optional[int] = None,
        sudo: bool = False,
        node_name: Optional[str] = None,
    ) -> CommandResult:
        """Execute a command either locally or via the WSL bridge.
        
        Args:
            command: Command string or list of arguments.
            cwd: Working directory for execution.
            timeout: Timeout in seconds (falls back to default_timeout).
            sudo: If True, execute with root/sudo privileges.
            node_name: Optional node label to attach to CommandResult.
            
        Returns:
            CommandResult containing exit code, stdout, stderr, and elapsed time.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        cmd_str = command if isinstance(command, str) else " ".join(command)
        start_time = time.time()

        try:
            if self.use_wsl_bridge:
                result = self._run_wsl(command=cmd_str, cwd=cwd, timeout=effective_timeout, sudo=sudo)
            else:
                result = self._run_native(command=command, cwd=cwd, timeout=effective_timeout, sudo=sudo)
            
            elapsed = time.time() - start_time
            return CommandResult(
                command=cmd_str,
                exit_code=result[0],
                stdout=result[1],
                stderr=result[2],
                node=node_name,
                duration_seconds=round(elapsed, 4),
            )
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            return CommandResult(
                command=cmd_str,
                exit_code=-1,
                stdout="",
                stderr=f"Command timed out after {effective_timeout}s",
                node=node_name,
                duration_seconds=round(elapsed, 4),
            )
        except Exception as exc:
            elapsed = time.time() - start_time
            return CommandResult(
                command=cmd_str,
                exit_code=1,
                stdout="",
                stderr=f"Execution failed: {exc}",
                node=node_name,
                duration_seconds=round(elapsed, 4),
            )

    def exec_in_container(
        self,
        container_name: str,
        command: str,
        timeout: int = 15,
        node_name: Optional[str] = None,
    ) -> CommandResult:
        """Execute a command inside a running Docker container via `docker exec`.
        
        Args:
            container_name: Full container name (e.g. 'clab-lab-pc1').
            command: Command to run inside the container.
            timeout: Execution timeout in seconds.
            node_name: Node label for the result.
            
        Returns:
            CommandResult from the container execution.
        """
        # If the command contains shell constructs (pipes, redirects, compound, subshells),
        # wrap it in `sh -c '<cmd>'` so execution happens strictly inside the target container.
        needs_shell = any(char in command for char in ("|", "&", ";", ">", "<", "(", ")", "$"))
        if needs_shell and not (command.strip().startswith("sh -c") or command.strip().startswith("bash -c")):
            escaped = command.replace("'", "'\\''")
            docker_cmd = f"docker exec {container_name} sh -c '{escaped}'"
        else:
            docker_cmd = f"docker exec {container_name} {command}"

        return self.run(
            command=docker_cmd,
            timeout=timeout,
            sudo=False,
            node_name=node_name or container_name,
        )

    def _run_native(
        self,
        command: Union[str, List[str]],
        cwd: Optional[Union[str, Path]],
        timeout: int,
        sudo: bool,
    ) -> tuple[int, str, str]:
        """Execute command natively on the current operating system."""
        use_shell = isinstance(command, str)
        cmd_args: Union[str, List[str]]

        if sudo and self.os_name != "windows":
            if isinstance(command, list):
                cmd_args = ["sudo", "-n"] + command
                use_shell = False
            else:
                cmd_args = f"sudo -n {command}"
                use_shell = True
        else:
            cmd_args = command

        str_cwd = str(cwd) if cwd else None
        proc = subprocess.run(
            cmd_args,
            shell=use_shell,
            cwd=str_cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            errors="replace",
        )
        stdout = strip_ansi_codes(proc.stdout or "").replace("\r\n", "\n")
        stderr = strip_ansi_codes(proc.stderr or "").replace("\r\n", "\n")
        return proc.returncode, stdout, stderr

    def _run_wsl(
        self,
        command: str,
        cwd: Optional[Union[str, Path]],
        timeout: int,
        sudo: bool,
    ) -> tuple[int, str, str]:
        """Execute command inside WSL2 via wsl.exe bridge."""
        wsl_bin = shutil.which("wsl.exe") or "wsl"
        args = [wsl_bin]
        if self.wsl_distro:
            args.extend(["-d", self.wsl_distro])

        # If sudo or Containerlab operation, execute as root user
        if sudo:
            args.extend(["-u", "root"])

        args.append("--")
        args.append("bash")
        args.append("-c")

        # Wrap with cd if cwd is provided
        if cwd:
            wsl_cwd = windows_to_wsl_path(cwd)
            bash_script = f"cd '{wsl_cwd}' && {command}"
        else:
            bash_script = command

        args.append(bash_script)

        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            errors="replace",
        )
        stdout = strip_wsl_noise(strip_ansi_codes(proc.stdout or "").replace("\r\n", "\n"))
        stderr = strip_wsl_noise(strip_ansi_codes(proc.stderr or "").replace("\r\n", "\n"))
        return proc.returncode, stdout, stderr


class WSLBridgeRunner(SubprocessRunner):
    """Convenience subclass explicitly enforcing WSL bridge execution."""

    def __init__(self, wsl_distro: Optional[str] = None, default_timeout: int = 30):
        super().__init__(use_wsl_bridge=True, wsl_distro=wsl_distro, default_timeout=default_timeout)
