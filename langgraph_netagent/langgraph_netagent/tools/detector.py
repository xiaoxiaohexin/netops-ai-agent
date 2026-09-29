"""Environment Capability Detection for Live Containerlab vs Mock Execution."""

from __future__ import annotations
from enum import Enum
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class ExecutionMode(str, Enum):
    """Adapter execution mode."""
    LIVE = "live"
    MOCK = "mock"
    AUTO = "auto"


class DetectedTopology(BaseModel):
    """A detected live or simulated network topology available for binding."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(..., description="Selection ID (e.g. '1', '2')")
    name: str = Field(..., description="Lab or topology identifier (e.g. 'clos5')")
    kind: str = Field(..., description="'containerlab' or 'in_memory'")
    display_type: str = Field(..., description="Human-readable category description")
    node_count: int = Field(default=0, description="Total nodes in the topology")
    status: str = Field(..., description="Operating status (Active/Ready)")
    summary: str = Field(..., description="Summary of nodes, tiers, or subnets")
    subnet: Optional[str] = Field(default=None, description="Management or underlay subnet")
    is_active: bool = Field(default=False, description="True if currently active/selected")


class SystemNetworkInventory(BaseModel):
    """Comprehensive inventory of host NICs, WSL bridges, and accessible network topologies."""
    model_config = ConfigDict(populate_by_name=True)

    host_interfaces: List[Dict[str, Any]] = Field(default_factory=list, description="Host physical/virtual NICs")
    wsl_bridges: List[Dict[str, Any]] = Field(default_factory=list, description="WSL bridges and container veths")
    available_topologies: List[DetectedTopology] = Field(default_factory=list, description="Discoverable topologies")
    recommended_lab: Optional[str] = Field(default=None, description="Recommended default lab name")



class EnvironmentCapabilities(BaseModel):
    """Detected capabilities of the host environment."""
    model_config = ConfigDict(populate_by_name=True)

    os_name: str = Field(..., description="Operating system: 'windows', 'linux', or 'wsl'")
    has_wsl: bool = Field(default=False, description="True if Windows Subsystem for Linux is available")
    wsl_distro: Optional[str] = Field(default=None, description="Default or detected WSL distribution name")
    has_docker: bool = Field(default=False, description="True if docker CLI is present")
    docker_responsive: bool = Field(default=False, description="True if docker daemon responds to 'docker info'")
    has_clab: bool = Field(default=False, description="True if clab CLI is found natively or inside WSL")
    has_root: bool = Field(default=False, description="True if root or passwordless sudo privileges are available")
    resolved_mode: ExecutionMode = Field(..., description="Resolved operational mode (LIVE or MOCK)")
    reason: str = Field(..., description="Explanation of mode resolution")


class EnvironmentDetector:
    """Probes the host environment to determine whether Containerlab can run live."""

    ENV_VAR_MODE = "NETAGENT_MODE"
    ENV_VAR_CLAB_MODE = "CONTAINERLAB_MODE"

    def __init__(self, wsl_distro: Optional[str] = None):
        self.wsl_distro = wsl_distro

    def detect(
        self,
        forced_mode: Optional[Union[str, ExecutionMode]] = None,
        strict: bool = False,
    ) -> EnvironmentCapabilities:
        """Probe the system and resolve the execution mode.
        
        Args:
            forced_mode: Explicitly enforce 'live', 'mock', or 'auto'. Overrides env vars.
            strict: If True and forced_mode is LIVE, raise RuntimeError when live checks fail.
            
        Returns:
            EnvironmentCapabilities detailing detected features and resolved mode.
        """
        # Determine requested mode from arguments or environment
        mode_str = (
            forced_mode.value if isinstance(forced_mode, ExecutionMode)
            else forced_mode
            or os.environ.get(self.ENV_VAR_MODE)
            or os.environ.get(self.ENV_VAR_CLAB_MODE)
            or "auto"
        ).lower()

        # Probe OS
        os_name, is_wsl = self._probe_os()
        has_wsl_cli = False
        wsl_distro = self.wsl_distro

        if os_name == "windows":
            has_wsl_cli, detected_distro = self._probe_wsl_on_windows()
            if not wsl_distro and detected_distro:
                wsl_distro = detected_distro

        # If explicitly forced to MOCK, bypass external probing
        if mode_str == "mock":
            return EnvironmentCapabilities(
                os_name=os_name,
                has_wsl=has_wsl_cli or is_wsl,
                wsl_distro=wsl_distro,
                has_docker=False,
                docker_responsive=False,
                has_clab=False,
                has_root=False,
                resolved_mode=ExecutionMode.MOCK,
                reason="Forced to MOCK mode by configuration or environment",
            )

        # Probe Docker
        has_docker, docker_responsive = self._probe_docker(os_name=os_name, has_wsl=has_wsl_cli, wsl_distro=wsl_distro)

        # Probe Containerlab
        has_clab = self._probe_clab(os_name=os_name, has_wsl=has_wsl_cli, wsl_distro=wsl_distro)

        # Probe Root / Sudo privileges
        has_root = self._probe_root(os_name=os_name, has_wsl=has_wsl_cli, wsl_distro=wsl_distro)

        # Resolve mode
        reasons = []
        if not docker_responsive:
            reasons.append("Docker daemon not running or not responsive")
        if not has_clab:
            reasons.append("Containerlab ('clab') binary not found")
        if not has_root:
            reasons.append("Root or passwordless sudo privilege not available")

        can_run_live = docker_responsive and has_clab and has_root

        if mode_str == "live":
            if not can_run_live:
                failure_reason = "Enforced LIVE mode but prerequisites missing: " + "; ".join(reasons)
                if strict:
                    raise RuntimeError(failure_reason)
                return EnvironmentCapabilities(
                    os_name=os_name,
                    has_wsl=has_wsl_cli or is_wsl,
                    wsl_distro=wsl_distro,
                    has_docker=has_docker,
                    docker_responsive=docker_responsive,
                    has_clab=has_clab,
                    has_root=has_root,
                    resolved_mode=ExecutionMode.LIVE,
                    reason=failure_reason,
                )
            return EnvironmentCapabilities(
                os_name=os_name,
                has_wsl=has_wsl_cli or is_wsl,
                wsl_distro=wsl_distro,
                has_docker=has_docker,
                docker_responsive=docker_responsive,
                has_clab=has_clab,
                has_root=has_root,
                resolved_mode=ExecutionMode.LIVE,
                reason="Enforced LIVE mode and prerequisites satisfied",
            )

        # Auto mode
        if can_run_live:
            return EnvironmentCapabilities(
                os_name=os_name,
                has_wsl=has_wsl_cli or is_wsl,
                wsl_distro=wsl_distro,
                has_docker=has_docker,
                docker_responsive=docker_responsive,
                has_clab=has_clab,
                has_root=has_root,
                resolved_mode=ExecutionMode.LIVE,
                reason="Full Containerlab, Docker, and root capabilities detected",
            )
        else:
            return EnvironmentCapabilities(
                os_name=os_name,
                has_wsl=has_wsl_cli or is_wsl,
                wsl_distro=wsl_distro,
                has_docker=has_docker,
                docker_responsive=docker_responsive,
                has_clab=has_clab,
                has_root=has_root,
                resolved_mode=ExecutionMode.MOCK,
                reason=f"Fell back to MOCK mode: {'; '.join(reasons)}",
            )

    def _probe_os(self) -> tuple[str, bool]:
        """Detect OS family and WSL indicator."""
        sys_name = platform.system().lower()
        if sys_name == "windows":
            return "windows", False
        if sys_name == "linux":
            # Check if running inside WSL
            try:
                proc_ver = Path("/proc/version")
                if proc_ver.exists():
                    text = proc_ver.read_text(encoding="utf-8", errors="replace").lower()
                    if "microsoft" in text or "wsl" in text:
                        return "wsl", True
            except Exception:
                pass
            return "linux", False
        return sys_name, False

    def _probe_wsl_on_windows(self) -> tuple[bool, Optional[str]]:
        """Check if WSL CLI is available on Windows and detect default distro."""
        wsl_bin = shutil.which("wsl.exe") or shutil.which("wsl")
        if not wsl_bin:
            return False, None
        try:
            res = subprocess.run(
                [wsl_bin, "-l", "-q"],
                capture_output=True,
                text=True,
                timeout=5,
                encoding="utf-16le",  # wsl -l -q on Windows often uses UTF-16LE
                errors="replace",
            )
            if res.returncode == 0:
                distros = [line.strip().replace("\x00", "") for line in res.stdout.splitlines() if line.strip()]
                # Prefer real Linux distributions like Ubuntu/Debian over helper distros like docker-desktop
                preferred = next((d for d in distros if any(name in d.lower() for name in ["ubuntu", "debian", "arch", "fedora", "centos"])), None)
                default_distro = preferred or (distros[0] if distros else None)
                return True, default_distro
        except Exception:
            pass

        # Fallback without explicit encoding
        try:
            res = subprocess.run(
                [wsl_bin, "--status"],
                capture_output=True,
                text=True,
                timeout=5,
                errors="replace",
            )
            return (res.returncode == 0), None
        except Exception:
            return False, None

    def _probe_docker(self, os_name: str, has_wsl: bool, wsl_distro: Optional[str]) -> tuple[bool, bool]:
        """Check if Docker CLI exists and daemon responds."""
        # Probe Docker natively first
        docker_cli = shutil.which("docker")
        if docker_cli:
            try:
                res = subprocess.run(
                    [docker_cli, "info"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    errors="replace",
                )
                if res.returncode == 0:
                    return True, True
            except Exception:
                pass

        # On Windows, check inside WSL if native Docker daemon is absent or not responding
        if os_name == "windows" and has_wsl:
            wsl_bin = shutil.which("wsl.exe") or "wsl"
            cmd = [wsl_bin]
            if wsl_distro:
                cmd.extend(["-d", wsl_distro])
            cmd.extend(["-u", "root", "--", "docker", "info"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, errors="replace")
                if res.returncode == 0:
                    return True, True
            except Exception:
                pass

        return False, False

    def _probe_clab(self, os_name: str, has_wsl: bool, wsl_distro: Optional[str]) -> bool:
        """Check if containerlab CLI is available."""
        if shutil.which("clab"):
            try:
                res = subprocess.run(["clab", "version"], capture_output=True, text=True, timeout=5, errors="replace")
                return res.returncode == 0
            except Exception:
                return False

        # On Windows, check if clab is installed inside WSL
        if os_name == "windows" and has_wsl:
            wsl_bin = shutil.which("wsl.exe") or "wsl"
            cmd = [wsl_bin]
            if wsl_distro:
                cmd.extend(["-d", wsl_distro])
            cmd.extend(["-u", "root", "--", "clab", "version"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, errors="replace")
                return res.returncode == 0
            except Exception:
                return False

        return False

    def _probe_root(self, os_name: str, has_wsl: bool, wsl_distro: Optional[str]) -> bool:
        """Check if root or passwordless sudo is available."""
        if os_name in ("linux", "wsl"):
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                return True
            # Test passwordless sudo
            try:
                res = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=3)
                return res.returncode == 0
            except Exception:
                return False

        if os_name == "windows" and has_wsl:
            # Running with wsl.exe -u root provides root privileges inside WSL
            wsl_bin = shutil.which("wsl.exe") or "wsl"
            cmd = [wsl_bin]
            if wsl_distro:
                cmd.extend(["-d", wsl_distro])
            cmd.extend(["-u", "root", "--", "id", "-u"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, errors="replace")
                return res.returncode == 0 and res.stdout.strip() == "0"
            except Exception:
                return False

        return False

    def scan_inventory(self, active_lab: Optional[str] = None) -> SystemNetworkInventory:
        """Scan host NICs, WSL bridges, and all discoverable network topologies."""
        host_nics: List[Dict[str, Any]] = []
        wsl_bridges: List[Dict[str, Any]] = []
        available_topos: List[DetectedTopology] = []

        # 1. Probe Host Windows NICs
        if platform.system().lower() == "windows":
            ps_bin = shutil.which("powershell.exe") or "powershell"
            cmd = [
                ps_bin,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name, InterfaceDescription, LinkSpeed | ConvertTo-Json -Compress",
            ]
            try:
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                out = res.stdout.decode("utf-8", errors="replace").strip()
                if res.returncode == 0 and out:
                    raw = json.loads(out)
                    items = raw if isinstance(raw, list) else [raw]
                    for it in items:
                        host_nics.append({
                            "name": it.get("Name", "unknown"),
                            "description": it.get("InterfaceDescription", ""),
                            "speed": it.get("LinkSpeed", "unknown"),
                        })
            except Exception:
                pass

        # 2. Probe WSL Interfaces & Bridges
        wsl_bin = shutil.which("wsl.exe") or "wsl"
        distro = self.wsl_distro or "Ubuntu"
        try:
            cmd = [wsl_bin, "-d", distro, "-u", "root", "--", "ip", "-br", "addr"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            out = res.stdout.decode("utf-8", errors="replace")
            if res.returncode == 0 and out:
                lines = [l for l in out.splitlines() if not l.startswith("wsl:")]
                veth_count = 0
                for line in lines:
                    parts = line.split()
                    if not parts:
                        continue
                    ifname = parts[0]
                    state = parts[1] if len(parts) > 1 else "UNKNOWN"
                    addrs = " ".join(parts[2:]) if len(parts) > 2 else ""
                    if ifname.startswith("veth"):
                        veth_count += 1
                        continue
                    wsl_bridges.append({
                        "name": ifname,
                        "state": state,
                        "addrs": addrs,
                    })
                if veth_count > 0:
                    wsl_bridges.append({
                        "name": f"veth* ({veth_count} 对容器虚拟网卡)",
                        "state": "UP",
                        "addrs": "直连容器端口",
                    })
        except Exception:
            pass

        # 3. Probe Live Containerlab Labs
        try:
            cmd = [wsl_bin, "-d", distro, "-u", "root", "--", "clab", "inspect", "--all", "--format", "json"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
            out = res.stdout.decode("utf-8", errors="replace").strip()
            if res.returncode == 0 and out:
                data = json.loads(out)
                containers = []
                if isinstance(data, list):
                    containers = data
                elif isinstance(data, dict):
                    if "containers" in data and isinstance(data["containers"], list):
                        containers = data["containers"]
                    else:
                        for v in data.values():
                            if isinstance(v, list):
                                containers.extend(v)

                labs_map: Dict[str, List[Dict[str, Any]]] = {}
                for c in containers:
                    c_name = c.get("name") or c.get("Names", [""])[0] if isinstance(c.get("Names"), list) else str(c.get("Names") or "")
                    l_name = c.get("lab_name") or c.get("LabName")
                    if not l_name:
                        labels = c.get("Labels") or c.get("labels") or {}
                        l_name = labels.get("clab-node-lab-name") or labels.get("containerlab")
                    if not l_name and "clab-" in c_name:
                        parts = c_name.replace("clab-", "").split("-")
                        l_name = parts[0] if parts else "clos5"
                    l_name = l_name or "clos5"
                    labs_map.setdefault(l_name, []).append(c)

                for l_name, c_list in labs_map.items():
                    topo_id = str(len(available_topos) + 1)
                    mgmt_net = "172.100.100.0/24"
                    available_topos.append(DetectedTopology(
                        id=topo_id,
                        name=l_name,
                        kind="containerlab",
                        display_type="Containerlab (真实容器网卡)",
                        node_count=len(c_list),
                        status="运行中 (Active)",
                        summary=f"{len(c_list)} 个容器节点 (含 leaf, spine, router, hosts)",
                        subnet=mgmt_net,
                        is_active=(l_name == active_lab),
                    ))
        except Exception:
            pass

        # 4. In-Memory Mock Topology Option
        mock_id = str(len(available_topos) + 1)
        available_topos.append(DetectedTopology(
            id=mock_id,
            name="netagent-lab",
            kind="in_memory",
            display_type="In-Memory Mock (内存虚拟拓扑)",
            node_count=3,
            status="就绪 (Ready)",
            summary="3 个虚拟节点 (pc1, frr1, pc2), 2 个子网 (纯内存仿真)",
            subnet="10.1.1.0/24, 10.2.2.0/24",
            is_active=(active_lab == "netagent-lab"),
        ))

        rec_lab = available_topos[0].name if available_topos else "netagent-lab"

        return SystemNetworkInventory(
            host_interfaces=host_nics,
            wsl_bridges=wsl_bridges,
            available_topologies=available_topos,
            recommended_lab=rec_lab,
        )

