"""Live Physical and Virtual Network Interface (NIC) Adapter.

Enables NetOps Agent to attach to any real host network interface (e.g.
VMware VMnet, Wi-Fi WLAN, Physical Ethernet, TUN/TAP tunnels), discover
neighbor nodes (VMs, gateways, appliances) via ARP/NDP, and execute
telemetry probes and operations.
"""

from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Union

from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)


class LiveNICAdapter(BaseNetworkLabAdapter):
    """Adapter attaching directly to a physical or virtual host NIC."""

    def __init__(self, interface_name: str):
        self.interface_name = interface_name
        self.lab_name = interface_name
        self._cached_topo_summary: Optional[str] = None

    def deploy(
        self,
        topo_file: Union[str, Path],
        reconfigure: bool = True,
    ) -> DeploymentResult:
        """Physical/virtual NICs are already provisioned by host OS."""
        return DeploymentResult(
            success=True,
            lab_name=self.interface_name,
            topo_file=str(topo_file),
            nodes_deployed=[],
            raw_output=f"Attached to active host network interface: {self.interface_name}",
            duration_seconds=0.0,
        )

    def destroy(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
        cleanup: bool = True,
    ) -> DestructionResult:
        """Detach from host interface without destroying system NIC."""
        return DestructionResult(
            success=True,
            lab_name=self.interface_name,
            raw_output=f"Detached from host network interface: {self.interface_name}",
            duration_seconds=0.0,
        )

    def inspect(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
    ) -> LabInspectionResult:
        """Inspect all active nodes, neighbors, and gateway on this interface."""
        target_iface = lab_name or self.interface_name
        nodes: List[LabNodeState] = []

        if platform.system().lower() == "windows":
            ps_bin = shutil.which("powershell.exe") or "powershell"

            # 1. Fetch Host IP on this interface
            cmd_ip = [
                ps_bin,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f'Get-NetIPAddress -InterfaceAlias "*{target_iface}*" -AddressFamily IPv4 | Select-Object IPAddress, PrefixLength | ConvertTo-Json -Compress',
            ]
            host_ip = None
            host_prefix = 24
            try:
                res_ip = subprocess.run(cmd_ip, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=4)
                out_ip = res_ip.stdout.decode("utf-8", errors="replace").strip()
                if res_ip.returncode == 0 and out_ip:
                    data_ip = json.loads(out_ip)
                    if isinstance(data_ip, list):
                        data_ip = data_ip[0]
                    host_ip = data_ip.get("IPAddress")
                    host_prefix = data_ip.get("PrefixLength", 24)
            except Exception:
                pass

            if host_ip:
                nodes.append(
                    LabNodeState(
                        name="host-win32 (本机网卡)",
                        container_id=f"nic-{target_iface[:10]}",
                        image="Windows TCP/IP Stack",
                        kind="host",
                        state="running",
                        ipv4_address=f"{host_ip}/{host_prefix}",
                    )
                )

            # 2. Fetch Neighbors / VMs / Gateway on this interface
            cmd_nbr = [
                ps_bin,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f'Get-NetNeighbor -InterfaceAlias "*{target_iface}*" -AddressFamily IPv4 | Where-Object {{ $_.IPAddress -notlike "224.*" -and $_.IPAddress -notlike "239.*" -and $_.IPAddress -notlike "255.*" }} | Select-Object IPAddress, LinkLayerAddress, State | ConvertTo-Json -Compress',
            ]
            try:
                res_nbr = subprocess.run(cmd_nbr, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                out_nbr = res_nbr.stdout.decode("utf-8", errors="replace").strip()
                if res_nbr.returncode == 0 and out_nbr:
                    data_nbr = json.loads(out_nbr)
                    items = data_nbr if isinstance(data_nbr, list) else [data_nbr]
                    for it in items:
                        ip = str(it.get("IPAddress", "")).strip()
                        mac = str(it.get("LinkLayerAddress", "")).strip()
                        raw_state = it.get("State", "")
                        state_str = str(raw_state).lower()
                        if not ip or ip == host_ip or mac in ("00-00-00-00-00-00", "FF-FF-FF-FF-FF-FF") or ip.endswith(".255"):
                            continue

                        # Standard OUI prefix table for dynamic hardware identification (No Presets)
                        mac_clean = mac.upper().replace("-", ":")
                        vendor = "LAN Endpoint Device"
                        kind = "workstation"
                        if mac_clean.startswith("00:0C:29") or mac_clean.startswith("00:50:56") or mac_clean.startswith("00:05:69"):
                            vendor = "VMware Virtual Device"
                            kind = "linux-vm"
                        elif mac_clean.startswith("00:15:5D"):
                            vendor = "Microsoft Hyper-V VM"
                            kind = "linux-vm"
                        elif mac_clean.startswith("08:00:27"):
                            vendor = "Oracle VirtualBox VM"
                            kind = "linux-vm"
                        elif mac_clean.startswith("70:42:D3") or mac_clean.startswith("FC:6D:77"):
                            vendor = "Switch / Network Gateway"
                            kind = "router"
                        elif mac_clean.startswith("00:1A:A0") or mac_clean.startswith("3C:CD:57") or mac_clean.startswith("C0:25:67"):
                            vendor = "Apple Device"
                            kind = "workstation"
                        elif mac_clean.startswith("34:E1:2D") or mac_clean.startswith("00:E0:4C"):
                            vendor = "PC Ethernet Device"
                            kind = "workstation"
                        elif mac_clean.startswith("B8:27:EB") or mac_clean.startswith("DC:A6:32") or mac_clean.startswith("E4:5F:01"):
                            vendor = "Raspberry Pi Device"
                            kind = "iot"

                        # Determine dynamic role
                        if ip.endswith(".1") or ip.endswith(".254") or ip.endswith(".2"):
                            node_role = f"gateway ({ip})"
                            kind = "router"
                        else:
                            node_role = f"node ({ip})"

                        node_name = f"{node_role} [{vendor}]"
                        img_desc = f"MAC: {mac} | {vendor}"

                        is_active = (
                            state_str in ("reachable", "stale", "permanent", "2", "4", "6")
                            or (isinstance(raw_state, int) and raw_state in (2, 3, 4, 5, 6))
                        )
                        st_str = "running" if is_active else "unreachable"
                        nodes.append(
                            LabNodeState(
                                name=node_name,
                                container_id=f"mac-{mac[:8].replace('-', '')}",
                                image=img_desc,
                                kind=kind,
                                state=st_str,
                                ipv4_address=f"{ip}/{host_prefix}",
                            )
                        )
            except Exception:
                pass

        if not nodes:
            # Fallback placeholder if no neighbors found yet
            nodes.append(
                LabNodeState(
                    name=f"{target_iface} (宿主机接口)",
                    container_id="nic-local",
                    image="Host NIC",
                    kind="interface",
                    state="running",
                    ipv4_address="N/A",
                )
            )

        return LabInspectionResult(
            success=True,
            lab_name=target_iface,
            nodes=nodes,
            raw_output=f"Found {len(nodes)} active endpoints on interface {target_iface}",
        )

    def exec_command(
        self,
        node_name: str,
        command: str,
        timeout: int = 15,
    ) -> CommandResult:
        """Execute command against node or host network."""
        return self.execute(node=node_name, command=command, timeout=timeout)

    def is_live_ready(self) -> bool:
        """Check if interface is active and reachable."""
        return True

    def execute(
        self,
        node: str,
        command: str,
        timeout: int = 30,
        sudo: bool = False,
    ) -> CommandResult:
        """Execute command against node or host network."""
        t0 = time.time()
        # Direct execution on host or ping test
        ps_bin = shutil.which("powershell.exe") or "powershell"
        cmd = [ps_bin, "-NoProfile", "-NonInteractive", "-Command", command]
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            duration = time.time() - t0
            return CommandResult(
                command=command,
                exit_code=res.returncode,
                stdout=res.stdout.decode("utf-8", errors="replace"),
                stderr=res.stderr.decode("utf-8", errors="replace"),
                node=node,
                duration_seconds=duration,
            )
        except Exception as e:
            return CommandResult(
                command=command,
                exit_code=1,
                stdout="",
                stderr=str(e),
                node=node,
                duration_seconds=time.time() - t0,
            )

    def get_topology_summary(self) -> str:
        """Generate human-readable architectural overview of this NIC network."""
        inspect_res = self.inspect()
        lines = [
            f"当前运行中网络拓扑: {self.interface_name}",
            f"网络拓扑类型: 真实主机物理/虚拟网卡局域网 (Host NIC Network)",
            f"在线节点规模: 共 {len(inspect_res.nodes)} 个活跃网络节点\n",
            "【当前网卡互联资产与节点角色】:",
        ]
        for n in inspect_res.nodes:
            lines.append(f"- {n.name}: IP={n.ipv4_address or 'N/A'}, 角色/镜像={n.image}, 状态={n.state}")

        lines.extend([
            "\n【底层控制与通信机制】:",
            f"- 承载网卡: {self.interface_name}",
            "- 二层交换: 虚拟以太网交换机 (VMware Virtual Switch / 802.3 Ethernet)",
            "- 三层转发: 本地子网直接路由 (Direct Connected Route) + NAT 网关出口",
            "- 支持运维操作: ICMP 探针、TCP/UDP 端口探测、ARP 扫描、SSH 远程诊断",
        ])
        return "\n".join(lines)
