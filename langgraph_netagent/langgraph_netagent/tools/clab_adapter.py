"""Live Containerlab Adapter Interfacing with Host or WSL2 CLI."""

from __future__ import annotations
import json
from pathlib import Path
import posixpath
import re
from typing import List, Optional, Union
import yaml

from langgraph_netagent.tools.base import (
    BaseNetworkLabAdapter,
    CommandResult,
    DeploymentResult,
    DestructionResult,
    LabInspectionResult,
    LabNodeState,
)
from langgraph_netagent.tools.detector import EnvironmentDetector, ExecutionMode
from langgraph_netagent.tools.runner import SubprocessRunner, windows_to_wsl_path


class LiveContainerlabAdapter(BaseNetworkLabAdapter):
    """Adapter executing real clab and docker commands on Linux or Windows via WSL2."""

    def __init__(
        self,
        runner: Optional[SubprocessRunner] = None,
        lab_name: Optional[str] = None,
        wsl_distro: Optional[str] = None,
    ):
        self.detector = EnvironmentDetector(wsl_distro=wsl_distro)
        caps = self.detector.detect()
        effective_distro = wsl_distro or caps.wsl_distro
        self.runner = runner or SubprocessRunner(wsl_distro=effective_distro)
        self.lab_name = lab_name
        self._node_to_container: dict[str, str] = {}
        self._cached_topo_summary: Optional[str] = None

    def deploy(
        self,
        topo_file: Union[str, Path],
        reconfigure: bool = True,
    ) -> DeploymentResult:
        """Deploy a Containerlab topology."""
        topo_p = Path(topo_file)
        if self.runner.use_wsl_bridge:
            topo_arg = windows_to_wsl_path(topo_p)
            cwd_arg = windows_to_wsl_path(topo_p.parent)
        else:
            topo_arg = str(topo_p)
            cwd_arg = str(topo_p.parent)

        cmd = f"clab deploy --topo '{topo_arg}'"
        if reconfigure:
            cmd += " --reconfigure"

        result = self.runner.run(
            command=cmd,
            cwd=topo_p.parent if not self.runner.use_wsl_bridge else None,
            timeout=180,
            sudo=True,
        )

        success = (result.exit_code == 0)
        deployed_nodes = self._extract_deployed_nodes(result.stdout)
        inferred_lab_name = self.lab_name or self._extract_lab_name(result.stdout) or topo_p.stem.replace(".clab", "")
        self.lab_name = inferred_lab_name

        self._cached_topo_summary = None
        return DeploymentResult(
            success=success,
            lab_name=inferred_lab_name,
            topo_file=str(topo_file),
            nodes_deployed=deployed_nodes,
            raw_output=result.stdout + ("\n" + result.stderr if result.stderr else ""),
            error_message=None if success else (result.stderr or "Deployment exited with non-zero code"),
            duration_seconds=result.duration_seconds,
        )

    def destroy(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
        cleanup: bool = True,
    ) -> DestructionResult:
        """Destroy a Containerlab topology."""
        self._cached_topo_summary = None
        target_name = lab_name or self.lab_name
        cmd = "clab destroy"
        if topo_file:
            topo_p = Path(topo_file)
            topo_arg = windows_to_wsl_path(topo_p) if self.runner.use_wsl_bridge else str(topo_p)
            cmd += f" --topo '{topo_arg}'"
        elif target_name:
            cmd += f" --name '{target_name}'"
        else:
            raise ValueError("Either topo_file or lab_name must be provided to destroy()")

        if cleanup:
            cmd += " --cleanup"

        result = self.runner.run(command=cmd, timeout=120, sudo=True)
        success = (result.exit_code == 0)

        return DestructionResult(
            success=success,
            lab_name=target_name or "unknown",
            raw_output=result.stdout + ("\n" + result.stderr if result.stderr else ""),
            error_message=None if success else (result.stderr or "Destroy exited with non-zero code"),
            duration_seconds=result.duration_seconds,
        )

    def inspect(
        self,
        topo_file: Optional[Union[str, Path]] = None,
        lab_name: Optional[str] = None,
    ) -> LabInspectionResult:
        """Inspect running lab containers."""
        target_name = lab_name or self.lab_name
        cmd = "clab inspect --format json"
        if topo_file:
            topo_p = Path(topo_file)
            topo_arg = windows_to_wsl_path(topo_p) if self.runner.use_wsl_bridge else str(topo_p)
            cmd += f" --topo '{topo_arg}'"
        elif target_name:
            cmd += f" --name '{target_name}'"
        else:
            cmd += " --all"

        result = self.runner.run(command=cmd, timeout=30, sudo=True)
        if result.exit_code != 0:
            return LabInspectionResult(
                success=False,
                lab_name=target_name or "unknown",
                nodes=[],
                raw_output=result.stdout + "\n" + result.stderr,
                error_message=result.stderr or "Inspect command failed",
            )

        nodes = self._parse_inspect_json(result.stdout)
        return LabInspectionResult(
            success=True,
            lab_name=target_name or "unknown",
            nodes=nodes,
            raw_output=result.stdout,
        )

    def _resolve_container_name(self, node_name: str) -> str:
        """Resolve a logical node name (e.g. 'leaf1') to an actual running Docker container name (e.g. 'clab--leaf1')."""
        if node_name.startswith("clab-") or node_name.startswith("clab--"):
            return node_name

        if node_name in self._node_to_container:
            return self._node_to_container[node_name]

        # Query live docker containers to populate cache
        res = self.runner.run("docker ps --format '{{.Names}}'", timeout=10, sudo=False)
        if res.exit_code == 0 and res.stdout.strip():
            for c_name in res.stdout.splitlines():
                c_name = c_name.strip()
                if not c_name:
                    continue
                self._node_to_container[c_name] = c_name
                if c_name.startswith("clab--"):
                    short_n = c_name[6:]
                    self._node_to_container[short_n] = c_name
                elif c_name.startswith("clab-"):
                    parts = c_name.split("-")
                    if len(parts) >= 3:
                        short_n = parts[-1]
                        self._node_to_container[short_n] = c_name

        if node_name in self._node_to_container:
            return self._node_to_container[node_name]

        # Check suffix matches (e.g. 'clab--leaf1' or 'clab-clos5-leaf1' ends with '-leaf1')
        for c_id in self._node_to_container.values():
            if c_id.endswith(f"-{node_name}") or c_id.endswith(f"--{node_name}"):
                return c_id

        if self.lab_name:
            return f"clab-{self.lab_name}-{node_name}"
        return f"clab-{node_name}"

    def exec_command(
        self,
        node_name: str,
        command: str,
        timeout: int = 15,
    ) -> CommandResult:
        """Execute command in a container node."""
        container_name = self._resolve_container_name(node_name)

        return self.runner.exec_in_container(
            container_name=container_name,
            command=command,
            timeout=timeout,
            node_name=node_name,
        )

    def is_live_ready(self) -> bool:
        """Check if environment is capable of live Containerlab operations."""
        caps = self.detector.detect()
        return caps.resolved_mode == ExecutionMode.LIVE

    def _extract_deployed_nodes(self, output: str) -> List[str]:
        """Extract node names from clab deploy output table."""
        nodes = []
        for line in output.splitlines():
            # Format often contains | clab-<lab>-<node> | <image> | ...
            match = re.search(r"\|\s*clab-[a-zA-Z0-9_\-]+-([a-zA-Z0-9_\-]+)\s*\|", line)
            if match:
                node = match.group(1).strip()
                if node not in nodes:
                    nodes.append(node)
        return nodes

    def _extract_lab_name(self, output: str) -> Optional[str]:
        """Extract lab name from clab output headers."""
        match = re.search(r"Lab\s+name:\s*([a-zA-Z0-9_\-]+)", output, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match_table = re.search(r"clab-([a-zA-Z0-9_\-]+)-[a-zA-Z0-9_\-]+", output)
        if match_table:
            return match_table.group(1).strip()
        return None

    def _parse_inspect_json(self, json_text: str) -> List[LabNodeState]:
        """Parse JSON output from `clab inspect --format json`."""
        if not json_text.strip():
            return []
        try:
            data = json.loads(json_text)
        except Exception:
            return []

        containers: List[dict] = []
        if isinstance(data, list):
            containers = data
        elif isinstance(data, dict):
            if "containers" in data and isinstance(data["containers"], list):
                containers = data["containers"]
            else:
                # Sometimes keyed by lab name
                for val in data.values():
                    if isinstance(val, list):
                        containers.extend(val)

        nodes = []
        for c in containers:
            raw_name = c.get("name", "")
            # Extract simple node name from clab-<lab>-<node>
            node_name = raw_name
            if raw_name.startswith("clab-"):
                parts = raw_name.split("-")
                if len(parts) >= 3:
                    node_name = parts[-1]

            if raw_name:
                self._node_to_container[node_name] = raw_name
                self._node_to_container[raw_name] = raw_name

            state = c.get("state", "running")
            img = c.get("image", "")
            kind = c.get("kind", "")
            ipv4 = c.get("ipv4_address") or c.get("ipv4Address")
            ipv6 = c.get("ipv6_address") or c.get("ipv6Address")
            nodes.append(
                LabNodeState(
                    name=node_name,
                    container_id=raw_name,
                    image=img,
                    kind=kind,
                    state=state,
                    ipv4_address=ipv4,
                    ipv6_address=ipv6,
                )
            )
        return nodes

    def get_topology_summary(self) -> str:
        """Extract and format live topology details from running Containerlab lab."""
        if self._cached_topo_summary:
            return self._cached_topo_summary

        # 1. Run inspect to find running containers and lab path
        cmd = "clab inspect --format json"
        if not self.lab_name:
            cmd = "clab inspect --all --format json"
        else:
            cmd = f"clab inspect --name '{self.lab_name}' --format json"

        result = self.runner.run(command=cmd, timeout=30, sudo=True)
        if result.exit_code != 0 or not result.stdout.strip():
            return ""

        try:
            data = json.loads(result.stdout)
        except Exception:
            return ""

        lab_path = None
        containers = []
        if isinstance(data, list):
            containers = data
        elif isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    containers.extend(v)

        for item in containers:
            if isinstance(item, dict) and item.get("labPath"):
                lab_path = item.get("labPath")
                break

        if not lab_path:
            # Fallback to simple node listing from inspect
            nodes = self._parse_inspect_json(result.stdout)
            if not nodes:
                return ""
            lines = [f"当前运行中 Containerlab 实验节点 (共 {len(nodes)} 个):"]
            for n in nodes:
                lines.append(f"- {n.name}: 镜像={n.image}, IP={n.ipv4_address or 'N/A'}, 状态={n.state}")
            summary = "\n".join(lines)
            self._cached_topo_summary = summary
            return summary

        # 2. Read topology files (.state.clab.yaml and topology-data.json)
        dir_path = posixpath.dirname(lab_path)
        topo_data_file = posixpath.join(dir_path, "topology-data.json")
        topo_data = {}
        res_td = self.runner.run(f"cat '{topo_data_file}'", sudo=True)
        if res_td.exit_code == 0:
            try:
                topo_data = json.loads(res_td.stdout)
            except Exception:
                pass

        state_yaml = {}
        res_sy = self.runner.run(f"cat '{lab_path}'", sudo=True)
        if res_sy.exit_code == 0:
            try:
                state_yaml = yaml.safe_load(res_sy.stdout)
            except Exception:
                pass

        lab_name = topo_data.get("name") or self.lab_name or posixpath.basename(dir_path).replace("clab-", "")
        self.lab_name = lab_name
        topo_nodes = state_yaml.get("topology", {}).get("nodes", {})
        topo_links = state_yaml.get("topology", {}).get("links", [])

        summary_lines = [
            f"当前运行中 Containerlab 实验名称: {lab_name}",
            f"网络拓扑类型: 5-Stage CLOS (Folded Clos) 数据中心网络" if ("clos" in lab_name.lower() or any("leaf" in k for k in topo_nodes)) else f"网络拓扑名称: {lab_name}",
            f"节点规模: 共 {len(topo_nodes)} 个节点",
            f"链路规模: 共 {len(topo_links)} 条互联链路\n",
            "【分层架构与节点角色规划】:",
        ]

        # Group nodes (servers, leaf, spine, superspine, monitor/other)
        groups: dict[str, list] = {}
        for n_name, n_conf in topo_nodes.items():
            grp = n_conf.get("group", "other")
            groups.setdefault(grp, []).append((n_name, n_conf))

        order = ["server", "leaf", "spine", "superspine", "other"]
        sorted_grps = sorted(groups.keys(), key=lambda g: order.index(g) if g in order else 99)

        for grp in sorted_grps:
            items = groups[grp]
            summary_lines.append(f"\n- 【{grp.upper()} 层】({len(items)} 个节点):")
            for n_name, n_conf in items:
                img = n_conf.get("image", "")
                env = n_conf.get("env", {})
                exec_cmds = n_conf.get("exec", [])
                details = []
                if "LOCAL_AS" in env:
                    details.append(f"BGP AS: {env['LOCAL_AS']}")
                if "HOSTNET" in env:
                    details.append(f"业务网段: {env['HOSTNET']}")
                if "NEIGHBORS" in env:
                    details.append(f"BGP邻居端口: {env['NEIGHBORS']}")
                for c in exec_cmds:
                    if "ip addr add" in c and "172." in c:
                        details.append(f"IP: {c.split()[3]}")
                    elif "ip route add" in c and "via" in c:
                        parts = c.split()
                        details.append(f"默认路由: {parts[3]} via {parts[5]}")
                desc = f"  * {n_name} ({img})"
                if details:
                    desc += f": {', '.join(details)}"
                summary_lines.append(desc)

        if topo_links:
            summary_lines.append(f"\n【物理/虚拟链路互联】({len(topo_links)} 条链路):")
            for link in topo_links:
                eps = link.get("endpoints", [])
                if len(eps) == 2:
                    if isinstance(eps[0], dict):
                        a = f"{eps[0].get('node')}:{eps[0].get('interface')}"
                        b = f"{eps[1].get('node')}:{eps[1].get('interface')}"
                    else:
                        a, b = str(eps[0]), str(eps[1])
                    summary_lines.append(f"  * {a} <--> {b}")

        summary_lines.append(
            "\n【底层控制平面与路由协议设计】:\n"
            "- 底层 Underlay 路由协议: eBGP Unnumbered (RFC 5549 / RFC 8950), 基于 IPv6 Link-Local 邻居与 Extended Next-Hop 机制交换 IPv4 路由前缀。\n"
            "- 自治系统规划: 私有 AS (Leaf 独占 65001~65004, Spine Pod 共享 65005/65006, Superspine 共享 65007)。\n"
            "- 流量工程与高可用: 多级 ECMP 等价多路径负载均衡，双上行防单点故障无阻塞 CLOS 架构。"
        )

        full_summary = "\n".join(summary_lines)
        self._cached_topo_summary = full_summary
        return full_summary
