"""Interactive Command-Line REPL Console for NetOps AI Agent.

Provides an interactive shell for operators to inspect live Containerlab nodes,
run active ping probes, inject test faults, query routing tables, and run the
Day-2 LangGraph self-healing Agent with human-in-the-loop approval.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import sys
from typing import Any, Dict, List, Optional

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from langgraph_netagent.llm.base import ChatMessage, LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.llm.providers.qwen_openai import QwenOpenAIProvider
from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
from langgraph_netagent.tools.detector import EnvironmentDetector, ExecutionMode
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
from langgraph_netagent.workflow.day2_graph import run_day2_workflow
from langgraph_netagent.workflow.qa_agent import SimpleQAAgent


# ANSI color helpers
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_RED = "\033[31m"
C_CYAN = "\033[36m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"


def print_banner(mode: str, distro: Optional[str]) -> None:
    """Print welcoming banner."""
    print(f"\n{C_CYAN}{C_BOLD}{'=' * 75}{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}       _   _      _   ____              _    ___    _       {C_RESET}")
    print(f"{C_CYAN}{C_BOLD}      | \\ | | ___| |_/ __ \\ _ __  ___   / \\  |_ _|  / \\      {C_RESET}")
    print(f"{C_BLUE}{C_BOLD}      |  \\| |/ _ \\ __/ / / / '_ \\/ __| / _ \\  | |  / _ \\     {C_RESET}")
    print(f"{C_BLUE}{C_BOLD}      | |\\  |  __/ || /_/ /| |_) \\__ \\/ ___ \\ | | / ___ \\    {C_RESET}")
    print(f"{C_BLUE}{C_BOLD}      |_| \\_|\\___|\\__\\____/ | .__/|___/_/   \\_\\___/_/   \\_\\   {C_RESET}")
    print(f"{C_BLUE}{C_BOLD}                            |_|                              {C_RESET}")
    print(f"{C_YELLOW}{C_BOLD}          >> 智能网络运维 Agent 交互式控制台 (Containerlab) <<{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}{'=' * 75}{C_RESET}")
    print(f"{C_DIM}环境底座: {C_BOLD}{mode.upper()}{C_RESET}{C_DIM} (WSL Distro: {distro or 'native'}){C_RESET}")
    print(f"{C_DIM}输入 {C_CYAN}help{C_RESET}{C_DIM} 或 {C_CYAN}?{C_RESET}{C_DIM} 查看可用指令，输入 {C_CYAN}exit{C_RESET}{C_DIM} 退出。{C_RESET}\n")


def print_help() -> None:
    """Print available interactive commands."""
    print(f"""
{C_BOLD}可用交互指令列表:{C_RESET}
  {C_CYAN}/All <问题>{C_RESET} (或 {C_CYAN}/all{C_RESET})          : 直接与 AI 智能助手自由问答 (无范围限制)
  {C_CYAN}0. scan{C_RESET} (或 {C_CYAN}networks{C_RESET}, {C_CYAN}topo{C_RESET}) : 扫描所有网卡/容器/内存拓扑并支持手动交互切换
  {C_CYAN}use <lab_name>{C_RESET}               : 切换 Agent 当前绑定的网络实验拓扑 (如: use clos5)
  {C_CYAN}1. inspect{C_RESET} (或 {C_CYAN}status{C_RESET})       : 探测当前绑定的 Containerlab 容器与管理 IP
  {C_CYAN}2. probe{C_RESET} (或 {C_CYAN}ping{C_RESET})           : 对网络节点执行连通性与丢包率探针矩阵
  {C_CYAN}3. routes{C_RESET}                    : 抓取并打印路由器与主机的核心路由表
  {C_CYAN}4. diagnose{C_RESET} (或 {C_CYAN}heal{C_RESET})         : 启动 LangGraph Day-2 自动排障诊断与热修复闭环
  {C_CYAN}5. exec <node> <command>{C_RESET}     : 在指定容器内直接执行命令 (如: exec leaf1 vtysh -c 'show ip route')
  {C_CYAN}6. fault inject <type>{C_RESET}       : 注入模拟故障用于演练测试 (iface-down / bgp-down / missing-route / recover)
  {C_CYAN}7. deploy <clab_yaml>{C_RESET}        : 部署新的 Containerlab 实验拓扑
  {C_CYAN}8. destroy [name]{C_RESET}            : 销毁并清理指定的 Containerlab 实验
  {C_CYAN}help{C_RESET} / {C_CYAN}?{C_RESET}                     : 显示本帮助菜单
  {C_CYAN}exit{C_RESET} / {C_CYAN}quit{C_RESET}                  : 退出控制台
""")


class InteractiveNetOpsREPL:
    """Interactive shell session controller."""

    def __init__(
        self,
        mode: str = "auto",
        provider: str = "mock",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        lab_name: Optional[str] = None,
        base_url: Optional[str] = None,
    ):
        # Auto-load .env if present
        if not os.environ.get("OPENAI_API_KEY") and not os.environ.get("DASHSCOPE_API_KEY"):
            try:
                from dotenv import load_dotenv
                for candidate in [
                    Path.cwd() / ".env",
                    Path(__file__).resolve().parent / ".env",
                    Path(__file__).resolve().parent.parent / ".env",
                    Path(__file__).resolve().parent.parent.parent / ".env",
                ]:
                    if candidate.exists():
                        load_dotenv(candidate)
                        break
            except Exception:
                pass

        self.detector = EnvironmentDetector()
        caps = self.detector.detect()
        if mode == "auto":
            self.mode = "live" if caps.resolved_mode == ExecutionMode.LIVE else "mock"
        else:
            self.mode = mode

        self.wsl_distro = caps.wsl_distro
        self.lab_name = lab_name

        # Setup adapter
        if self.mode == "live":
            self.adapter = LiveContainerlabAdapter(lab_name=lab_name, wsl_distro=self.wsl_distro)
        else:
            self.adapter = MockContainerlabAdapter()

        # Setup LLM Provider
        if provider == "mock" and (os.environ.get("OPENAI_API_KEY") or os.environ.get("DASHSCOPE_API_KEY")):
            provider = "openai"

        if provider in ("qwen", "openai"):
            key = api_key or os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("OPENAI_API_KEY")
            effective_model = model or os.environ.get("OPENAI_MODEL") or os.environ.get("QWEN_MODEL") or "qwen-max"
            effective_base_url = base_url or os.environ.get("OPENAI_BASE_URL")
            config = LLMConfig(provider_type="openai", model_name=effective_model, api_key=key, base_url=effective_base_url)
            self.llm = QwenOpenAIProvider(config=config)
        else:
            self.llm = MockLLMProvider()

        # Setup Q&A Agent with live lab adapter
        self.qa_agent = SimpleQAAgent(llm_provider=self.llm, lab_adapter=self.adapter)

    def run(self) -> None:
        """Main REPL loop."""
        print_banner(mode=self.mode, distro=self.wsl_distro)
        if not self.lab_name:
            self.do_scan_networks(prompt_select=True)
        else:
            self.do_inspect()

        while True:
            try:
                line = input(f"{C_BOLD}{C_GREEN}NetOps-Agent>{C_RESET} ").strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{C_DIM}已退出控制台。{C_RESET}")
                break

            if not line:
                continue

            # Direct AI Conversation via /All or /all
            if line.lower().startswith("/all") or (line.lower().startswith("all ") or line.lower() == "all"):
                if line.lower().startswith("/all"):
                    q = line[4:].strip().lstrip(":").strip()
                else:
                    q = line[3:].strip().lstrip(":").strip()
                if q:
                    self.do_qa(q)
                else:
                    self.start_qa_session()
                continue

            parts = shlex.split(line)
            cmd = parts[0].lower()

            if cmd in ("exit", "quit", "q"):
                print(f"{C_DIM}已退出控制台。再见！{C_RESET}")
                break
            elif cmd in ("0", "scan", "networks", "topo"):
                self.do_scan_networks(prompt_select=True)
            elif cmd in ("use", "select"):
                if len(parts) < 2:
                    print(f"{C_YELLOW}用法: use <lab_name 或 序号>{C_RESET} (例如: use clos5 或 use 1)")
                else:
                    self.do_use(parts[1])
            elif cmd in ("1", "inspect", "status"):
                self.do_inspect()
            elif cmd in ("2", "probe", "ping"):
                self.do_probe()
            elif cmd in ("3", "routes"):
                self.do_routes()
            elif cmd in ("4", "diagnose", "heal"):
                self.do_diagnose()
            elif cmd in ("5", "exec"):
                if len(parts) < 3:
                    print(f"{C_YELLOW}用法: exec <node> <command>{C_RESET}")
                    print(f"示例: exec frr1 vtysh -c 'show ip route'")
                else:
                    target_node = parts[1]
                    idx = line.find(target_node)
                    if idx != -1:
                        target_cmd = line[idx + len(target_node):].strip()
                    else:
                        target_cmd = " ".join(parts[2:])
                    self.do_exec(target_node, target_cmd)
            elif cmd in ("6", "fault"):
                sub = parts[1] if len(parts) > 1 else "help"
                self.do_fault(sub)
            elif cmd in ("7", "deploy"):
                if len(parts) < 2:
                    print(f"{C_YELLOW}用法: deploy <topo_yaml_path>{C_RESET}")
                else:
                    self.do_deploy(parts[1])
            elif cmd in ("8", "destroy"):
                name = parts[1] if len(parts) > 1 else None
                self.do_destroy(name)
            else:
                print(f"{C_RED}未知指令: '{cmd}'。输入 'help' 查看所有可用指令。{C_RESET}")

    def do_scan_networks(self, prompt_select: bool = False) -> None:
        """Scan and list all detected interactive networks, containers, and NICs."""
        print(f"\n{C_CYAN}正在检索宿主机网卡、WSL 网桥与网络拓扑环境...{C_RESET}")
        inv = self.detector.scan_inventory(active_lab=self.lab_name)

        print(f"\n{C_BOLD}1. 宿主机真实网络适配器 (Windows Host NICs):{C_RESET}")
        if inv.host_interfaces:
            print(f"  {'网卡名称':<34} {'描述':<44} {'速率'}")
            print(f"  {'-' * 88}")
            for nic in inv.host_interfaces:
                print(f"  {nic.get('name', ''):<34} {nic.get('description', '')[:42]:<44} {nic.get('speed', '')}")
        else:
            print(f"  {C_DIM}(未检测到活跃网卡){C_RESET}")

        print(f"\n{C_BOLD}2. WSL 虚拟桥接与容器网卡 (WSL Linux Bridges & Virtual Interfaces):{C_RESET}")
        if inv.wsl_bridges:
            print(f"  {'网络接口/网桥':<34} {'状态':<10} {'绑定 IP 网段 / 角色'}")
            print(f"  {'-' * 88}")
            for br in inv.wsl_bridges:
                st_color = C_GREEN if br.get("state") == "UP" else C_DIM
                print(f"  {br.get('name', ''):<34} {st_color}{br.get('state', ''):<10}{C_RESET} {br.get('addrs', '')}")
        else:
            print(f"  {C_DIM}(未检测到 WSL 网桥){C_RESET}")

        print(f"\n{C_BOLD}3. 当前可接入的网络拓扑 (Available Network Topologies):{C_RESET}")
        print(f"  {'序号':<6} {'拓扑环境类型':<30} {'实验名称':<16} {'节点数':<8} {'详情与状态'}")
        print(f"  {'-' * 88}")
        for topo in inv.available_topologies:
            cur_mark = f" {C_GREEN}<- [当前绑定]{C_RESET}" if topo.name == self.lab_name else (
                f" {C_YELLOW}<- [推荐接入]{C_RESET}" if (not self.lab_name and topo.name == inv.recommended_lab) else ""
            )
            print(f"  [{topo.id}]    {topo.display_type:<26} {topo.name:<16} {topo.node_count:<8} {topo.summary}{cur_mark}")

        print(f"\n{C_DIM}提示: 输入 {C_CYAN}use <实验名称 或 序号>{C_RESET}{C_DIM} 即可人工选择接入对应网络。{C_RESET}\n")

        if prompt_select and sys.stdin.isatty():
            def_choice = self.lab_name or inv.recommended_lab or "1"
            try:
                choice = input(f"{C_BOLD}{C_YELLOW}请选择要接入的网络拓扑序号或名称 [默认: {def_choice}]: {C_RESET}").strip()
            except (KeyboardInterrupt, EOFError):
                choice = ""
            if not choice:
                choice = def_choice
            self.do_use(choice)

    def do_use(self, target: str) -> None:
        """Switch active lab or NIC network topology dynamically."""
        clean = target.strip()
        if clean.endswith(".yml") or clean.endswith(".yaml"):
            clean = Path(clean).stem

        # Query current dynamic topologies (No presets, real hardware discovery)
        inv = self.detector.scan_inventory(active_lab=self.lab_name)
        matched_topo = None

        # 1. Match by numeric ID (e.g. "1", "2", "3", "4"...)
        for t in inv.available_topologies:
            if clean == t.id:
                matched_topo = t
                break

        # 2. Match by exact or partial name
        if not matched_topo:
            for t in inv.available_topologies:
                if clean.lower() == t.name.lower():
                    matched_topo = t
                    break
        if not matched_topo:
            for t in inv.available_topologies:
                if clean.lower() in t.name.lower() or t.name.lower() in clean.lower():
                    matched_topo = t
                    break

        if matched_topo:
            self.lab_name = matched_topo.name
            if matched_topo.kind == "containerlab":
                self.adapter = LiveContainerlabAdapter(lab_name=matched_topo.name, wsl_distro=self.wsl_distro)
                self.mode = "live"
                print(f"{C_GREEN}已成功人工选择并接入 Containerlab 容器网络: {matched_topo.name}{C_RESET}\n")
            elif matched_topo.kind == "nic_network":
                self.adapter = LiveNICAdapter(interface_name=matched_topo.name)
                self.mode = "live"
                print(f"{C_GREEN}已成功人工选择并接入网卡网络: {matched_topo.name} ({matched_topo.display_type}){C_RESET}\n")
            elif matched_topo.kind == "in_memory":
                self.adapter = MockContainerlabAdapter()
                self.mode = "mock"
                print(f"{C_GREEN}已成功人工选择并切换至: {matched_topo.name} (内存虚拟仿真模式){C_RESET}\n")
            self.qa_agent.set_adapter(self.adapter)
            self.do_inspect()
            return

        # Fallback if unindexed
        self.lab_name = clean
        if any(k in clean.lower() for k in ("wlan", "eth", "net", "vmnet", "adapter", "meta")):
            self.adapter = LiveNICAdapter(interface_name=clean)
            self.mode = "live"
        else:
            self.adapter = LiveContainerlabAdapter(lab_name=clean, wsl_distro=self.wsl_distro)
        self.qa_agent.set_adapter(self.adapter)
        print(f"{C_GREEN}已将当前目标拓扑设置为: {self.lab_name}{C_RESET}\n")
        self.do_inspect()

    def do_inspect(self) -> None:
        """Inspect running lab containers or host NIC endpoints."""
        print(f"\n{C_CYAN}正在检查网络拓扑节点与通信端点状态...{C_RESET}")
        res = self.adapter.inspect(lab_name=self.lab_name)
        if (not res.success or not res.nodes) and self.lab_name and isinstance(self.adapter, LiveContainerlabAdapter):
            # Fallback to inspecting all labs
            res_all = self.adapter.inspect(lab_name=None)
            if res_all.success and res_all.nodes:
                res = res_all
                self.lab_name = res.lab_name
                print(f"{C_GREEN}自动发现并切换至运行中的实验: '{self.lab_name}'{C_RESET}")

        if not res.success or not res.nodes:
            print(f"{C_YELLOW}未检测到正在运行的实验节点或 inspect 失败: {res.error_message}{C_RESET}\n")
            return

        if not self.lab_name or self.lab_name == "unknown":
            self.lab_name = res.lab_name

        print(f"\n{C_BOLD}当前绑定网络拓扑: {C_GREEN}{self.lab_name}{C_RESET}")
        print(f"{C_BOLD}{'节点名称':<42} {'端点/容器 ID':<16} {'类型/镜像':<36} {'管理 IPv4':<18} {'状态'}{C_RESET}")
        print("-" * 120)
        for n in res.nodes:
            status_color = C_GREEN if n.state == "running" else C_RED
            name_disp = n.name if len(n.name) <= 40 else n.name[:37] + "..."
            img_disp = n.image if len(n.image) <= 34 else n.image[:31] + "..."
            print(f"{name_disp:<42} {n.container_id[:14]:<16} {img_disp:<36} {str(n.ipv4_address):<18} {status_color}{n.state}{C_RESET}")
        print()

    def do_probe(self) -> None:
        """Run connectivity probe matrix."""
        print(f"\n{C_CYAN}正在执行端到端连通性与丢包率探针...{C_RESET}")
        # Detect nodes
        insp = self.adapter.inspect(lab_name=self.lab_name)
        if not insp.nodes:
            print(f"{C_YELLOW}无运行中节点可供探测。{C_RESET}\n")
            return

        if isinstance(self.adapter, LiveNICAdapter):
            print(f"正在向接口 {self.lab_name} 上的活跃节点下发连通性探针...")
            for n in insp.nodes:
                raw_ip = (n.ipv4_address or "").split("/")[0]
                if not raw_ip or raw_ip.startswith("127.") or "本机" in n.name:
                    continue
                cmd = f"Test-Connection -ComputerName {raw_ip} -Count 2 -Quiet"
                ret = self.adapter.exec_command(node_name=n.name, command=cmd, timeout=4)
                is_ok = ("True" in ret.stdout)
                res_tag = f"{C_GREEN}[√] [通]{C_RESET}" if is_ok else f"{C_RED}[X] [断]{C_RESET}"
                extra = ""
                if is_ok and ("vm" in n.name.lower() or "linux" in n.image.lower()):
                    tcp_cmd = f"Test-NetConnection -ComputerName {raw_ip} -Port 22 -InformationLevel Quiet"
                    t_ret = self.adapter.exec_command(node_name=n.name, command=tcp_cmd, timeout=3)
                    ssh_ok = ("True" in t_ret.stdout)
                    extra = f" (SSH 端口 22: {'已开放/就绪' if ssh_ok else '未开放'})"
                print(f"  {res_tag} 本机网卡 -> {n.name} ({raw_ip}){extra}")
            print()
            return

        nodes = [n.name for n in insp.nodes]
        print(f"检测到 {len(nodes)} 个节点: {', '.join(nodes[:6])}{'...' if len(nodes)>6 else ''}")

        # Choose ping targets
        # Choose ping targets from live hosts
        ping_pairs = []
        host_nodes = [n for n in nodes if n in ("h1", "h2", "h3", "h4")]
        if len(host_nodes) >= 2:
            host_ips = {
                "h1": "172.16.1.2",
                "h2": "172.16.2.2",
                "h3": "172.16.3.2",
                "h4": "172.16.4.2",
            }
            if "h1" in host_nodes and "h2" in host_nodes:
                ping_pairs.append(("h1", host_ips.get("h2", "172.16.2.2")))
                ping_pairs.append(("h2", host_ips.get("h1", "172.16.1.2")))
            if "h3" in host_nodes and "h4" in host_nodes:
                ping_pairs.append(("h3", host_ips.get("h4", "172.16.4.2")))
                ping_pairs.append(("h4", host_ips.get("h3", "172.16.3.2")))
        elif len(nodes) >= 2:
            # Fallback across discovered nodes
            ping_pairs.append((nodes[0], "127.0.0.1"))

        for src, dst in ping_pairs:
            cmd = f"ping -c 2 -W 2 {dst}"
            ret = self.adapter.exec_command(node_name=src, command=cmd, timeout=5)
            if ret.success and " 0% packet loss" in ret.stdout:
                print(f"  {C_GREEN}[√] [通]{C_RESET} {src} -> {dst}: {C_GREEN}0% 丢包{C_RESET}")
            else:
                loss_hint = "100% 丢包" if ret.exit_code != 0 else "有丢包"
                print(f"  {C_RED}[X] [断]{C_RESET} {src} -> {dst}: {C_RED}{loss_hint}{C_RESET}")
        print()

    def do_routes(self) -> None:
        """Dump routing tables on routers or host NIC."""
        print(f"\n{C_CYAN}正在查询核心节点路由表...{C_RESET}")
        if isinstance(self.adapter, LiveNICAdapter):
            iface = self.lab_name or getattr(self.adapter, "interface_name", "Host NIC")
            cmd = f"Get-NetRoute -InterfaceAlias '{iface}' -AddressFamily IPv4 | Select-Object DestinationPrefix, NextHop, RouteMetric | Format-Table -AutoSize"
            res = self.adapter.exec_command(node_name="host", command=cmd, timeout=6)
            print(f"\n{C_BOLD}--- 网卡接口 [{iface}] 宿主机核心 IPv4 路由表 ---{C_RESET}")
            print(res.stdout.strip() if res.stdout else res.stderr)
            print()
            return

        insp = self.adapter.inspect(lab_name=self.lab_name)
        for n in insp.nodes:
            k = (n.kind or "").lower()
            img = (n.image or "").lower()
            if "frr" in k or "frr" in img:
                res = self.adapter.exec_command(node_name=n.name, command="vtysh -c 'show ip route'", timeout=5)
                print(f"\n{C_BOLD}--- FRR 节点 [{n.name}] 路由表 ---{C_RESET}")
                print(res.stdout.strip() if res.stdout else res.stderr)
            elif "srl" in k or "srlinux" in img:
                res = self.adapter.exec_command(node_name=n.name, command="sr_cli 'show network-instance default route-table'", timeout=5)
                print(f"\n{C_BOLD}--- SRL 节点 [{n.name}] 路由表 ---{C_RESET}")
                print(res.stdout.strip() if res.stdout else res.stderr)
        print()

    def do_diagnose(self) -> None:
        """Run Day-2 LangGraph self-healing Agent."""
        print(f"\n{C_BOLD}{C_CYAN}>>> 启动 LangGraph Day-2 网络运维诊断与自愈 Agent <<<{C_RESET}\n")
        target_lab = self.lab_name or getattr(self.adapter, "lab_name", None)
        if not target_lab:
            try:
                insp = self.adapter.inspect()
                target_lab = insp.lab_name if insp.lab_name and insp.lab_name != "unknown" else "clos5"
            except Exception:
                target_lab = "clos5"

        try:
            state = run_day2_workflow(
                llm_provider=self.llm,
                lab_adapter=self.adapter,
                lab_name=target_lab,
                max_retries=3,
                auto_approve=True,  # Auto-approve so it executes the patch and re-verifies
            )
            print(f"\n{C_BOLD}执行轨迹 (Execution Trace):{C_RESET}")
            for log in state.get("execution_logs", []):
                lvl = log.get("level", "info").upper()
                c = C_GREEN if lvl == "INFO" else (C_YELLOW if lvl == "WARNING" else C_RED)
                print(f"  {c}[{lvl:<7}]{C_RESET} [{log.get('stage')}] {log.get('message')}")

            status = state.get("status")
            print(f"\n{C_BOLD}诊断与自愈最终结果:{C_RESET} {C_GREEN if status in ('healthy', 'fixed') else C_RED}{status.upper()}{C_RESET}")
            if state.get("diagnostic_report"):
                diag = state["diagnostic_report"]
                print(f"  - 根因定位: {diag.get('root_cause')}")
                print(f"  - 嫌疑节点: {', '.join(diag.get('affected_nodes', []))}")
            if state.get("remediation_plan"):
                rem = state["remediation_plan"]
                print(f"  - 修复指令: {rem.get('exec_commands')}")
        except Exception as e:
            print(f"{C_RED}Agent 执行发生异常: {e}{C_RESET}")
        print()

    def do_exec(self, node: str, command: str) -> None:
        """Execute a direct command in a container."""
        print(f"{C_DIM}[执行] {node} -> {command}{C_RESET}")
        res = self.adapter.exec_command(node_name=node, command=command, timeout=15)
        if res.stdout:
            print(res.stdout.strip())
        if res.stderr:
            print(f"{C_YELLOW}{res.stderr.strip()}{C_RESET}")
        print()

    def do_fault(self, action: str) -> None:
        """Inject test faults into the running lab."""
        if action == "iface-down":
            print(f"{C_YELLOW}正在关闭 leaf1 连接主机 h1 的接入接口 eth3...{C_RESET}")
            cmd = "vtysh -c 'configure terminal' -c 'interface eth3' -c 'shutdown'"
            res = self.adapter.exec_command("leaf1", cmd)
            print(f"{C_GREEN}✔ 接口故障已注入！现在可以运行 'probe' 观察丢包，或运行 'diagnose' 让 Agent 自愈。{C_RESET}\n")
        elif action == "recover":
            print(f"{C_CYAN}正在恢复 leaf1 的接入接口 eth3...{C_RESET}")
            cmd = "vtysh -c 'configure terminal' -c 'interface eth3' -c 'no shutdown'"
            res = self.adapter.exec_command("leaf1", cmd)
            print(f"{C_GREEN}✔ 接口已恢复！运行 'probe' 验证连通性。{C_RESET}\n")
        elif action == "bgp-down":
            print(f"{C_YELLOW}正在关闭 leaf1 上行连接 spine1 的核心链路 eth1...{C_RESET}")
            cmd = "vtysh -c 'configure terminal' -c 'interface eth1' -c 'shutdown'"
            res = self.adapter.exec_command("leaf1", cmd)
            print(f"{C_GREEN}✔ 骨干链路已关闭！运行 'probe' 观察链路切换。{C_RESET}\n")
        elif action == "missing-route":
            print(f"{C_YELLOW}正在向 h1 注入故障: 删除到 172.16.0.0/16 的路由...{C_RESET}")
            cmd = "ip route del 172.16.0.0/16 via 172.16.1.1"
            res = self.adapter.exec_command("h1", cmd)
            print(f"{C_GREEN}✔ 路由已删除！现在可以运行 'probe' 观察丢包，或运行 'diagnose' 让 Agent 自愈。{C_RESET}\n")
        else:
            print(f"{C_YELLOW}可用故障注入模式:{C_RESET}")
            print("  fault iface-down     : 关闭 leaf1 的 eth3 接口 (造成 h1 接入断网)")
            print("  fault bgp-down       : 关闭 leaf1 的 eth1 接口 (造成 leaf1-spine1 骨干链路中断)")
            print("  fault recover        : 恢复 leaf1 的接入接口 eth3\n")

    def do_qa(self, question: str) -> None:
        """Process direct Q&A via the /All tag."""
        print(f"\n{C_BOLD}{C_CYAN}[AI 问答助手 (Q&A Agent) 正在思考...]{C_RESET}")
        ans = self.qa_agent.answer(question)
        print(f"\n{C_BOLD}AI 回复:{C_RESET}\n{ans}\n")

    def start_qa_session(self) -> None:
        """Interactive open-domain conversational session with the AI."""
        print(f"\n{C_BOLD}{C_CYAN}>>> 进入 AI 自由问答模式 (/All) <<<{C_RESET}")
        print(f"{C_DIM}你可以向 AI 咨询任何网络技术、Containerlab、排障方案或通用问题 (无范围限制)。{C_RESET}")
        print(f"{C_DIM}输入 'exit' 或 'q' 退出并返回主控制台。{C_RESET}\n")
        while True:
            try:
                q = input(f"{C_BOLD}{C_CYAN}AI-Chat>{C_RESET} ").strip()
            except (KeyboardInterrupt, EOFError):
                print()
                break
            if not q:
                continue
            if q.lower() in ("exit", "quit", "q", "/exit"):
                print(f"{C_DIM}已退出 AI 问答模式。{C_RESET}\n")
                break
            print(f"\n{C_DIM}AI 正在思考...{C_RESET}")
            ans = self.qa_agent.answer(q)
            print(f"\n{C_BOLD}AI 回复:{C_RESET}\n{ans}\n")

    def do_deploy(self, topo_path: str) -> None:
        """Deploy a topology."""
        print(f"{C_CYAN}正在调用 Containerlab 部署拓扑: {topo_path}...{C_RESET}")
        res = self.adapter.deploy(topo_file=topo_path)
        if res.success:
            print(f"{C_GREEN}✔ 部署成功！节点: {', '.join(res.nodes_deployed)}{C_RESET}\n")
        else:
            print(f"{C_RED}✖ 部署失败: {res.error_message}{C_RESET}\n")

    def do_destroy(self, name: Optional[str]) -> None:
        """Destroy a topology."""
        lab = name or self.lab_name
        if not lab:
            print(f"{C_YELLOW}用法: destroy <lab_name>{C_RESET}\n")
            return
        print(f"{C_YELLOW}正在销毁实验: {lab}...{C_RESET}")
        res = self.adapter.destroy(lab_name=lab)
        if res.success:
            print(f"{C_GREEN}✔ 实验已销毁清理。{C_RESET}\n")
        else:
            print(f"{C_RED}✖ 销毁失败: {res.error_message}{C_RESET}\n")


def start_repl(
    mode: str = "auto",
    provider: str = "mock",
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    lab_name: Optional[str] = None,
    base_url: Optional[str] = None,
) -> None:
    """Entrypoint function for starting interactive shell."""
    repl = InteractiveNetOpsREPL(
        mode=mode,
        provider=provider,
        model=model,
        api_key=api_key,
        lab_name=lab_name,
        base_url=base_url,
    )
    repl.run()


if __name__ == "__main__":
    start_repl()
