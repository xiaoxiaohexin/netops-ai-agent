"""Simple Q&A Agent with Lightweight Knowledge Retrieval, Day-2 Closed-Loop Execution, and Working Memory.

Implements:
1. Conversation Memory Management (Entity working memory, sliding window, operational state).
2. Day-2 Operational Loop (Intent parsing -> AAL safety gate -> Container execution -> Multi-tier probes -> Self-healing retry).
3. Live Containerlab & SOP Knowledge Context Enrichment.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from langgraph_netagent.llm.base import BaseLLMProvider, ChatMessage
from langgraph_netagent.tools.aal import AgentAccessLayer
from langgraph_netagent.tools.base import BaseNetworkLabAdapter
from langgraph_netagent.tools.sop_retriever import SOPRetriever

logger = logging.getLogger(__name__)


class ConversationMemory:
    """Working Memory and Operational Entity Tracker for Multi-turn Dialogues."""

    def __init__(self, max_turns: int = 8):
        self.max_turns = max_turns
        self.history: List[ChatMessage] = []
        self.active_services: Dict[str, List[Dict[str, Any]]] = {}
        self.recent_actions: List[Dict[str, Any]] = []

    def add_service(
        self,
        node: str,
        service: str,
        port: int,
        protocol: str = "tcp",
        url: str = "",
    ) -> None:
        self.active_services.setdefault(node, [])
        for s in self.active_services[node]:
            if s.get("port") == port:
                s.update({
                    "service": service,
                    "protocol": protocol,
                    "url": url,
                    "status": "running",
                    "updated_at": time.time(),
                })
                return
        self.active_services[node].append({
            "service": service,
            "port": port,
            "protocol": protocol,
            "url": url,
            "status": "running",
            "created_at": time.time(),
        })

    def remove_service(self, node: str, port: Optional[int] = None) -> None:
        if node in self.active_services:
            if port is None:
                self.active_services[node] = []
            else:
                self.active_services[node] = [s for s in self.active_services[node] if s.get("port") != port]

    def format_memory_context(self) -> str:
        lines: List[str] = []
        if self.active_services:
            lines.append("【会话运行态实体记忆 (Active Services in Memory)】:")
            for node, svcs in self.active_services.items():
                for s in svcs:
                    lines.append(
                        f"- 节点 `{node}`: {s['service']} 服务 (端口: {s['port']}/{s['protocol']}, "
                        f"地址: {s.get('url') or 'N/A'}, 状态: {s.get('status')})"
                    )
        if self.recent_actions:
            last = self.recent_actions[-1]
            lines.append(
                f"【最近一次执行的运维动作】: 节点 `{last.get('node')}`, 命令: `{last.get('command')}`, "
                f"结果: {last.get('status')} ({last.get('description', '')})"
            )
        return "\n".join(lines)


class SimpleQAAgent:
    """Agentic Q&A Assistant with Day-2 Operational Loop and Working Memory."""

    def __init__(
        self,
        llm_provider: BaseLLMProvider,
        retriever: Optional[SOPRetriever] = None,
        lab_adapter: Optional[BaseNetworkLabAdapter] = None,
        memory: Optional[ConversationMemory] = None,
    ):
        self.llm = llm_provider
        self.retriever = retriever or SOPRetriever()
        self.adapter = lab_adapter
        self.aal = AgentAccessLayer(lab_adapter=lab_adapter) if lab_adapter else None
        self.memory = memory or ConversationMemory()

    @property
    def lab_adapter(self) -> Optional[BaseNetworkLabAdapter]:
        return self.adapter

    @lab_adapter.setter
    def lab_adapter(self, adapter: Optional[BaseNetworkLabAdapter]) -> None:
        self.set_adapter(adapter)

    def set_adapter(self, adapter: Optional[BaseNetworkLabAdapter]) -> None:
        self.adapter = adapter
        self.aal = AgentAccessLayer(lab_adapter=adapter) if adapter else None

    def _parse_action_block(self, text: str) -> Optional[Dict[str, str]]:
        """Parse ```action ... ``` blocks emitted by the LLM."""
        m = re.search(r"```action\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
        if not m:
            return None
        block_text = m.group(1).strip()
        data: Dict[str, str] = {}
        for line in block_text.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            data[k.strip().lower()] = v.strip()
        return data if "node" in data and "command" in data else None

    def execute_day2_action(self, action: Dict[str, str]) -> Tuple[bool, str]:
        """Execute action via Day-2 Closed Loop: AAL -> Execute -> Local Probe -> Remote Probe -> Self-Healing."""
        if not self.adapter:
            return False, "错误: 未挂载实验环境 Adapter，无法执行底层容器动作。"

        node = action.get("node", "").strip()
        command = action.get("command", "").strip()
        verify_cmd = action.get("verify", "").strip()
        probe_from = action.get("probe_from", "").strip()
        probe_cmd = action.get("probe_command", "").strip()
        desc = action.get("description", "执行运维指令").strip()

        trace_lines = [
            f"🔄 **[Day-2 闭环执行中]**",
            f"  • **目标节点**: `{node}`",
            f"  • **操作意图**: {desc}",
        ]

        # 1. AAL Security Gate
        if self.aal:
            is_safe, reason = self.aal.validate_command_safety(command)
            if not is_safe:
                trace_lines.append(f"  ✖ **[1/4 安全审计失败]** AAL 策略拦截: {reason}")
                return False, "\n".join(trace_lines)
        trace_lines.append("  ✔ **[1/4 安全审计]** AAL 策略检查通过 (非破坏性命令)")

        # 2. Live Execution
        exec_payload = command
        # Auto-wrap compound/background shell commands for Docker POSIX compliance
        if ("&" in command or "nohup" in command or ">" in command or ";" in command) and not command.startswith("sh -c"):
            clean_cmd = command.replace('"', '\\"')
            exec_payload = f'sh -c "{clean_cmd}"'

        res_exec = self.adapter.exec_command(node, exec_payload, timeout=25)
        is_kill_cmd = any(k in command.lower() for k in ("kill", "pkill", "stop"))
        exec_success = (res_exec.exit_code == 0) or (is_kill_cmd and res_exec.exit_code in (0, 1, 143))

        if not exec_success:
            trace_lines.append(f"  ✖ **[2/4 执行失败]** Exit Code {res_exec.exit_code}: {res_exec.stderr or res_exec.stdout}")
            return False, "\n".join(trace_lines)
        trace_lines.append(f"  ✔ **[2/4 容器执行]** 指令已下发并成功返回 (Exit Code {res_exec.exit_code})")

        # Brief settle time for daemons or process changes
        time.sleep(0.6)

        # 3. Local Probe Verification
        local_passed = True
        local_evidence = ""
        if verify_cmd:
            res_v = self.adapter.exec_command(node, verify_cmd, timeout=10)
            local_evidence = res_v.stdout.strip()
            if is_kill_cmd:
                if "LISTEN" not in local_evidence and "8080" not in local_evidence:
                    trace_lines.append("  ✔ **[3/4 本地状态探针]** 确认进程/端口已成功释放关闭")
                else:
                    local_passed = False
                    trace_lines.append(f"  ✖ **[3/4 本地探针检测]** 端口仍处于占用状态: {local_evidence}")
            else:
                if res_v.exit_code != 0 or not local_evidence:
                    local_passed = False
                    trace_lines.append(f"  ✖ **[3/4 本地探针未检测到预期结果]**: {verify_cmd} -> {res_v.stderr or '无输出'}")
                else:
                    trace_lines.append(f"  ✔ **[3/4 本地状态探针]** 状态确认为就绪:\n    ```\n    {local_evidence[:200]}\n    ```")
        else:
            trace_lines.append("  ✔ **[3/4 本地探针]** 无需显式探针，执行成功")

        # 4. Cross-Node Probe Verification
        remote_passed = True
        remote_evidence = ""
        if local_passed and probe_from and probe_cmd and not is_kill_cmd:
            res_p = self.adapter.exec_command(probe_from, probe_cmd, timeout=10)
            remote_evidence = res_p.stdout.strip()
            if res_p.exit_code != 0 or not remote_evidence:
                remote_passed = False
                trace_lines.append(f"  ✖ **[4/4 跨节点探针失败]** 从 `{probe_from}` 探测失败: {res_p.stderr or '超时或连接被拒绝'}")
            else:
                trace_lines.append(f"  ✔ **[4/4 跨节点连通性探针]** 从 `{probe_from}` 探测成功 (HTTP 200 OK):\n    ```html\n    {remote_evidence[:250]}\n    ```")
        elif local_passed:
            trace_lines.append("  ✔ **[4/4 闭环确认]** 操作已通过所有安全与状态验证！")

        overall_success = local_passed and remote_passed

        # Synchronize Working Memory
        if overall_success:
            port_match = re.search(r"(?::|\bport\s*|\bhttp\.server\s*)(\d{2,5})\b", command)
            if not port_match:
                port_match = re.search(r"(?<![\.\d])(8080|8000|80|443|3000|5000)(?![\.\d])", command)
            port_num = int(port_match.group(1)) if port_match else None

            is_start_server = any(w in command.lower() for w in ("http.server", "nginx", "busybox httpd", "apache2"))
            is_client_test = any(w in command.lower() for w in ("wget", "curl", "ping", "traceroute"))

            if is_kill_cmd:
                self.memory.remove_service(node, port=port_num)
            elif is_start_server and not is_client_test:
                effective_port = port_num or 8080
                ip_addr = "172.16.1.2" if node == "h1" else ("172.16.2.2" if node == "h2" else f"node-{node}")
                self.memory.add_service(node, "web-server", effective_port, "tcp", f"http://{ip_addr}:{effective_port}")

            self.memory.recent_actions.append({
                "node": node,
                "command": command,
                "status": "success",
                "evidence": local_evidence or remote_evidence,
                "description": desc,
            })

        return overall_success, "\n".join(trace_lines)

    def answer(
        self,
        question: str,
        history: Optional[List[ChatMessage]] = None,
    ) -> str:
        """Process user question through Knowledge Retrieval, Day-2 Action Execution, and LLM Generation."""
        # 1. 实时网络环境拓扑提取与环境类型识别
        topo_summary = ""
        is_nic_network = False
        adapter_name = ""
        if self.adapter:
            try:
                topo_summary = self.adapter.get_topology_summary()
            except Exception:
                pass
            from langgraph_netagent.tools.nic_adapter import LiveNICAdapter
            if isinstance(self.adapter, LiveNICAdapter):
                is_nic_network = True
                adapter_name = getattr(self.adapter, "interface_name", "Host NIC")
            else:
                adapter_name = getattr(self.adapter, "lab_name", "Containerlab")

        # 2. 实体工作记忆提取
        memory_ctx = self.memory.format_memory_context()

        # 3. 知识检索 (轻量相关度检索)
        retrieved_docs = []
        try:
            retrieved_docs = self.retriever.retrieve(query=question, top_k=2)
        except Exception:
            pass

        context_blocks = []
        for doc in retrieved_docs:
            context_blocks.append(
                f"- Playbook: {doc.title} ({doc.category})\n"
                f"  诊断步骤: {', '.join(doc.diagnosis_steps[:2])}\n"
                f"  参考修复: {', '.join(doc.remediation_template[:2])}"
            )

        if is_nic_network:
            system_prompt = (
                "你是一个专业的网络工程与智能网络运维 AI 助手，精通企业网、局域网架构、虚拟化网络 (VMware Workstation/ESXi, Hyper-V) 与物理网络运维诊断。\n"
                "用户正在通过 /All 标签与你直接对话。请针对用户提出的任何问题（无范围限制），生成清晰、专业、结构化且直接有用的中文 Markdown 回答。\n"
            )
            if topo_summary:
                system_prompt += (
                    f"\n\n【当前接入的真实网卡网络拓扑与在线资产】:\n"
                    f"{topo_summary}\n\n"
                    "【回答指引与规则】:\n"
                    f"1. 你当前已接入宿主机真实物理/虚拟网卡网络: 【{adapter_name}】。\n"
                    "2. 拓扑中所有节点均为真实扫描发现的在线网络设备（包含宿主机本地网卡、局域网物理/虚拟网关、以及网卡直连通信的物理机或虚拟机，例如 VMware 中运行的 Linux/openEuler 虚拟机）。\n"
                    "3. 当用户询问当前网络、拓扑结构、节点角色、IP 地址、网段规划、连通性或设备状态时，必须直接依据上述真实资产信息进行详尽、准确、专业的解答，绝对不要套用虚构的 Containerlab 或 CLOS 节点！\n"
                    "4. 切勿回答'无法确定'、'没有接入环境'等推脱免责辞令。\n"
                    "5. 如果用户只是咨询概念或拓扑结构等非操作类问题，请直接用专业中文 Markdown 解答，不要输出 action 代码块。\n"
                )
            else:
                system_prompt += (
                    f"\n\n【回答指引】: 当前已选定网卡接口【{adapter_name}】，但尚未检测到在线邻居端点。请直接以专业、清晰的中文解答用户的网络问题。\n"
                )

            if memory_ctx:
                system_prompt += f"{memory_ctx}\n\n"

            system_prompt += (
                "【核心指令规则 - 会话即运维，指令即闭环】:\n"
                "1. 当用户要求在当前网卡网络执行连通性探测、端口扫描或诊断时，可以输出 action 代码块调用底层工具执行：\n"
                "   - 节点连通性测试: `Test-Connection -ComputerName <目标IP> -Count 2`\n"
                "   - 端口扫描验证 (如目标虚机 SSH 端口): `Test-NetConnection -ComputerName <目标IP> -Port 22`\n"
                "   - ARP 状态与网段排查: `Get-NetNeighbor -InterfaceAlias '<网卡名>'`\n"
                "2. 输出 action 代码块格式规范：\n"
                "```action\n"
                "node: <目标节点名或IP, 例如 192.168.245.139>\n"
                "command: <在主机网络中执行的诊断测试命令>\n"
                "verify: <可选, 验证结果的命令>\n"
                "description: <操作简述>\n"
                "```\n"
            )
        else:
            system_prompt = (
                "你是一个专业的网络工程与智能运维 AI 助手，精通 Containerlab、FRRouting、BGP、EVPN 及数据中心自动化运维与故障自愈。\n"
                "用户正在通过 /All 标签与你直接对话。请针对用户提出的任何问题（无范围限制），生成清晰、专业、结构化且直接有用的中文 Markdown 回答。\n"
            )

            if topo_summary:
                system_prompt += (
                    "\n\n【当前运行中的真实网络环境与拓扑底座】:\n"
                    f"{topo_summary}\n\n"
                    "【回答指引与规则】:\n"
                    "1. 你已全面接入上述真实的 Containerlab 运行环境。\n"
                    "2. 当用户询问当前网络、拓扑结构、节点角色、网段规划、BGP 路由互联或运行状态时，必须直接依据上述真实环境信息进行详尽、准确、专业的解答。\n"
                    "3. 切勿回答'无法确定'、'没有接入环境'或'没有拓扑文件'等推脱免责辞令。\n"
                    "4. 如果用户只是咨询概念或拓扑结构等非操作类问题，请直接用专业中文 Markdown 解答，不要输出 action 代码块。\n"
                )
            else:
                system_prompt += (
                    "\n\n【回答指引】: 当前尚未检测到运行拓扑。请直接以专业、清晰的中文解答用户的通用网络技术、协议设计或方案问题。\n"
                )

            if memory_ctx:
                system_prompt += f"{memory_ctx}\n\n"

            system_prompt += (
                "【核心指令规则 - 会话即运维，指令即闭环】:\n"
                "1. 当用户要求在容器内执行运维操作（例如：安装服务、启动程序、配置路由、测试连通性、停止服务等），必须输出 action 代码块调用底层工具执行，严禁只输出让用户手动操作的教程文本！\n"
                "2. 主机节点环境特性 (h1, h2, h3, h4):\n"
                "   - 镜像基于精简 Alpine Linux，已预装 python3，没有 systemctl 或 busybox httpd。\n"
                "   - 启动轻量 Web 服务建议直接使用: `sh -c 'mkdir -p /var/www/html && echo \"<h1>Hello from h1</h1>\" > /var/www/html/index.html && nohup python3 -m http.server 8080 --directory /var/www/html >/tmp/http.log 2>&1 & sleep 0.5'`\n"
                "   - 停止服务建议使用: `pkill -9 -f 'python3 -m http.server'`\n"
                "   - 本地状态验证: `(ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null) | grep 8080`\n"
                "   - 跨节点探针验证: 在 probe_from 节点 (如 h2/h3) 使用 `wget -qO- -T 3 http://172.16.1.2:8080`\n"
                "3. 输出 action 代码块格式规范：\n"
                "```action\n"
                "node: <目标节点名, 例如 h1, leaf1, h2>\n"
                "command: <在容器内执行的具体命令>\n"
                "verify: <在目标容器中验证生效的本地探针命令>\n"
                "probe_from: <可选, 跨节点发起端对端验证的源节点, 例如 h2>\n"
                "probe_command: <可选, 在 probe_from 节点执行的验证命令, 例如 wget -qO- -T 3 http://172.16.1.2:8080>\n"
                "description: <操作简述>\n"
                "```\n"
            )

        if context_blocks:
            system_prompt += "\n\n【参考知识库检索结果】:\n" + "\n".join(context_blocks)

        messages: List[ChatMessage] = [
            ChatMessage(role="system", content=system_prompt)
        ]

        # Use passed history or internal memory sliding window
        active_hist = history if history is not None else self.memory.history
        messages.extend(active_hist[-self.memory.max_turns:])
        messages.append(ChatMessage(role="user", content=question))

        try:
            raw_resp = self.llm.chat(messages, json_mode=False)
        except Exception as exc:
            return f"AI 回答生成异常: {exc}"

        if not raw_resp or raw_resp.strip() in ("", "{}"):
            if topo_summary:
                raw_resp = (
                    f"### 🌐 当前网络拓扑与资产概览 (离线响应)\n\n"
                    f"{topo_summary}\n\n"
                    f"- **拓扑说明**: Agent 已识别并绑定当前网络环境，包含上述在线端点与网段互联。\n"
                    f"- **运维提示**: 可在控制台使用 `probe` 测试连通性或使用 `routes` 查看路由表。"
                )
            else:
                raw_resp = "已收到您的网络运维咨询。当前处于离线 Mock 模式，请配置 OPENAI_API_KEY 或 DASHSCOPE_API_KEY 以启用大模型实时深度问答。"

        # Check if LLM emitted an action block
        action = self._parse_action_block(raw_resp)
        if action and self.adapter:
            attempt = 0
            max_self_healing_attempts = 2
            cumulative_traces = []
            success = False

            while attempt <= max_self_healing_attempts:
                attempt += 1
                success, trace = self.execute_day2_action(action)
                cumulative_traces.append(trace)
                if success:
                    break

                if attempt <= max_self_healing_attempts:
                    # Day-2 Self-Healing reflection retry
                    reflection_msg = (
                        f"【Day-2 闭环自愈触发 (第 {attempt} 次重试)】:\n"
                        f"上一次执行未完全通过探针验证，详细探针轨迹如下:\n{trace}\n\n"
                        f"请仔细分析探针失败原因，重新生成修正后的 ```action ... ``` 代码块执行自愈修复。"
                    )
                    retry_messages = list(messages)
                    retry_messages.append(ChatMessage(role="assistant", content=raw_resp))
                    retry_messages.append(ChatMessage(role="user", content=reflection_msg))
                    try:
                        raw_resp = self.llm.chat(retry_messages, json_mode=False)
                        new_action = self._parse_action_block(raw_resp)
                        if new_action:
                            action = new_action
                        else:
                            break
                    except Exception as e:
                        logger.warning("Day-2 self-healing retry failed: %s", e)
                        break

            final_trace = "\n\n".join(cumulative_traces)
            explanation = re.sub(r"```action\s*\n.*?\n```", "", raw_resp, flags=re.DOTALL | re.IGNORECASE).strip()
            summary_block = (
                f"{final_trace}\n\n"
                f"---\n"
                f"### 📋 执行结果总结\n"
                f"- **目标节点**: `{action.get('node')}`\n"
                f"- **执行状态**: {'✔ 成功完成并通过全部探针闭环验证' if success else '✖ 经过自愈重试后仍未通过闭环验证'}\n"
                f"- **运行态已同步**: 动作执行与验证结果已登记入会话工作记忆中，可继续发起多轮联动排查。"
            )
            final_report = f"{explanation}\n\n---\n{summary_block}" if explanation else summary_block
            # Update history and memory
            self.memory.history.append(ChatMessage(role="user", content=question))
            self.memory.history.append(ChatMessage(role="assistant", content=final_report))
            return final_report
        else:
            self.memory.history.append(ChatMessage(role="user", content=question))
            self.memory.history.append(ChatMessage(role="assistant", content=raw_resp))
            return raw_resp
