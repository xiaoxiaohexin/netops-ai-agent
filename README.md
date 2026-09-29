# NetOps AI Agent

> 自然语言驱动的网络运维智能体（LLM + LangGraph 状态机）：覆盖「意图解析 → 拓扑生成 → 离线预检 → Containerlab / 宿主机网卡部署 → 遥测探针 → 两阶段诊断 → 有界自治自愈」全生命周期闭环，并内置对抗性红队压测能力。

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Containerlab](https://img.shields.io/badge/Containerlab-Multi--Vendor-blueviolet.svg)](https://containerlab.dev/)

---

## ✨ 核心能力

- **意图驱动拓扑设计**：将自然语言需求翻译为严格校验过的 Pydantic 网络模型（`NetworkIntent`），自动生成多厂商 Containerlab 拓扑（Alpine Linux、FRRouting、Nokia SR Linux）。
- **离线预检闭环**：部署前执行语法 / IP 重叠 / 子网不匹配 / 链路端点校验，出错时自动回传错误信息驱动 LLM 迭代自纠。
- **遥测探针与自愈**：通过 `PingProbe` / `RouteTableProbe` / `InterfaceProbe` 采集实时网络健康，自动分析丢包与路由缺失，生成原子化 `RemediationPlan` 并打补丁、重部署、复测直至恢复。
- **有界自治（Day-1/2/3）**：AAL（Agent Access Layer）只读强制、Docker/Mock 沙箱预演、Canonical Intent 编译与逆序回滚、厂商知识库双路检索、HITL（Human-in-the-Loop）审批门。
- **统一 Harmonized 工作流**：`harmonized_graph` 统一 Day-1（发现/摄取）、Day-2（诊断）、Day-3（沙箱/执行）三阶段，并向后兼容旧版 Day-2 节点。
- **宿主机资产发现与交互式 REPL**：`EnvironmentDetector` 自动识别宿主机网卡 / WSL 网桥 / 在线拓扑，`LiveNICAdapter` 直接挂载真实网卡巡检，`netagent -it` 提供交互式运维控制台。
- **对抗性红队压测**：内置 MCP 攻击工具服务器、11 个 MITRE ATT&CK 对抗场景、10 轮实弹攻击与 Agent 反应实时监控。

---

## 🏗️ 架构总览

系统按生命周期分为三个阶段，由 `HarmonizedOperationalGraph` 统一编排：

| 阶段 | 职责 | 关键模块 |
|------|------|----------|
| **Day-1 发现与摄取** | 摄取在线网络基线、提取 IP/资产清单、摄取厂商文档（Cisco/Huawei/FRR/Linux），构建树状命令库与轻量向量索引 | `vendor_knowledge`, `sop_retriever`, `EnvironmentDetector` |
| **Day-2 认知诊断** | 连续遥测监控（`--watch`）、多维异常感知与五元组提取、两阶段诊断（只读观察 + 双路检索生成 Canonical Intent） | `operational_nodes`, `operational_state` |
| **Day-3 预演与执行** | 沙箱预演 → `PreflightSandboxPassReport` → HITL 审批 → 实弹热补丁 → 变更后复测 → 失败自动回滚 | `sandbox_runtime`, `intent_compiler`, `aal` |

安全护栏：AAL 白名单（违规返回 exit code 126）、单调 `step_tag` + 熔断器（`retry_count >= max_retries` 即熔断）、逆序回滚补偿命令。

---

## 📦 安装方式

本仓库已配置标准 Python 打包规范（PEP 517/518），支持多种安装与分发方式：

### 方式 1：通过 GitHub 一键在线安装（推荐）

```bash
pip install git+https://github.com/xiaoxiaohexin/netops-ai-agent.git
```

### 方式 2：本地可编辑安装

```bash
git clone https://github.com/xiaoxiaohexin/netops-ai-agent.git
cd netops-ai-agent
pip install -e .
```

### 方式 3：离线 Wheel 二进制包分发

```bash
# 离线或企业内网环境，直接安装已构建的 wheel
pip install dist/netops_ai_agent-0.1.0-py3-none-any.whl

# 或自行构建
python -m build
```

安装后自动注册全局命令 `netagent`。

---

## 🚀 CLI 命令行使用

```bash
# 1. 交互式运维 REPL（实时识别宿主机网卡与在线资产）
netagent -it

# 2. 扫描宿主机网卡 / WSL 网桥 / 在线拓扑并打印资产报告
netagent --scan

# 3. 纯内存虚拟拓扑极速验证（Mock 模式，零 Docker）
netagent --harmonized --mode mock

# 4. 真实 Containerlab 网络闭环运维
netagent --harmonized --mode live --lab-name clos5

# 5. 真实环境持续监控自愈（每 5 秒一轮，最多 10 轮）
netagent --mode live --watch --watch-interval 5 --max-watch-cycles 10

# 6. 指定大模型后端
netagent --provider qwen --model qwen-max --api-key $DASHSCOPE_API_KEY
```

### 完整参数表

| 参数 | 简写 | 默认值 | 说明 |
|------|:----:|--------|------|
| `--intent` | `-i` | 标准 host-router-host 意图 | 自然语言网络需求 |
| `--mode` | `-m` | `auto` | 执行模式：`mock`（内存模拟）/ `live`（Containerlab）/ `auto`（自动探测） |
| `--max-retries` | | `3` | 熔断前最大自愈/校验重试次数 |
| `--auto-approve` / `--no-auto-approve` | | 自动审批 | 是否自动通过 HITL 审批门 |
| `--interactive` | `-it` | `False` | 启动交互式运维 REPL 控制台 |
| `--output-dir` | `-o` | `./clab_output` | 拓扑与配置输出目录 |
| `--topo-only` | | `False` | 仅生成并校验拓扑（已弃用的旧版路径） |
| `--day2` | | `False` | 对在运行网络执行 Day-2 直连运维 |
| `--harmonized` | | `False` | 执行 Day-1/2/3 统一 Harmonized 工作流 |
| `--lab-name` | | `None` | Containerlab 实验名（Day-2 或 inspect/destroy） |
| `--scan` | | `False` | 扫描宿主机网卡、WSL 网桥与在线拓扑后退出 |
| `--watch` | `-w` | `False` | 持续遥测监控自愈循环 |
| `--watch-interval` | | `5.0` | 监控轮询间隔（秒） |
| `--max-watch-cycles` | | 无限 | 监控最大循环次数 |
| `--provider` | | `mock` | LLM 后端：`mock` / `qwen` / `openai` / `vllm` / `ollama` |
| `--model` | | `None` | 模型名（如 `Qwen/Qwen2.5-7B-Instruct`） |
| `--api-key` | | 环境变量 | Qwen/OpenAI API Key |
| `--base-url` | | `None` | vLLM / Ollama / OpenAI 兼容端点 |
| `--verbose` | `-v` | `False` | 详细执行日志 |
| `--version` | | | 打印版本号 |

退出码约定：`0` 成功（verified/fixed/healthy）；`1` 校验失败、拒绝或异常；`2` 熔断器触发。

---

## 🐍 作为 Python 库二次开发

```python
from langgraph_netagent.tools.detector import EnvironmentDetector
from langgraph_netagent.tools.nic_adapter import LiveNICAdapter

# 1. 自动探测宿主机网卡 / WSL 网桥 / 在线拓扑资产
detector = EnvironmentDetector()
inventory = detector.scan_inventory()
for topo in inventory.available_topologies:
    print(f"[{topo.display_type}] {topo.name}: {topo.summary}")

# 2. 挂载指定网卡（如 VMware VMnet8）进行主动巡检
nic = LiveNICAdapter("VMware Network Adapter VMnet8")
inspection = nic.inspect()
print("在线节点:", [node.name for node in inspection.nodes])
```

更完整的闭环工作流入口请参阅包级文档 [`langgraph_netagent/README.md`](langgraph_netagent/README.md)。

---

## 🛡️ 有界自治与安全模型

- **AAL（Agent Access Layer）**：所有前向/回滚命令经安全白名单校验，违规直接拒绝（exit code 126）；Stage 1 观察阶段强制 `read_only=True`，阻断一切变更命令。
- **沙箱预演**：`DockerSandboxRuntime`（`--network none` 网络隔离、CPU/内存/PID 配额、孤儿容器自动 GC），无 Docker 时回退 `MockSandboxRuntime`。
- **Canonical Intent 编译与回滚**：抽象意图编译为 Linux iptables / Cisco ACL / Huawei VRP / FRR 具体语法，并生成逆序数学逆回滚补偿命令。
- **HITL 审批门**：只有拿到认证的 `PreflightSandboxPassReport` 才允许人工审批（或 `--auto-approve`）进入实弹部署，杜绝未经验证的线上变更。

---

## ⚔️ 对抗性红队压测

针对 Clos5 拓扑的实验室隔离红队工具集（仅限实验环境，勿用于生产）：

| 脚本 | 说明 |
|------|------|
| `mcp_attacker_server.py` | MCP（Model Context Protocol）攻击工具服务器，向 Agent 暴露 SYN 洪泛、UDP 带宽饱和、HTTP 请求风暴、IP 轮换等红队工具 |
| `netops_adversarial_lab_scenarios.py` | 11 个 MITRE ATT&CK 对抗场景（ARP/L2、ICMP/L3、UDP/TCP/L4、Slowloris 等），带 ground-truth 评估报告 |
| `run_live_attack.py` | 10 轮实弹攻击压测（含防御规避、多协议混合风暴、TTL=1 控制面压测等）与恢复审计 |
| `monitor_agent_reactions.py` | Agent 反应实时监控：进程健康、防火墙 ACL 差异、QoS 缓冲遥测、服务健康、事件关联与 MTTR |

MCP 服务器配置见 [`mcp_config.json`](mcp_config.json)。

---

## 🧪 自动化测试

项目内置完备的单元、端到端、故障自愈与对抗鲁棒性测试集（55 个测试文件、767 个 `test_*` 用例）：

```bash
cd langgraph_netagent
pytest -q
```

覆盖范围包括：模型与解析器、LLM Provider、环境探测、导出器、Mock 引擎、遥测探针、状态机、图编译、离线校验、故障注入、工作流 happy-path / 校验环 / 自愈环 / 熔断 / HITL、CLI、AAL、沙箱运行时、Canonical Intent 编译、厂商知识库双路检索、两阶段诊断、持续监控压测及多轮对抗测试。

---

## 📁 项目结构

```
netops-ai-agent/
├── langgraph_netagent/          # 核心 Python 包
│   ├── langgraph_netagent/      # 包源码（models / tools / workflow / llm / validation / prompts / data）
│   ├── tests/                   # 55 个测试文件
│   ├── pyproject.toml           # 内层打包配置（langgraph-netagent）
│   ├── requirements.txt
│   └── README.md                # 包级详细文档（微调指南、架构、CLI 参考）
├── mcp_attacker_server.py       # MCP 红队攻击工具服务器
├── netops_adversarial_lab_scenarios.py  # 11 个 MITRE ATT&CK 对抗场景
├── run_live_attack.py           # 10 轮实弹攻击压测
├── monitor_agent_reactions.py   # Agent 反应实时监控
├── clos5_dhcp.yml               # Clos5 拓扑定义
├── setup_real_network.sh        # 真实网络搭建脚本
├── mcp_config.json              # MCP 服务器配置
├── pyproject.toml               # 根打包配置（netops-ai-agent）
└── README.md                    # 本文件
```

运行时产物目录：`clab_output/`（生成的拓扑与配置）、`attack_logs/`（攻击与监控日志）、`scenario_results/`（对抗场景结果）、`exported_logs/`（导出的执行日志）。

---

## 📚 相关文档

- 架构与设计：见根目录 [`PROJECT.md`](PROJECT.md)（有界自治与解耦架构）。
- 包级详细文档（微调、架构图、CLI/Python API 完整参考）：见 [`langgraph_netagent/README.md`](langgraph_netagent/README.md)。
