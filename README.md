# NetOps AI Agent

> **定位**：这是一个**研究原型 / 教学演示**，不是生产系统。它在 **Containerlab 容器实验网**（或宿主机网卡）上演示「感知 → 诊断 → 有界修复 → 复测 → 回滚」的闭环自愈流程。默认 `mock` 模式下**不含真实 AI 推理**，诊断主要靠规则与模板。

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Containerlab](https://img.shields.io/badge/Containerlab-Multi--Vendor-blueviolet.svg)](https://containerlab.dev/)

---

## 它实际能做什么

- **意图 → 拓扑 → 离线校验 → 部署**：自然语言意图解析为结构化模型，生成 Containerlab 拓扑与配置，部署前做静态校验（IP 重叠 / 子网不匹配 / 链路端点）。
- **遥测探针**：真实执行 `ping`、`vtysh show ip route`、`tc -s qdisc show`、`ip -s link show` 并解析输出。
- **诊断与修复**：基于规则的异常分类（外部过载 / 单出口故障 / 内链路故障 / 健康），生成修复命令并应用。
- **有界修复闭环**：修复前先把目标节点 `docker commit` 克隆到隔离副本上预演，再经 HITL 审批门，通过后才实弹下发；复测失败则执行逆序回滚，重试超限触发熔断。
- **宿主机资产发现与 REPL**：`--scan` 扫描宿主机网卡 / WSL 网桥 / 在线拓扑；`-it` 交互式控制台。
- **对抗性红队压测**（仅实验网）：MCP 攻击工具服务器、11 个 MITRE ATT&CK 场景、10 轮实弹攻击与反应监控。

---

## 明确的能力边界（重要）

下面这些是当前实现的真实限制，请勿当作已具备的能力：

- **诊断是规则驱动**，不是模型推理。`classify_anomaly` 是硬编码的 if/else 分类。
- **修复是模板 + 写死参数**。代码中存在大量针对特定 Clos5 lab 的默认值（如 `192.168.100.2`、`203.0.113.10`、`dc-egress`、`10.1.12.2`、`10.2.2.0/24`），换一张网络需改代码。
- **AAL 是正则黑名单**，不是安全边界，可被混淆绕过，也非 OS 级隔离。
- **沙箱是 `docker commit` + `--network none` 且带 `--privileged`**，是「克隆试跑」而非强隔离。
- **只支持能 `docker exec` 的 Linux/FRR 容器**。Cisco / Huawei 仅**生成文本命令**（`intent_compiler`），**没有 SSH / NETCONF / gNMI 通道下发到真实设备**。
- **默认 LLM 是 `mock`**（罐头 / 模式匹配），无真实推理；真实模型需自行接 Qwen/OpenAI 兼容端点。
- **SOP 知识库是约 10 条硬编码 playbook + 手工模板树**，不是实时摄取厂商文档的 RAG。

---

## 架构（真实分层）

代码库是**分阶段演进叠加**的结果，实际存在三条工作流：

| 工作流 | 入口 | 状态 | 职责 |
|---|---|---|---|
| Greenfield（8 节点） | `--topo-only` | 已弃用（CLI 内标注 DEPRECATED） | 从零生成拓扑 → 校验 → 部署 → 自愈 |
| Operational（Day-2） | 默认路径 | 当前主用 | 对**已在运行的网络**做基线摄取 → 遥测 → 两阶段诊断 → 沙箱 → 热补丁 |
| Harmonized（Day-1/2/3） | `--harmonized` | 当前主用 | 统一 Day-1 / Day-2 / Day-3 三阶段 |

核心组件位于 `langgraph_netagent/langgraph_netagent/`：

- `models/`：Pydantic 数据契约
- `tools/`：Containerlab 适配器、探针、AAL、沙箱、意图编译器、SOP 检索、网卡适配
- `workflow/`：三条工作流的节点 / 边 / 图
- `llm/`：provider 抽象（`mock` / `qwen` / `openai` / `vllm` / `ollama`）
- `validation/`：离线校验器
- `prompts/`：系统提示词

---

## 安装方式

### 方式 1：通过 GitHub 在线安装

```bash
pip install git+https://github.com/xiaoxiaohexin/netops-ai-agent.git
```

### 方式 2：本地可编辑安装

```bash
git clone https://github.com/xiaoxiaohexin/netops-ai-agent.git
cd netops-ai-agent
pip install -e .
```

### 方式 3：离线 Wheel 安装

```bash
pip install dist/netops_ai_agent-0.1.0-py3-none-any.whl
```

安装后注册全局命令 `netagent`。

---

## CLI 命令行使用

```bash
# 交互式 REPL（实时识别宿主机网卡与在线资产）
netagent -it

# 扫描宿主机网卡 / WSL 网桥 / 在线拓扑
netagent --scan

# 默认走 Operational（Day-2）工作流，针对已在运行的 lab
netagent --mode live --lab-name clos5

# 走 Harmonized（Day-1/2/3）统一工作流
netagent --harmonized --mode live --lab-name clos5

# 纯内存 mock 模式（零 Docker）
netagent --harmonized --mode mock

# 持续监控自愈循环
netagent --mode live --watch --watch-interval 5 --max-watch-cycles 10
```

### 参数表

| 参数 | 简写 | 默认值 | 说明 |
|------|:----:|--------|------|
| `--intent` | `-i` | 标准 host-router-host 意图 | 自然语言网络需求 |
| `--mode` | `-m` | `auto` | `mock`（内存模拟）/ `live`（Containerlab）/ `auto`（自动探测） |
| `--max-retries` | | `3` | 熔断前最大自愈/校验重试次数 |
| `--auto-approve` / `--no-auto-approve` | | 自动审批 | 是否自动通过 HITL 审批门 |
| `--interactive` | `-it` | `False` | 交互式 REPL |
| `--output-dir` | `-o` | `./clab_output` | 拓扑与配置输出目录 |
| `--topo-only` | | `False` | 仅生成并校验拓扑（**已弃用的旧版路径**） |
| `--day2` | | `False` | **当前已定义但未接入执行流**（死标志） |
| `--harmonized` | | `False` | 执行 Day-1/2/3 统一工作流 |
| `--lab-name` | | `None` | Containerlab 实验名 |
| `--scan` | | `False` | 扫描网卡 / WSL 网桥 / 在线拓扑后退出 |
| `--watch` | `-w` | `False` | 持续遥测监控自愈循环 |
| `--watch-interval` | | `5.0` | 监控轮询间隔（秒） |
| `--max-watch-cycles` | | 无限 | 监控最大循环次数 |
| `--provider` | | `mock` | LLM 后端：`mock` / `qwen` / `openai` / `vllm` / `ollama` |
| `--model` | | `None` | 模型名（如 `Qwen/Qwen2.5-7B-Instruct`） |
| `--api-key` | | 环境变量 | Qwen/OpenAI API Key |
| `--base-url` | | `None` | vLLM / Ollama / OpenAI 兼容端点 |
| `--verbose` | `-v` | `False` | 详细执行日志 |
| `--version` | | | 打印版本号 |

退出码：`0` 成功；`1` 校验失败 / 拒绝 / 异常；`2` 熔断器触发。

---

## Python API

```python
from langgraph_netagent.tools.detector import EnvironmentDetector
from langgraph_netagent.tools.nic_adapter import LiveNICAdapter

# 1. 探测宿主机网卡 / WSL 网桥 / 在线拓扑资产
detector = EnvironmentDetector()
inventory = detector.scan_inventory()
for topo in inventory.available_topologies:
    print(f"[{topo.display_type}] {topo.name}: {topo.summary}")

# 2. 挂载指定网卡进行主动巡检
nic = LiveNICAdapter("VMware Network Adapter VMnet8")
inspection = nic.inspect()
print("在线节点:", [node.name for node in inspection.nodes])
```

更完整的闭环工作流入口见 [`langgraph_netagent/README.md`](langgraph_netagent/README.md)。

---

## 对抗性红队压测（仅限实验网）

> ⚠️ 以下脚本仅用于隔离的实验环境，**严禁对生产网络使用**。

| 脚本 | 说明 |
|------|------|
| `mcp_attacker_server.py` | MCP 攻击工具服务器（SYN 洪泛、UDP 饱和、HTTP 风暴、IP 轮换等） |
| `netops_adversarial_lab_scenarios.py` | 11 个 MITRE ATT&CK 对抗场景及评估报告 |
| `run_live_attack.py` | 10 轮实弹攻击压测与恢复审计 |
| `monitor_agent_reactions.py` | Agent 反应实时监控（进程健康、ACL 差异、QoS 缓冲、事件关联） |

MCP 服务器配置见 [`mcp_config.json`](mcp_config.json)。

---

## 测试

测试覆盖模型、探针、工作流、AAL、沙箱、意图编译等模块（实测 55 个测试文件、767 个 `test_*` 函数）：

```bash
cd langgraph_netagent
pytest -q
```

> 注：文档中曾出现 972+ / 798+ / 453 等测试数量，均与实测不符，已统一为上述实测值。

---

## 项目结构

```
netops-ai-agent/
├── langgraph_netagent/          # 核心 Python 包
│   ├── langgraph_netagent/      # 包源码（models / tools / workflow / llm / validation / prompts / data）
│   ├── tests/                   # 测试文件
│   ├── pyproject.toml           # 内层打包配置（langgraph-netagent）
│   ├── requirements.txt
│   └── README.md                # 包级文档
├── mcp_attacker_server.py       # MCP 攻击工具服务器
├── netops_adversarial_lab_scenarios.py  # 11 个 MITRE ATT&CK 场景
├── run_live_attack.py           # 10 轮实弹攻击压测
├── monitor_agent_reactions.py   # Agent 反应实时监控
├── clos5_dhcp.yml               # Clos5 拓扑定义
├── setup_real_network.sh        # 实验网搭建脚本
├── mcp_config.json              # MCP 服务器配置
├── pyproject.toml               # 根打包配置（netops-ai-agent）
└── README.md                    # 本文件
```

运行时产物目录：`clab_output/`（生成的拓扑与配置）、`attack_logs/`（攻击与监控日志）、`scenario_results/`（对抗场景结果）、`exported_logs/`（导出的执行日志）。

---

## 相关文档

- 项目逻辑梳理（真实架构、执行链路与局限）：见 [`PROJECT.md`](PROJECT.md)。
- 包级文档（架构图、CLI / Python API 参考）：见 [`langgraph_netagent/README.md`](langgraph_netagent/README.md)。
