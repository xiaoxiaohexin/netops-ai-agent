# NetOps AI Agent

> **项目定位**：**面向实验环境与小型局域网的网络运维智能助手（NetOps Assistant）**。
> 本项目主要作为研究与教学原型，在 Containerlab 等实验环境下演示网络感知、异常检测、故障诊断与有限场景自愈的闭环运维能力。

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Containerlab](https://img.shields.io/badge/Containerlab-Multi--Vendor-blueviolet.svg)](https://containerlab.dev/)

---

## 核心流程

本项目固化了以下标准运维闭环流程：

```text
网络感知
  ↓
网络状态/拓扑发现
  ↓
异常检测
  ↓
故障诊断
  ↓
运维建议
  ↓
人工确认/自动执行
  ↓
结果验证
  ↓
恢复/回滚
```

---

## 功能分层

本项目的功能分为三个清晰的层级，以明确哪些是核心能力，哪些处于实验或预研阶段：

### 1. 核心功能
* **网卡/网络感知**：发现并绑定宿主机网卡或 WSL 网桥。
* **局域网发现**：在实验环境下发现节点和拓扑。
* **拓扑状态**：解析 Containerlab 配置与运行状态。
* **连通性检测**：执行 ping 等基础网络测试。
* **性能监控**：收集基础的网络接口遥测数据。
* **故障诊断**：基于规则与大模型的异常诊断。
* **运维建议**：从动态运维知识中检索诊断指令与修复建议。
* **执行与验证**：在 HITL 授权下执行操作并重新测定连通性。

### 2. 实验功能 (Experimental)
* **链路故障/丢包/延迟/流量过载**：用于在 Containerlab 环境下进行故障与异常流量注入。
* **安全异常实验**：原有的红队攻击与安全相关脚本，已移至 `experiments/security/` 目录。
* **路由异常**：有限场景下针对 FRR 等软件路由的表项诊断与自动修复。

### 3. 预研/未完成 (Research / W.I.P)
* **真实设备接入 (DEVICE MODE)**：目前主要针对 LOCAL MODE 和 LAB MODE，暂未深度验证真实网络设备。
* **多厂商深度适配**：目前仅为初步多厂商适配（如 FRR, Linux 基础网络）。
* **高级自动回滚**：目前通过命令反转实现有限场景自动回滚，基于状态的 `State Diff` 回滚仍在探索中。
* **更复杂的自主运维**：需引入更完备的 NetworkState 模型驱动代理决策。

---

## 实验与运行模式

我们明确定义了以下几种操作模式：

* **LOCAL MODE (本地模式)**：适用于家庭或小型局域网，探测宿主网络、WSL 接口或局域网主机。
* **LAB MODE (实验模式)**：使用 Containerlab 和 FRR 等构建的可复现网络拓扑，是本项目的**主要实验环境**。
* **DEVICE MODE (真实设备接入)**：尚未完成，未来计划对接真实 Cisco/Arista/Juniper 物理设备。

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

# 默认走 Operational 工作流，针对已在运行的 lab
netagent --mode live --lab-name clos5

# 走 Harmonized 统一工作流
netagent --harmonized --mode live --lab-name clos5

# 纯内存 mock 模式（零 Docker）
netagent --harmonized --mode mock

# 持续监控循环
netagent --mode live --watch --watch-interval 5 --max-watch-cycles 10
```

### 参数表

| 参数 | 简写 | 默认值 | 说明 |
|------|:----:|--------|------|
| `--intent` | `-i` | 标准 host-router-host 意图 | 自然语言网络需求 |
| `--mode` | `-m` | `auto` | `mock`（内存模拟）/ `live`（Containerlab） / `auto`（自动探测） |
| `--max-retries` | | `3` | 熔断前最大自动校验重试次数 |
| `--auto-approve` / `--no-auto-approve` | | 自动审批 | 是否自动通过 HITL 审批门 |
| `--interactive` | `-it` | `False` | 交互式 REPL |
| `--output-dir` | `-o` | `./clab_output` | 拓扑与配置输出目录 |
| `--topo-only` | | `False` | 仅生成并校验拓扑（**已弃用的旧版路径**） |
| `--harmonized` | | `False` | 执行统一工作流 |
| `--lab-name` | | `None` | Containerlab 实验名 |
| `--scan` | | `False` | 扫描网卡 / WSL 网桥 / 在线拓扑后退出 |
| `--watch` | `-w` | `False` | 持续遥测监控循环 |
| `--watch-interval` | | `5.0` | 监控轮询间隔（秒） |
| `--max-watch-cycles` | | 无限 | 监控最大循环次数 |
| `--provider` | | `mock` | LLM 后端：`mock` / `qwen` / `openai` / `vllm` / `ollama` |
| `--model` | | `None` | 模型名（如 `Qwen/Qwen2.5-7B-Instruct`） |
| `--api-key` | | 环境变量 | Qwen/OpenAI API Key |
| `--base-url` | | `None` | vLLM / Ollama / OpenAI 兼容端点 |
| `--verbose` | `-v` | `False` | 详细执行日志 |
| `--version` | | | 打印版本号 |

退出码：`0` 成功，`1` 校验失败 / 拒绝 / 异常，`2` 熔断器触发。

---

## 核心能力证据表

为确保项目边界清晰、诚实可信，下表展示了当前各项能力的落地程度：

| 功能 | 代码实现 | 单元测试 | E2E测试 | Containerlab | 真实网络环境 |
|---|:---:|:---:|:---:|:---:|:---:|
| **网卡监控** | ✅ | ✅ | ✅ | - | ✅ (LOCAL MODE) |
| **拓扑发现** | ✅ | ✅ | ✅ | ✅ | ⚠️ (部分探测) |
| **故障诊断** | ✅ | ✅ | ✅ | ✅ | ⚠️ |
| **自动修复** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **自动回滚** | ✅ | ✅ | ⚠️ | ⚠️ | ❌ |
| **多厂商支持(Cisco/Arista)** | ⚠️ (初步) | ⚠️ | ❌ | ❌ | ❌ |

*(✅ 已完成并闭环 / ⚠️ 实验性或部分完成 / ❌ 尚未支持)*

---

## 测试覆盖

测试覆盖模型、探针、工作流、AAL、沙箱、意图编译等模块：

```bash
cd langgraph_netagent
pytest -q
```
*(注：当前实际测试数量为 1449 个，未来请以 CI/CD 自动生成的最新测试报告为准，消除文档中静态硬编码的数据不一致问题)*

---

## 项目结构

```
netops-ai-agent/
├── langgraph_netagent/          # 核心 Python 包
│   ├── langgraph_netagent/      # 包源码
│   ├── tests/                   # 测试文件
│   ├── pyproject.toml           
│   ├── requirements.txt
│   └── README.md                
├── experiments/                 # 实验与非核心功能区
│   └── security/                # 安全异常与故障注入实验 (含原 MCP Server)
├── clos5_dhcp.yml               # Clos5 拓扑定义
├── setup_real_network.sh        # 实验网搭建脚本
├── mcp_config.json              # MCP 服务器配置
├── pyproject.toml               # 根打包配置
└── README.md                    # 本文件
```

运行产物：`clab_output/` (生成拓扑)、`attack_logs/` (注入实验日志)、`scenario_results/` (对抗场景)、`exported_logs/` (执行日志)。

---

## 相关文档

* 项目逻辑梳理：见 [`PROJECT.md`](PROJECT.md)。
* 包级文档：见 [`langgraph_netagent/README.md`](langgraph_netagent/README.md)。
