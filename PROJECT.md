# 项目逻辑梳理（Project Logic）

> 本文如实描述 `netops-ai-agent` 当前的代码结构与执行链路，替换了此前带营销成分的架构文档。目标是「看清代码现在是什么」，而不是「它想成为什么」。

---

## 1. 这是什么

一个 Python（LangGraph 状态机）编写的**闭环自愈网络运维 Agent 研究原型**。它面向 **Containerlab 容器实验网**（或宿主机网卡），演示：

```
感知（遥测探针） → 诊断（规则分类） → 有界修复（沙箱预演 + HITL） → 复测 → 回滚 / 熔断
```

核心定位：**验证"有界自治"的工程形态**，而非可交付生产的网管系统。

---

## 2. 代码库的演进与分层（真实现状）

代码是**多轮迭代叠加**的结果，三条工作流并存，而非单一干净架构：

| 工作流 | 文件 | 入口 | 现状 |
|---|---|---|---|
| Greenfield（8 节点） | `workflow/graph.py`、`workflow/nodes.py` | `--topo-only` | 最早版本；从零「意图→拓扑→部署→自愈」，CLI 已标注 DEPRECATED |
| Operational（Day-2） | `workflow/operational_graph.py`、`workflow/operational_nodes.py` | 默认路径 | 当前主用；对**已在运行的网络**做排障自愈 |
| Harmonized（Day-1/2/3） | `workflow/harmonized_graph.py` | `--harmonized` | 当前主用；统一三阶段，带相位校验 |

CLI 实际分发逻辑（`cli.py`）：

- 默认 → `run_operational_workflow`
- `--harmonized` → `run_harmonized_workflow`
- `--topo-only` → 旧 greenfield 导出（弃用）
- `--day2` → **已定义但未使用**（死标志）
- `-it` / `--scan` → 独立于工作流，走交互式 / 资产扫描

---

## 3. 真实执行链路（Operational / Harmonized）

以 Operational 工作流为例，逐步说明每步**实际做了什么**：

1. **基线摄取（baseline_ingestion）**：`clab inspect --format json` + `docker exec` 读取运行中节点的 IP/资产清单，构建 `InventoryPool`。
2. **遥测与五元组提取（telemetry_extraction）**：真实执行 `ping`、`vtysh show ip route`、`tc -s qdisc show`、`ip -s link show`，解析出失败五元组与差异项。
3. **异常分类（classify_anomaly）**：**纯规则**，四类 —— 外部过载 / 单出口故障 / 内链路故障 / 健康。含大量针对 Clos5 的写死默认值。
4. **两阶段诊断（diagnostic_stage1 / stage2）**：
   - Stage 1：经 AAL 只读执行，拉取 running-config / 路由表 / qdisc，推断 RAG 关键词。
   - Stage 2：检索 SOP 模板，生成 Canonical Intent（如 `DROP_TRAFFIC` / `RESTORE_ROUTE` / `RESET_INTERFACE`），编译为平台命令；LLM 仅用于生成 `DiagnosticReport`/`RemediationPlan` 文案，**失败则走确定性回退**。
5. **沙箱预演（sandbox_validation）**：`docker commit` 克隆目标节点 → `docker run --network none --privileged` 起隔离副本 → 在副本执行补丁命令 → 清理。mock 模式下改为克隆虚拟节点。
6. **HITL 审批（human_approval）**：必须有沙箱预演通过报告才允许审批（`--auto-approve` 自动通过，或交互式 `[y/N]`）。
7. **实弹热补丁（live_hot_patch）**：经 AAL 逐条 `docker exec` 执行补丁命令，带 step_tag。
8. **复测与回滚（re_verification）**：重新探测；失败则执行逆序回滚命令，重试超限 → 熔断。

---

## 4. 各模块的真实职责

| 模块 | 文件 | 实际职责 |
|---|---|---|
| 数据契约 | `models/` | Pydantic 模型（意图、拓扑、诊断、遥测、意图、知识、沙箱报告） |
| 网络适配 | `tools/clab_adapter.py` | 真实执行 `clab deploy/destroy/inspect` + `docker exec`（Windows 走 WSL2） |
| 遥测探针 | `tools/probes.py` | ping / 路由表 / 接口 / qdisc 采集与解析 |
| 访问控制层 | `tools/aal.py` | **正则黑名单** + 只读约束 + CLI 输出归一化 |
| 沙箱 | `tools/sandbox.py`、`tools/sandbox_runtime.py` | docker commit 克隆 + 试跑 + 清理（含 mock 回退） |
| 意图编译 | `tools/intent_compiler.py` | 生成 Linux iptables / FRR / Cisco ACL / Huawei VRP **文本命令** + 逆序回滚 |
| 知识检索 | `tools/sop_retriever.py`、`tools/vendor_knowledge.py` | ~10 条硬编码 SOP + 手工模板树，关键词重叠检索 |
| 环境探测 | `tools/detector.py`、`tools/nic_adapter.py` | 探测 OS/WSL/Docker/Containerlab；挂载宿主机网卡 |
| LLM 抽象 | `llm/` | provider 接口；`mock`（罐头）/ `qwen` / `openai` / `vllm` / `ollama` |
| 工作流 | `workflow/` | 三条工作流的节点 / 边 / 状态 |

---

## 5. 已知局限（诚实清单）

1. **诊断是规则，不是模型**：`classify_anomaly` 为 if/else 硬编码分类，覆盖异常类型很窄（过载 / 缺路由 / 接口 down / ping 丢包）。
2. **修复模板绑定特定 lab**：代码中大量写死 Clos5 的 IP / 节点名（`192.168.100.2`、`203.0.113.10`、`dc-egress`、`10.1.12.2`、`10.2.2.0/24`），换网络需改代码。
3. **AAL 是正则黑名单**：可被混淆绕过，非 OS 级安全边界。
4. **沙箱含 `--privileged`**：有网络隔离（`--network none`），但并非强隔离；「pass 签名」仅为本地哈希，非可信证明。
5. **无真实设备下发通道**：Cisco / Huawei 只生成文本命令，没有 SSH / NETCONF / gNMI 传输层，无法真正下发到物理设备。
6. **默认无真实 AI**：`--provider mock` 是罐头回复；真实推理需自行接模型。
7. **知识库非实时 RAG**：SOP 与厂商模板为手工维护，非文档摄取。
8. **`--day2` 为死标志**，`--topo-only` 为弃用路径，CLI 存在历史遗留。

---

## 6. 关键数据流

```
用户意图 / 运行中 lab
        │
        ▼
[baseline_ingestion] ── clab inspect + docker exec ──► InventoryPool / baseline
        │
        ▼
[telemetry_extraction] ── ping/vtysh/tc/ip ──► NetworkHealthReport + FiveTuple + Discrepancy
        │
        ▼
[classify_anomaly] ── 规则 ──► AnomalyClassification
        │
        ▼
[diagnostic_stage1] ── AAL 只读 ──► enriched_context + rag_keywords
        │
        ▼
[diagnostic_stage2] ── SOP 检索 + 意图编译 +（可选）LLM ──► RemediationPlan + rollback_steps
        │
        ▼
[sandbox_validation] ── docker commit 克隆试跑 ──► PreflightSandboxPassReport
        │
        ▼
[human_approval] ── 需通过报告 ──► approved / rejected
        │
        ▼
[live_hot_patch] ── AAL docker exec ──► patch_result
        │
        ▼
[re_verification] ── 复测 ──► re_verified / 回滚 / circuit_breaker
```

---

## 7. 如果目标是生产网络，还缺什么

- 真实设备接入（SSH / NETCONF / gNMI）与凭证管理
- 通用拓扑抽象，去掉写死 IP / 节点名
- 真实 LLM 推理 + 结构化输出强校验 + 人工确认
- 最小权限沙箱（去 `--privileged`）、命令 allowlist、审计入库
- 配置基线 / 版本快照、变更窗口、逐设备 diff
