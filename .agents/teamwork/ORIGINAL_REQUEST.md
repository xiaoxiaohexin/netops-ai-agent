# Original User Request

## Initial Request — 2026-09-25T06:39:43Z

This is a single self-contained refactor; keep it small and focused.

# Teamwork Project Prompt — Launched

> Status: Launched
> Goal: Multi-agent execution delegated to teamwork_preview
> Requested team: small focused team

Refactor the `netops-ai-agent` Python core by deprecating greenfield topology generation and implementing a pure Network Operations (NetOps / AIOps) incident troubleshooting and self-healing agent system that strictly executes the user-defined UML activity diagram.

Working directory: `e:\netops-ai-agent`
Integrity mode: development

## Requirements

### R1. Telemetry-Driven Operational Workflow (UML Conformance)
Replace the current declarative topology-building entrypoint with an operational troubleshooting state machine in `langgraph_netagent`:
1. Ingest existing healthy network baseline and extract IP/asset inventory (`inventory_pool`).
2. Run continuous telemetry monitoring/probe matrix, parsing alerts/syslog to extract 5-tuple failure attributes.
3. Compare observed network state against initial topology baseline to isolate single-exit or interface discrepancies.
4. Support human approval (HITL) gate only after sandbox validation passes.
5. Apply hot-patch to target nodes and perform post-change verification probing.

### R2. Two-Stage Diagnostic Engine & Loop Prevention
Refactor the diagnostic reasoning workflow into two strictly separated stages:
1. **Stage 1 (Context Enrichment & Pre-retrieval)**: Read-only tool execution to fetch running/historical configs and infer RAG search keywords without mutating state.
2. **Stage 2 (Targeted Plan Generation)**: Incorporate retrieved SOP context to formulate actionable diagnosis/patch commands. Explicitly attach iteration counter tags (`step_tag`) to command execution to deterministically trip the circuit breaker and prevent infinite loops.

### R3. Agent Access Layer (AAL) & Shadow Sandbox Validation
Decouple agent tool calls from direct CLI execution:
1. Implement an Agent Access Layer (AAL) that validates structured tool calls, enforces a safety whitelist (blocking dangerous operations like full interface flushes or unexpected reboots), and normalizes CLI output into structured JSON.
2. Implement a Shadow Sandbox mechanism: before applying patches or invasive commands to live containers, clone the problematic node into an isolated sandbox replica (or simulated equivalent in mock mode) and run the patch there first.

### R4. Mock Compatibility & Test Suite Verification
Maintain seamless support for `--mode mock` without requiring Docker or root privileges. Ensure that all new state machine nodes, AAL filters, and sandbox simulation branches pass programmatically via `pytest`.

## Acceptance Criteria

### Workflow & State Machine
- [ ] The primary LangGraph workflow follows the UML flow: Baseline Ingestion → Telemetry/5-Tuple Extraction → 2-Stage Diagnosis → AAL Sandbox Validation → Human Approval → Live Hot-Patch → Re-verification.
- [ ] No code paths attempt to generate new Containerlab topologies from natural language text from scratch.
- [ ] Step tagging reliably forces termination into `circuit_breaker` when retry threshold is exceeded.

### AAL & Sandbox Safety
- [ ] Destructive commands in the AAL layer are blocked by security policy rules.
- [ ] Candidate configuration patches execute in the shadow replica sandbox before reaching the human approval stage.
- [ ] Unstructured CLI responses are parsed into structured JSON format.

### Verification & Testing
- [ ] `pytest` executes cleanly under `langgraph_netagent` in mock mode with all core workflow, AAL, and diagnostic tests passing.

## Follow-up — 2026-09-27T10:37:02Z

严格对齐用户提供的网络运维智能体架构图，完善 NetOps AI Agent 的主动常驻监控与闭环自愈能力：在不破坏现有既有逻辑与已有测试的前提下，实现网络连通性与流量异常（缓冲区溢出/丢包/5元组）的主动捕获循环，并在异常发生时全自动驱动两阶段诊断、AAL 沙箱验证与动态防护补丁下发。

Working directory: e:\netops-ai-agent\langgraph_netagent
Integrity mode: development

## Requirements

### R1. 常态持续监听与遥测循环 (Continuous Monitoring Loop)
按照架构图左上角闭环逻辑，实现“正常状态下不断载入上下文继续循环日志状态”的主动监听机制：
- 支持常驻监控模式（例如 `--watch` 或交互式自动轮询循环），在网络处于正常状态 (`end_healthy`) 时不直接退出进程，而是等待可配置的采样间隔后回流至遥测监测节点，保持会话上下文。

### R2. 多维异常捕获与五元组提取 (Multi-Dimensional Anomaly & 5-Tuple Extraction)
完善 `telemetry_extraction` 节点的多维异常感知能力：
- 结合架构图中的“流量基础信息”，除原有的节点连通性 (Ping) 与路由表外，将网关/路由器的硬件丢包、缓冲区溢出 (Overlimits) 与大流量过载纳入异常指标。
- 发生异常时，自动提取受影响的五元组 (FiveTuple) 与源/目的节点信息，并初步判断是否属于单出口故障或外部过载冲击。

### R3. 自愈状态机全链路联动 (Two-Stage Diagnosis, AAL Sandbox & Live Patching)
打通异常捕获后的处置主干链路：
- 驱动“生成针对性排障计划”（结合两层 Tool 调用与上下文补充）；
- 驱动 AAL 适配器进行配置翻译、安全规则校验，在独立沙箱容器中验证补丁有效性；
- 支持人工审批（Human-in-the-Loop，或配置自动审批）后，将防护规则（如 iptables 边界阻断、限流或路由修复）热下发到真实网关/路由器；
- 补丁下发后自动触发复验，确保网络回归健康状态。

### R4. 向后兼容与代码完整性保障 (Backward Compatibility & Zero-Regression)
- 保持现有 Day-1 拓扑生成部署、Day-2 故障诊断及交互式 CLI 的既有调用逻辑不变。
- 确保项目现有 453 个自动化测试全部保持 PASS，无破坏性破坏。

## Verification Resources & Mechanisms

### 验证资源
- 本地 Containerlab 真实拓扑：`clos5`（包含 attacker, ext-router, dc-egress, FRR Clos fabric, h1~h4 节点）。
- 现存自动化测试用例集：`langgraph_netagent/tests/`（包含 453 个测试）。
- 真实流量与攻击压测套件：`/home/zbr/Containerlab/containerlab/run_realistic_attack_suite.py`。

### 验收与验证机制
1. **单元与集成测试零回归**：在 `langgraph_netagent` 目录下执行 `pytest`，现有测试全部通过。
2. **常态监听与闭环自愈验证**：
   - 启动 Agent 持续监听模式；
   - 在后台触发突发流量或链路异常；
   - 验证 Agent 进程无需人工再次干预即可在数秒内主动捕获告警，并在状态机中输出针对性 5 元组排查日志；
   - 验证下发阻断/自愈补丁后，网络指标（丢包率与溢出）恢复正常。

## Acceptance Criteria

### 1. 监控循环与异常捕获
- [ ] 状态机提供常驻循环支持，正常状态下能够按周期持续探活而不异常退出。
- [ ] 能灵敏捕获包含网络丢包、路由缺失以及端口/网关缓冲区超额溢出在内的多维异常。
- [ ] 异常发生时能准确解析并输出受影响的 IP 与 5 元组特征结构体。

### 2. 自愈链路与安全控制
- [ ] 异常触发后能够顺利推进至针对性处置计划生成与 AAL 沙箱检验。
- [ ] 支持人工审批门禁（--auto-approve 时自动通过），补丁成功热下发至目标设备。
- [ ] 复验节点确认故障消除，状态正确转换为 `fixed` 或 `healthy`。

### 3. 系统兼容性
- [ ] 现有的 `pytest` 测试套件执行结果无新增 Failure 或 Error（保持 100% 通过）。
- [ ] 既有 CLI 参数（`--mode`, `--provider`, `--day2`, `-it` 等）保持完全兼容。

