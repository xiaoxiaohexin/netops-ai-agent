# Project: NetOps AI Agent — Bounded Autonomy & Decoupled Architecture

## Architecture
The system is an autonomous Network Operations (NetOps / AIOps) incident troubleshooting and closed-loop self-healing agent partitioned into three clean lifecycle phases:
- **Day-1 (Asset Discovery & Vendor Knowledge Ingestion)**:
  - Ingests healthy network baseline and extracts IP/asset inventory (`inventory_pool`).
  - Ingests router vendor documentation (Cisco IOS/XR, Huawei VRP, Linux FRR, Linux host/gateway).
  - Populates a **Tree-Structured Command Database** (`vendor/platform/domain/action`) storing authoritative command syntax, parameters, and exact rollback templates.
  - Builds a **Lightweight Vector Index** embedding abstract scene and intent descriptions mapped to tree node paths, enabling hierarchical dual-retrieval with zero prompt bloat (<500B syntax injection).
- **Day-2 (Cognitive Diagnostic State Machine & Bounded Reasoning)**:
  - Continuous telemetry monitoring (`--watch`) capturing connectivity, routing, buffer overlimits, and queue drops.
  - Multi-dimensional anomaly sensing and 5-tuple extraction.
  - **Two-Stage Diagnostic Decision Loop**:
    - Stage 1: Read-only context enrichment via AAL (`read_only=True`) and keyword inference. Full autonomy for observation.
    - Stage 2: Dual-retrieval template consultation and Canonical Intent generation (`DROP_TRAFFIC`, `RATE_LIMIT`, `RESTORE_ROUTE`, etc.) tagged with monotonic `step_tag` and circuit breaker tripping.
- **Day-3 (Pre-Flight Verification, Bounded Sandbox & Live Deployment)**:
  - **OpenHands-Inspired Lightweight Docker Sandbox Runtime**: Ephemeral micro-containers with default `--network none` isolation, strict CPU/memory/PIDs resource quotas, automated Garbage Collection (Auto-GC) for orphaned containers and untagged images, and seamless fallback to `MockSandboxRuntime`.
  - **Canonical Intent Compiler & Rollback Generator**: Compiles abstract intents into platform-specific syntax (Linux iptables, Cisco ACL, Huawei VRP, Linux FRR) and generates mathematically exact inverse rollback compensation commands in reverse topological order.
  - Pre-flight sandbox trial run producing a certified `PreflightSandboxPassReport`.
  - **Bounded Autonomy Human-in-the-Loop Gate (HITL)**: Requires verified sandbox pass report before human approval (or `--auto-approve`), completely preventing unverified live modifications.
  - Live deployment of verified hot-patches, post-change verification probing, and automated rollback execution if verification fails.
  - **Workflow Harmonization**: Backward-compatible deprecation facades for legacy linear Day-2 nodes (`day2_*`), ensuring 100% test pass rate with zero regression across all 798+ tests.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Ephemeral Docker Sandbox Lifecycle | Isolated container execution with context-manager lifecycle and exit-code/duration capture | M1 | Follow-up R1 |
| 2 | Network Namespace Isolation (`--network none`) | Complete network isolation preventing packet leakage during pre-flight trial runs | M1 | Follow-up R1 |
| 3 | Cgroups Resource Quotas | Enforce 1 CPU core (`nano_cpus`), 512MB memory limit, and 100 max PIDs | M1 | Follow-up R1 |
| 4 | Automated Garbage Collection (Auto-GC) | Sweeper discovering and force-removing orphaned labeled containers (`netops.sandbox=true`) and dangling images | M1 | Follow-up R1 |
| 5 | Mock Mode Sandbox Fallback | Zero-dependency in-memory virtual node simulation when Docker is absent or `--mode mock` | M1 | Follow-up R1 |
| 6 | Declarative Canonical Intent Schema | Abstract Pydantic models for `DROP_TRAFFIC`, `RATE_LIMIT`, `REDIRECT_FLOW`, `RESTORE_ROUTE`, `CLEAR_FILTER` | M2 | Follow-up R2 |
| 7 | Multi-Platform Intent Compiler | Bidirectional compilation targeting Linux `iptables`, Cisco ACL, Huawei VRP, and Linux FRR | M2 | Follow-up R2 |
| 8 | Mathematical Inverse Rollback Generator | Automatic generation of exact inverse compensation command sequences in reverse topological order | M2 | Follow-up R2 |
| 9 | AAL Safety Whitelist Integration | Gate all compiled forward and rollback commands through AAL security policies (exit code 126 on violation) | M2 | Follow-up R2 |
| 10 | Multi-Vendor Documentation Ingestor | Ingestion parser for Cisco, Huawei, Linux FRR command syntax and parameter structures | M3 | Follow-up R3 |
| 11 | Tree-Structured Command Database | Hierarchical tree storage (`vendor/platform/domain/action`) holding authoritative templates and rollbacks | M3 | Follow-up R3 |
| 12 | Lightweight Vector Index | In-process embedding/similarity index holding scene/intent descriptions pointing to tree paths | M3 | Follow-up R3 |
| 13 | Hierarchical Dual-Retrieval Pipeline | Vector query -> tree path resolution -> exact template retrieval, preventing prompt bloat (<500B) | M3 | Follow-up R3 |
| 14 | Decoupled Two-Stage Diagnostic Loop | Decouple Stage 1 (read-only telemetry & 5-tuple extraction) from Stage 2 (canonical intent plan generation) | M4 | Follow-up R4 |
| 15 | Strict Read-Only AAL Enforcement in Stage 1 | Block all mutating commands during telemetry observation with AAL `read_only=True` | M4 | Follow-up R4 |
| 16 | Monotonic Step-Tagging & Circuit Breaker | Explicit iteration tagging (`step_tag`) tripping circuit breaker when `retry_count >= max_retries` | M4 | Follow-up R4 |
| 17 | Certified Pre-Flight Sandbox Pass Report | Data structure emitting test results, exit codes, and resource stats; gates transition to HITL | M4 | Follow-up R4 |
| 18 | Human-in-the-Loop (HITL) Gate with Auto-Approve | Guardrailed approval gate requiring certified sandbox pass report before live execution | M4 | Follow-up R4 |
| 19 | Three-Day Lifecycle Harmonization | Formal separation of Day-1 (Discovery/Ingestion), Day-2 (Diagnosis), Day-3 (Sandbox/Execution) | M5 | Follow-up R5 |
| 20 | Legacy Day-2 Backward-Compatibility Facades | Non-breaking compatibility wrappers for `day2_nodes.py`, `day2_graph.py` preserving 100% existing tests | M5 | Follow-up R5 |
| 21 | Zero Regression Across 798+ Test Suite | Complete pass rate across all existing 798 tests + comprehensive new test tiers (T1-T4) | M5 | Follow-up R5 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | OpenHands-Inspired Lightweight Docker Sandbox Runtime (Day-3) | `tools/sandbox_runtime.py`, `tools/sandbox.py`, `tools/mock_engine.py`, `models/sandbox.py` | none | DONE |
| M2 | Canonical Intent Compiler & Rollback Generator (Day-3) | `models/intent.py`, `tools/intent_compiler.py`, `tools/aal.py` | none | DONE |
| M3 | Vendor Documentation Ingestion & Hierarchical Dual-Retrieval (Day-1) | `models/knowledge.py`, `tools/vendor_knowledge.py`, `tools/sop_retriever.py` | none | DONE |
| M4 | Bounded AI Autonomy & Two-Stage Diagnostic Decision Loop (Day-2) | `models/operational.py`, `workflow/operational_nodes.py`, `workflow/operational_edges.py`, `workflow/operational_state.py` | M1, M2, M3 | DONE |
| M5 | Workflow Harmonization & Zero Regression Verification (Day-1/2/3) | `workflow/harmonized_graph.py`, `workflow/day2_nodes.py`, `cli.py`, `tests/` | M4 | DONE |

## Interface Contracts

### 1. Intent Compiler ↔ Sandbox Runtime (M2 ↔ M1)
- `CanonicalIntent`:
  - `action: str` (e.g. `"DROP_TRAFFIC"`, `"RATE_LIMIT"`, `"RESTORE_ROUTE"`)
  - `target_platform: TargetPlatform` (`LINUX_IPTABLES`, `CISCO_IOS`, `HUAWEI_VRP`, `LINUX_FRR`)
  - `params: Dict[str, Any]` (source_ip, destination_ip, protocol, port, rate_limit_kbps, etc.)
- `CompilationResult`:
  - `forward_commands: List[str]`
  - `rollback_commands: List[str]` (reverse topological order)
  - `target_platform: TargetPlatform`
  - `is_safe: bool` (validated against AAL whitelist)

### 2. Dual-Retrieval ↔ Stage 2 Diagnosis (M3 ↔ M4)
- `DualRetrievalResult`:
  - `tree_path: str` (e.g. `"linux/iptables/traffic_filtering/drop_forward"`)
  - `command_template: str` (e.g. `"iptables -I FORWARD -s {src_ip} -d {dst_ip} -p {proto} --dport {dport} -j DROP"`)
  - `rollback_template: str` (e.g. `"iptables -D FORWARD -s {src_ip} -d {dst_ip} -p {proto} --dport {dport} -j DROP"`)
  - `parameters: List[str]`
  - `confidence_score: float`

### 3. Sandbox Validation ↔ HITL Gate (M1/M4)
- `PreflightSandboxPassReport`:
  - `sandbox_id: str`
  - `target_node: str`
  - `target_platform: TargetPlatform`
  - `commands_executed: List[str]`
  - `all_passed: bool`
  - `exit_codes: List[int]`
  - `execution_duration_sec: float`
  - `network_isolated: bool` (must be `True`)
  - `resource_quotas: Dict[str, Any]` (`cpu_limit="1.0"`, `mem_limit="512m"`, `pids_limit=100`)
  - `timestamp: str`
  - `pass_signature: str` (verification hash)

### 4. Legacy Day-2 Compatibility Facade (M5)
- `run_day2_workflow(...)` and `build_day2_graph(...)`:
  - Signatures, return types, and state dictionary keys (`status`, `discrepancies`, `candidate_plan`, `dry_run_verified`, `human_approved`, `patch_applied`, `re_verified`) remain 100% backward-compatible.
  - Emits `DeprecationWarning` advising migration to `HarmonizedOperationalGraph`.

## Code Layout
- `langgraph_netagent/models/sandbox.py`: Sandbox execution results, resource quota specs, GC report, pass report models
- `langgraph_netagent/models/intent.py`: Canonical intent taxonomy, compilation results, rollback steps
- `langgraph_netagent/models/knowledge.py`: Command tree nodes, vector index entries, dual-retrieval results
- `langgraph_netagent/tools/sandbox_runtime.py`: OpenHands-inspired Docker sandbox runtime, cgroups quotas, Auto-GC sweeper, MockSandboxRuntime
- `langgraph_netagent/tools/sandbox.py`: High-level `ShadowSandboxManager` integrating `sandbox_runtime`
- `langgraph_netagent/tools/intent_compiler.py`: Multi-platform intent compiler (Linux iptables, Cisco ACL, Huawei VRP, Linux FRR) and reverse rollback generator
- `langgraph_netagent/tools/vendor_knowledge.py`: Vendor doc ingestor, tree database, lightweight vector index, dual-retrieval engine
- `langgraph_netagent/tools/sop_retriever.py`: Integrates `vendor_knowledge` dual-retrieval with legacy SOP fallback
- `langgraph_netagent/tools/mock_engine.py`: Mock engine enhancements for sandbox, intent execution, and vendor syntax simulation
- `langgraph_netagent/workflow/operational_nodes.py`: Bounded autonomy two-stage diagnosis, certified pass report verification, and HITL gate
- `langgraph_netagent/workflow/operational_state.py`: Augmented state holding canonical intents, pass reports, and knowledge pointers
- `langgraph_netagent/workflow/day2_nodes.py`: Non-breaking compatibility wrappers for legacy Day-2 nodes
- `langgraph_netagent/workflow/harmonized_graph.py`: Unified Day-1 / Day-2 / Day-3 operational graph
- `langgraph_netagent/cli.py`: Integrated CLI options for watch loop, sandbox mode, auto-approve, and harmonized runner
- `langgraph_netagent/tests/`: Existing 49 test files (798 tests) + dedicated new test suites for M1-M5
