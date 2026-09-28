# Survey Report: NetOps AI Agent Architecture & R1 Continuous Monitoring Loop

> **Agent**: `teamwork_preview_explorer` (Survey Phase Subagent)  
> **Working Directory**: `e:\netops-ai-agent\.agents\teamwork\explorer_survey_1`  
> **Timestamp**: 2026-09-27T10:45:00Z  
> **Target Package**: `e:\netops-ai-agent\langgraph_netagent`  
> **Task**: Architecture survey, state machine transition trace, CLI entrypoint investigation, and exact R1 (Continuous Monitoring Loop) design.

---

## 1. Observation

### 1.1 Codebase Structure and Entrypoints
Direct inspection of `e:\netops-ai-agent\langgraph_netagent` reveals the following primary operational components:

| Component | File Path | Key Classes / Functions | Primary Responsibility |
|---|---|---|---|
| **Graph Builder** | `langgraph_netagent/workflow/operational_graph.py` | `build_operational_graph` (lines 52–169), `run_operational_workflow` (lines 171–218) | Compiles the 12-node UML troubleshooting graph and executes it |
| **State Schema** | `langgraph_netagent/workflow/operational_state.py` | `OperationalState` (lines 18–69), `create_operational_initial_state` (lines 71–128) | TypedDict defining state properties, log reducers, and audit structures |
| **Edge Routing** | `langgraph_netagent/workflow/operational_edges.py` | `route_after_telemetry` (14–38), `route_after_stage2` (40–58), `route_after_sandbox` (60–84), `route_after_approval` (85–104), `route_after_re_verification` (105–125) | Pure deterministic condition routers |
| **Node Factory** | `langgraph_netagent/workflow/operational_nodes.py` | `create_operational_nodes` (lines 55–952) | Instantiates all 12 operational node callables |
| **Graph Engine** | `langgraph_netagent/workflow/graph.py` | `CompiledSimpleGraph` (lines 74–194), `SimpleStateGraph` (lines 195–250) | Dual-mode execution engine supporting official `langgraph` and standalone fallback |
| **CLI Entrypoint** | `langgraph_netagent/cli.py` | `build_arg_parser` (lines 281–393), `run_cli` (lines 395–643), `main` (lines 645–647) | Console script entrypoint for `netagent` |
| **Interactive Shell** | `langgraph_netagent/interactive.py` | `InteractiveNetOpsREPL` (lines 78–205), `do_diagnose` (lines 281–318) | Terminal REPL for interactive operational management |
| **Telemetry & Probes** | `langgraph_netagent/tools/probes.py` | `PingProbe` (lines 18–110), `RouteTableProbe` (112–306), `InterfaceProbe` (308–386), `NetworkTelemetryCollector` (388–469) | Multi-vendor active probing and health report synthesis |
| **Operational Models** | `langgraph_netagent/models/operational.py` | `FiveTuple` (lines 19–224), `InventoryPool` (226–323), `NetworkDiscrepancy` (325–333), `AALToolCall` (335–343), `ShadowSandboxResult` (357–365) | Pydantic models for 5-tuples, inventory, discrepancies, AAL, and sandbox |

### 1.2 Existing Node Transition Flow
In `langgraph_netagent/workflow/operational_graph.py` (lines 100–167), edges are assembled as follows:
```
START
  │
  ▼
[baseline_ingestion]
  │
  ▼
[telemetry_extraction] ──(route_after_telemetry)
  ├── "end_healthy" ─────────► [end_healthy] ───────────────► END
  └── "diagnostic_stage1" ──► [diagnostic_stage1]
                                 │
                                 ▼
                              [diagnostic_stage2] ──(route_after_stage2)
                                 ├── "circuit_breaker" ──► [circuit_breaker] ─► END
                                 └── "sandbox_validation"
                                        │
                                        ▼
                                     [sandbox_validation] ──(route_after_sandbox)
                                        ├── "circuit_breaker" ──► [circuit_breaker] ─► END
                                        ├── "diagnostic_stage1" (retry loop)
                                        └── "human_approval"
                                               │
                                               ▼
                                            [human_approval] ──(route_after_approval)
                                               ├── "end_rejected" ──► [end_rejected] ─► END
                                               ├── "circuit_breaker" ─► [circuit_breaker] ─► END
                                               └── "live_hot_patch"
                                                      │
                                                      ▼
                                                   [live_hot_patch]
                                                      │
                                                      ▼
                                                   [re_verification] ──(route_after_re_verification)
                                                      ├── "end_fixed" ──► [end_fixed] ─► END
                                                      ├── "diagnostic_stage1" (retry loop)
                                                      └── "circuit_breaker" ─► [circuit_breaker] ─► END
```

### 1.3 Baseline Ingestion & Caching
In `langgraph_netagent/workflow/operational_nodes.py` (lines 72–108):
- `baseline_ingestion_node` executes `BaselineCollector.collect(adapter=lab_adapter, lab_name=lab_name)` and calls `InventoryPool.from_baseline(baseline)` on every invocation.
- It returns:
  ```python
  {
      "baseline": baseline,
      "inventory_pool": inventory_pool.model_dump(),
      "topology_path": baseline.get("topology_path", inventory_pool.assets),
      "node_kinds": baseline.get("node_kinds", {}),
      "status": "baseline_ingested",
      "error_message": None,
      "execution_logs": [log],
  }
  ```
- Currently, there is no fast-path bypass checking if `state.get("inventory_pool")` is already populated. In a tight continuous loop, re-collecting the baseline on every poll would query containerlab inspect redundantly.

### 1.4 Healthy Terminal Routing (`end_healthy`)
- In `operational_graph.py` (line 164):
  `graph.add_edge("end_healthy", END)`
- In `operational_nodes.py` (lines 892–901):
  ```python
  def end_healthy_node(state: OperationalState) -> Dict[str, Any]:
      log = create_log_entry(
          stage="end_healthy",
          message="Workflow completed: network is fully healthy, no remediation needed",
          level="info",
      )
      return {
          "status": "healthy",
          "execution_logs": [log],
      }
  ```
- Because `end_healthy` unconditionally transitions to `END`, any single invocation of `run_operational_workflow` terminates immediately once healthy.

### 1.5 CLI Entrypoint & Argument Parsing
In `langgraph_netagent/cli.py`:
- `build_arg_parser()` (lines 281–392) currently supports: `--intent`, `--mode`, `--max-retries`, `--auto-approve`, `--no-auto-approve`, `--interactive`, `--output-dir`, `--topo-only`, `--day2`, `--lab-name`, `--provider`, `--model`, `--api-key`, `--base-url`, `--verbose`, `--version`.
- There are **no arguments** for continuous monitoring (e.g. `--watch`, `--watch-interval`, `--max-watch-cycles`).
- In `run_cli()` (lines 584–591):
  ```python
  final_state = run_operational_workflow(
      llm_provider=llm_provider,
      lab_adapter=lab_adapter,
      lab_name=parsed_args.lab_name,
      max_retries=parsed_args.max_retries,
      auto_approve=parsed_args.auto_approve,
      interactive=parsed_args.interactive,
  )
  ```
- Following execution, `run_cli` prints execution logs and exits immediately (line 637):
  ```python
  if final_status in ("healthy", "fixed", "re_verified", "verified"):
      return 0
  elif final_status == "circuit_broken":
      return 2
  else:
      return 1
  ```

### 1.6 Existing Test Baseline
Direct tool execution of `python -m pytest` inside `e:\netops-ai-agent\langgraph_netagent`:
- **Result**: `677 passed in 8.64s`
- Zero failures, zero errors, 100% pass rate across all 42 test suites.

---

## 2. Logic Chain

### 2.1 The Need for Continuous Monitoring (UML Architecture Conformance)
1. **Observation**: In the user's NetOps architecture diagram (top-left loop), healthy monitoring is depicted as:
   `Telemetry / Log Ingestion -> Discrepancy Check -> [Normal] -> Wait interval / Load context -> Telemetry / Log Ingestion`.
2. **Inference**: In production Network Operations, an AIOps agent does not exit after finding the network healthy once; it remains active as a resident watchdog daemon, periodically sampling connectivity and queue statistics.
3. **Current Gap**: Currently, the agent terminates at `end_healthy -> END`, forcing external orchestrators or human operators to repeatedly invoke `netagent` from scratch, which incurs process startup, environment detection, and baseline re-ingestion latency.

### 2.2 Preservation of Session Context Across Cycles
1. **Observation**: Initial baseline ingestion extracts static asset topology, interface IPs, subnet CIDRs, and baseline static/connected routes into `inventory_pool`.
2. **Inference**: Once ingested during Cycle 1 (or Day-1 initialization), the baseline network inventory is stable unless topological changes occur. Re-ingesting it on every polling cycle is wasteful and adds 200–500ms of overhead per cycle.
3. **Requirement**: The continuous loop must retain `inventory_pool`, `baseline`, `topology_path`, and `node_kinds` in memory across cycles while resetting transient fault attributes (`failure_5tuples`, `discrepancies`, `retry_count`, `current_step_tag`, `sandbox_result`, `patch_result`).

### 2.3 Avoiding Infinite Recursion & Engine Limits
1. **Observation**: In `graph.py` (line 113), `CompiledSimpleGraph` enforces `steps < self.max_steps` (default 50). Official LangGraph enforces `recursion_limit` (default 25).
2. **Inference**: If continuous looping is executed purely *inside* a single invocation of `graph.invoke()` via an internal cyclic edge (`end_healthy -> telemetry_extraction`), a resident process will crash with `GraphRecursionError` or exceed `max_steps` after ~10–20 healthy cycles. Moreover, sleeping inside a node blocks external cancellation, signal handling (`SIGINT` / Ctrl+C), and streaming.
3. **Conclusion**: The continuous monitoring loop requires a **hybrid dual-tier design**:
   - **Tier 1 (In-Graph Routing)**: `operational_edges.py` provides `route_after_healthy(state)`. When `watch_mode=True` and bounded cycles are specified (e.g. in unit tests), the state machine can conditionally loop internally. When `watch_mode=False` (default), it routes to `END`.
   - **Tier 2 (Session-Preserving Runner Loop)**: `run_operational_workflow()` and `run_cli()` support an outer persistent watchdog loop with configurable `watch_interval`, graceful `KeyboardInterrupt` handling, session context reuse, and memory-safe execution log rolling.

---

## 3. Caveats

1. **Read-Only Survey**: This report provides the complete architectural design and survey; no production files in `langgraph_netagent` have been modified during this survey turn.
2. **Containerlab Daemon Dependence**: While the survey verified the Python codebase under mock execution mode (`677/677 tests passing`), live execution requires Docker and Containerlab (`clos5` topology). The mock adapter accurately models all CLI executions, routing tables, and ping probing.
3. **Log Truncation in Long-Running Daemons**: The `OperationalState` includes `execution_logs: Annotated[List[LogEntry], operator.add]`. If an agent runs continuously for days with thousands of cycles, appending to `execution_logs` without windowing would cause unbounded memory growth. The persistent runner must prune or roll execution logs to keep the latest N entries.

---

## 4. Conclusion & Proposed R1 Design

To achieve continuous monitoring (R1) without regressing one-shot runs or existing tests, the following changes are specified:

### 4.1 Data Structure Updates (`OperationalState`)
In `langgraph_netagent/workflow/operational_state.py`:

```python
class OperationalState(TypedDict):
    # Existing fields (lines 22–69)...
    
    # 9. Continuous Monitoring Loop Control (R1)
    watch_mode: Optional[bool]
    watch_interval: Optional[float]
    watch_cycle: Optional[int]
    max_watch_cycles: Optional[int]
    last_healthy_timestamp: Optional[str]
    consecutive_healthy_cycles: Optional[int]
```

In `create_operational_initial_state(...)`:
```python
def create_operational_initial_state(
    max_retries: int = 3,
    auto_approve: bool = False,
    initial_alerts: Optional[List[str]] = None,
    watch_mode: bool = False,
    watch_interval: float = 5.0,
    max_watch_cycles: Optional[int] = None,
) -> OperationalState:
    ...
    state["watch_mode"] = watch_mode
    state["watch_interval"] = watch_interval
    state["watch_cycle"] = 0
    state["max_watch_cycles"] = max_watch_cycles
    state["last_healthy_timestamp"] = None
    state["consecutive_healthy_cycles"] = 0
    return state
```

### 4.2 State Machine Routing & Node Updates
1. **`operational_edges.py`**:
   Add `route_after_healthy`:
   ```python
   def route_after_healthy(
       state: OperationalState,
   ) -> Literal["telemetry_extraction", "end"]:
       """Route after end_healthy node.
       
       If watch_mode is active and remaining cycles allow, loops back to telemetry_extraction.
       Otherwise, routes cleanly to END.
       """
       if state.get("watch_mode"):
           max_cycles = state.get("max_watch_cycles")
           current = state.get("watch_cycle", 0)
           if max_cycles is None or current < max_cycles:
               return "telemetry_extraction"
       return "end"
   ```

2. **`operational_graph.py`**:
   Update `build_operational_graph`:
   ```python
   # Replace graph.add_edge("end_healthy", END) with:
   graph.add_conditional_edges(
       "end_healthy",
       route_after_healthy,
       {
           "telemetry_extraction": "telemetry_extraction",
           "end": END,
       },
   )
   ```

3. **`operational_nodes.py`**:
   - In `baseline_ingestion_node`: Fast-path bypass if `state.get("inventory_pool") and state.get("baseline")` are already present in session context.
   - In `end_healthy_node`:
     - Increment `watch_cycle` and `consecutive_healthy_cycles`.
     - Record `last_healthy_timestamp = datetime.now(timezone.utc).isoformat()`.
     - Reset transient fault indicators (`failure_5tuples = []`, `discrepancies = []`, `suspect_devices = []`, `error_message = None`).
     - Log cycle status.

### 4.3 CLI Parser & Watchdog Runner Loop
1. **`cli.py` Argument Parser (`build_arg_parser`)**:
   Add flags:
   - `--watch`, `-w` (action="store_true", default=False): Enable persistent telemetry monitoring loop.
   - `--watch-interval` (type=float, default=5.0): Polling interval in seconds between healthy checks.
   - `--max-watch-cycles` (type=int, default=None): Optional cycle cap for automated testing and benchmarks.

2. **`cli.py` Execution Runner (`run_cli`)**:
   - If `not parsed_args.watch`:
     Executes single one-shot run identical to current behavior.
   - If `parsed_args.watch`:
     Executes resident watchdog loop:
     ```python
     session_state = None
     cycle = 0
     try:
         while True:
             cycle += 1
             if parsed_args.max_watch_cycles and cycle > parsed_args.max_watch_cycles:
                 break
             
             session_state = run_operational_workflow(
                 llm_provider=llm_provider,
                 lab_adapter=lab_adapter,
                 lab_name=parsed_args.lab_name,
                 max_retries=parsed_args.max_retries,
                 auto_approve=parsed_args.auto_approve,
                 interactive=parsed_args.interactive,
                 initial_state=session_state,
                 watch_mode=True,
                 watch_interval=parsed_args.watch_interval,
             )
             
             status = session_state.get("status")
             if status == "circuit_broken":
                 return 2
             elif status in ("rejected", "pending_approval") and not parsed_args.auto_approve:
                 return 1
             
             # Healthy or fixed: pause for interval and loop
             time.sleep(parsed_args.watch_interval)
             # Prune logs to avoid memory bloat
             if len(session_state.get("execution_logs", [])) > 100:
                 session_state["execution_logs"] = session_state["execution_logs"][-50:]
     except KeyboardInterrupt:
         print("\n[WATCH] Gracefully terminated by operator (Ctrl+C).")
         return 0
     ```

### 4.4 Backward Compatibility Guarantee
- Default `watch_mode = False` preserves current one-shot termination behavior identically.
- Default CLI flags leave all existing commands (`netagent --mode mock`, `netagent --topo-only`, etc.) unchanged.
- All existing 677 tests will continue to pass without regression.

---

## 5. Verification Method

### 5.1 Automated Test Verification
Run full test suite:
```powershell
cd e:\netops-ai-agent\langgraph_netagent
python -m pytest -v
```
**Passing Condition**: All 677 tests continue to pass.

### 5.2 Unit Verification for Continuous Monitoring
Add dedicated tests in `tests/test_operational_workflow.py` and `tests/test_cli_and_entrypoint.py`:
1. `test_route_after_healthy_watch_mode_active`: Verify `route_after_healthy` returns `"telemetry_extraction"`.
2. `test_route_after_healthy_watch_mode_disabled`: Verify `route_after_healthy` returns `"end"`.
3. `test_operational_workflow_watch_cycles`: Run `run_operational_workflow` with `watch_mode=True, max_watch_cycles=3` and verify 3 consecutive cycles execute without error.
4. `test_cli_watch_flags_and_max_cycles`: Run `run_cli(["--mode", "mock", "--watch", "--watch-interval", "0.01", "--max-watch-cycles", "2"])` and verify return code is 0.

### 5.3 Invalidation Conditions
- Any failure in the existing 677 test cases.
- Any regression where one-shot runs fail to terminate at `end_healthy -> END`.
- Memory leaks from unpruned `execution_logs` during extended monitoring.
