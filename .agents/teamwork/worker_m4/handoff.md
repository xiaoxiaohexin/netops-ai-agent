# Milestone 4 Handoff Report: Continuous Monitoring Loop (`--watch`)

## 1. Observation

### 1.1 Baseline Test Verification
- Executed `pytest` in `e:\netops-ai-agent\langgraph_netagent`:
  - `collected 714 items`
  - `============================= 714 passed in 8.62s =============================`
  - Confirmed baseline state machine, AAL, models, and diagnostic tools were fully functional.

### 1.2 Implemented Code Modifications
1. **`langgraph_netagent/langgraph_netagent/workflow/operational_state.py`**:
   - Added continuous monitoring control fields to `OperationalState`:
     ```python
     watch_mode: Optional[bool]
     watch_interval: Optional[float]
     watch_cycle: Optional[int]
     max_watch_cycles: Optional[int]
     last_healthy_timestamp: Optional[str]
     consecutive_healthy_cycles: Optional[int]
     ```
   - Updated `create_operational_initial_state(...)` signature to accept `watch_mode: bool = False, watch_interval: float = 5.0, max_watch_cycles: Optional[int] = None`.
   - Initialized `watch_cycle: 0`, `last_healthy_timestamp: None`, `consecutive_healthy_cycles: 0`.

2. **`langgraph_netagent/langgraph_netagent/workflow/operational_edges.py`**:
   - Implemented `route_after_healthy(state: OperationalState) -> Literal["telemetry_extraction", "end"]`:
     - If `state.get("watch_mode") is True`: checks `max_cycles = state.get("max_watch_cycles")` and `current = state.get("watch_cycle", 0)`.
     - Returns `"telemetry_extraction"` if `max_cycles is None or max_cycles <= 0 or current < max_cycles`.
     - Otherwise returns `"end"`.

3. **`langgraph_netagent/langgraph_netagent/workflow/operational_graph.py`**:
   - In `build_operational_graph(...)`: replaced static `graph.add_edge("end_healthy", END)` with conditional edge:
     ```python
     graph.add_conditional_edges(
         "end_healthy",
         route_after_healthy,
         {
             "telemetry_extraction": "telemetry_extraction",
             "end": END,
         },
     )
     ```
   - In `run_operational_workflow(...)`: added arguments `watch_mode: bool = False, watch_interval: float = 5.0, max_watch_cycles: Optional[int] = None, initial_state: Optional[OperationalState] = None`.

4. **`langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py`**:
   - In `baseline_ingestion_node`: implemented fast-path session cache hit when `state.get("inventory_pool") and state.get("baseline")`, bypassing `BaselineCollector.collect`.
   - In `end_healthy_node`:
     - Increments `watch_cycle` and `consecutive_healthy_cycles`.
     - Sets `last_healthy_timestamp` to `datetime.now(timezone.utc).isoformat()`.
     - Resets transient fault indicators: `failure_5tuples = []`, `discrepancies = []`, `suspect_devices = []`, `error_message = None`, `retry_count = 0`, `current_step_tag = None`.
     - Checks `is_looping` via `route_after_healthy(temp_state) == "telemetry_extraction"`. If looping and `watch_interval > 0`, sleeps `watch_interval`.
     - Emits structured log entry for watch cycle health.

5. **`langgraph_netagent/langgraph_netagent/cli.py`**:
   - In `build_arg_parser()`: added `--watch`, `-w` (store_true, default False), `--watch-interval` (float, default 5.0), `--max-watch-cycles` (int, default None).
   - In `run_cli()`: added persistent watchdog loop with session preservation when `parsed_args.watch` is True:
     - Retains `session_state` across loop iterations.
     - Gracefully catches `KeyboardInterrupt`, prints `[WATCH] Gracefully terminated by operator (Ctrl+C)` and returns 0.
     - Prunes `execution_logs` when exceeding 100 entries.
     - Exits with return code 2 if circuit breaker tripped, return code 1 if rejected.
     - Preserves existing one-shot execution path unchanged when `parsed_args.watch` is False.

### 1.3 New Test Suites Created
- `tests/test_operational_watch_loop.py` (10 test cases):
  - `test_create_operational_initial_state_watch_fields` (PASSED)
  - `test_create_operational_initial_state_default_watch_fields` (PASSED)
  - `test_route_after_healthy_watch_mode_disabled` (PASSED)
  - `test_route_after_healthy_watch_mode_unbounded` (PASSED)
  - `test_route_after_healthy_cycle_cap_reached` (PASSED)
  - `test_end_healthy_node_state_updates` (PASSED)
  - `test_end_healthy_node_does_not_sleep_on_terminal_cycle` (PASSED)
  - `test_baseline_ingestion_node_fast_path_caching` (PASSED)
  - `test_run_operational_workflow_watch_cycles` (PASSED)
  - `test_watch_loop_self_healing_and_continuity` (PASSED)
- `tests/test_cli_watch_loop.py` (8 test cases):
  - `test_cli_parser_watch_defaults` (PASSED)
  - `test_cli_parser_watch_custom_flags` (PASSED)
  - `test_cli_parser_watch_short_flag` (PASSED)
  - `test_run_cli_watch_mode_max_cycles_success` (PASSED)
  - `test_run_cli_watch_mode_keyboard_interrupt` (PASSED)
  - `test_run_cli_watch_mode_circuit_breaker` (PASSED)
  - `test_run_cli_watch_mode_rejected_exit_code` (PASSED)
  - `test_run_cli_watch_mode_log_pruning` (PASSED)

### 1.4 Full Test Execution Result
- Executed `pytest` in `langgraph_netagent`:
  - `collected 732 items`
  - `============================ 732 passed in 11.98s =============================`
  - 100% success rate, 0 failures, 0 errors, 0 regressions across all 44 test suites.

---

## 2. Logic Chain

1. **Routing Requirements (R1)**:
   - Observation: When `--watch` is specified or `watch_mode=True`, the state machine must not terminate after the first healthy check, but instead loop back to telemetry extraction.
   - Deduction: Replacing `graph.add_edge("end_healthy", END)` with `graph.add_conditional_edges("end_healthy", route_after_healthy, {"telemetry_extraction": "telemetry_extraction", "end": END})` allows dynamic looping based on state.
   - Verification: When `watch_mode=False`, `route_after_healthy` returns `"end"`, keeping one-shot execution completely identical to existing behavior.

2. **Session Preservation & Overhead Reduction**:
   - Observation: Baseline collection queries lab inspect and extracts node interfaces and subnets.
   - Deduction: Across continuous polling cycles in a stable network, re-inspecting the baseline is redundant.
   - Verification: `baseline_ingestion_node` checks `state.get("inventory_pool") and state.get("baseline")`, reusing cached assets with a fast-path cache hit and 0 inspect calls.

3. **Loop Termination & Sleep Precision**:
   - Observation: In-graph looping must not sleep if the current cycle is the terminating cycle (`current == max_cycles`).
   - Deduction: In `end_healthy_node`, evaluating `route_after_healthy(temp_state) == "telemetry_extraction"` ensures `time.sleep(watch_interval)` only executes when another cycle is about to start.
   - Verification: `test_end_healthy_node_does_not_sleep_on_terminal_cycle` confirmed elapsed time is < 0.2s even with `watch_interval=5.0`.

4. **Daemon Safety & Graceful Shutdown**:
   - Observation: Resident daemons in CLI must terminate cleanly upon operator Ctrl+C and avoid unbounded memory growth.
   - Deduction: Catching `KeyboardInterrupt` in `run_cli` returns code 0 and logs graceful shutdown; slicing `execution_logs` to latest 50 entries when exceeding 100 prevents unbounded memory growth.
   - Verification: `test_run_cli_watch_mode_keyboard_interrupt` and `test_run_cli_watch_mode_log_pruning` both pass.

---

## 3. Caveats

- **No Caveats**: The implementation satisfies all requirements specified in `ORIGINAL_REQUEST.md` (Follow-up R1) and the dispatch prompt. Changes were strictly constrained to the authorized files and adhere to the minimal change principle.

---

## 4. Conclusion

Milestone 4 (Continuous Monitoring Loop / R1) is completely implemented and verified:
- `operational_state.py` defines state schema and initialization for continuous monitoring.
- `operational_edges.py` implements deterministic `route_after_healthy` routing.
- `operational_graph.py` wires conditional looping after `end_healthy` and supports session continuity.
- `operational_nodes.py` implements fast-path session caching in `baseline_ingestion_node` and cycle tracking, timestamp updating, transient fault resets, and interval sleeping in `end_healthy_node`.
- `cli.py` exposes `--watch`, `-w`, `--watch-interval`, `--max-watch-cycles`, implements the resident watchdog runner loop, graceful `KeyboardInterrupt` handling, and trace log rolling.
- 18 new automated tests in `test_operational_watch_loop.py` and `test_cli_watch_loop.py` pass cleanly.
- Full test suite passes 732/732 (100%) with zero regressions.

---

## 5. Verification Method

To independently verify the implementation:

1. **Run New Watch Loop Tests**:
   ```powershell
   cd e:\netops-ai-agent\langgraph_netagent
   pytest tests/test_operational_watch_loop.py -v
   pytest tests/test_cli_watch_loop.py -v
   ```
   *Expected*: All 18 tests pass in < 5 seconds.

2. **Run Full Test Suite**:
   ```powershell
   cd e:\netops-ai-agent\langgraph_netagent
   pytest
   ```
   *Expected*: `732 passed` with 100% success rate.

3. **Verify CLI Watch Mode Directly**:
   ```powershell
   python -m langgraph_netagent.cli --mode mock --watch --watch-interval 0.001 --max-watch-cycles 2
   ```
   *Expected*: Returns exit code 0 after executing 2 healthy cycles.
