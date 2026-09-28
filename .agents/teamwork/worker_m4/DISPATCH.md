## 2026-09-27T11:14:38Z

You are a Worker subagent (teamwork_preview_worker) implementing Milestone 4 for NetOps AI Agent.
Your working directory is: `e:\netops-ai-agent\.agents\teamwork\worker_m4`
Your parent conversation ID is: `6ffd10a5-6718-4152-b29e-7560ee43cfce`
You MUST read the authoritative request file at:
`e:\netops-ai-agent\.agents\teamwork\ORIGINAL_REQUEST.md` (specifically `## Follow-up — 2026-09-27T10:37:02Z`).

You must also read:
- `e:\netops-ai-agent\PROJECT.md`
- `e:\netops-ai-agent\.agents\teamwork\explorer_survey_1\handoff.md` (Section 4 contains exact data structure, routing, and CLI loop designs for R1)

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive Write Ownership:
- `langgraph_netagent/langgraph_netagent/workflow/operational_state.py` (or `langgraph_netagent/workflow/operational_state.py`)
- `langgraph_netagent/langgraph_netagent/workflow/operational_edges.py` (or `langgraph_netagent/workflow/operational_edges.py`)
- `langgraph_netagent/langgraph_netagent/workflow/operational_graph.py` (or `langgraph_netagent/workflow/operational_graph.py`)
- `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py` (or `langgraph_netagent/workflow/operational_nodes.py`: `end_healthy_node`, `baseline_ingestion_node`)
- `langgraph_netagent/langgraph_netagent/cli.py` (or `langgraph_netagent/cli.py`)
- `langgraph_netagent/tests/test_operational_watch_loop.py` (new tests)
- `langgraph_netagent/tests/test_cli_watch_loop.py` (new tests)

Implementation Requirements:
1. `operational_state.py`:
   - Add fields to `OperationalState`:
     `watch_mode: Optional[bool]`
     `watch_interval: Optional[float]`
     `watch_cycle: Optional[int]`
     `max_watch_cycles: Optional[int]`
     `last_healthy_timestamp: Optional[str]`
     `consecutive_healthy_cycles: Optional[int]`
   - Update `create_operational_initial_state(...)` to accept:
     `watch_mode: bool = False, watch_interval: float = 5.0, max_watch_cycles: Optional[int] = None`
     and initialize `watch_cycle: 0`, `last_healthy_timestamp: None`, `consecutive_healthy_cycles: 0`.
2. `operational_edges.py`:
   - Implement `route_after_healthy(state: OperationalState) -> Literal["telemetry_extraction", "end"]`:
     - If `state.get("watch_mode") is True`:
       - `max_cycles = state.get("max_watch_cycles")`
       - `current = state.get("watch_cycle", 0)`
       - If `max_cycles is None or max_cycles <= 0 or current < max_cycles`:
         return `"telemetry_extraction"`
     - Return `"end"`
3. `operational_graph.py`:
   - In `build_operational_graph(...)`:
     Replace static `graph.add_edge("end_healthy", END)` with:
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
   - In `run_operational_workflow(...)`:
     Add arguments `watch_mode: bool = False, watch_interval: float = 5.0, max_watch_cycles: Optional[int] = None` and pass them to initial state creation.
4. `operational_nodes.py`:
   - In `baseline_ingestion_node`:
     Fast-path session caching: if `state.get("inventory_pool") and state.get("baseline")`:
     reuse existing baseline and inventory pool without re-querying `BaselineCollector.collect`.
   - In `end_healthy_node`:
     - Increment `watch_cycle = (state.get("watch_cycle") or 0) + 1`
     - Increment `consecutive_healthy_cycles = (state.get("consecutive_healthy_cycles") or 0) + 1`
     - Update `last_healthy_timestamp = datetime.now(timezone.utc).isoformat()`
     - Reset transient fault indicators: `failure_5tuples = []`, `discrepancies = []`, `suspect_devices = []`, `error_message = None`, `retry_count = 0`, `current_step_tag = None`.
     - If `watch_mode` is True and `route_after_healthy` returns `"telemetry_extraction"`:
       if `state.get("watch_interval", 0) > 0`:
         time.sleep(state["watch_interval"])
     - Add execution log entry reporting healthy watch cycle status.
     - Return dictionary updating these fields.
5. `cli.py`:
   - In `build_arg_parser()`:
     Add `--watch`, `-w` (action="store_true", default=False, help="Run persistent telemetry monitoring loop")
     Add `--watch-interval` (type=float, default=5.0, help="Polling interval in seconds between healthy checks")
     Add `--max-watch-cycles` (type=int, default=None, help="Maximum number of watch cycles before exiting (default: infinite)")
   - In `run_cli()`:
     - If `parsed_args.watch`:
       Implement persistent watchdog loop with session preservation:
       - Maintain session context across cycles.
       - Handle `KeyboardInterrupt` gracefully (print `[WATCH] Gracefully terminated by operator (Ctrl+C)` and return 0).
       - Prune `execution_logs` when exceeding 100 entries.
       - Terminate if `max_watch_cycles` reached or circuit breaker tripped (return 2) or rejected (return 1).
     - If not `parsed_args.watch`:
       Existing one-shot execution unchanged!
6. Unit & Integration Tests:
   - `tests/test_operational_watch_loop.py`:
     - Test `route_after_healthy` routing logic when watch_mode is disabled vs enabled vs cycle cap reached.
     - Test `end_healthy_node` state updates (cycle increment, timestamp, fault resets, inventory preservation).
     - Test `baseline_ingestion_node` fast-path caching.
     - Test `run_operational_workflow` with `watch_mode=True, max_watch_cycles=3, watch_interval=0.001` runs 3 cycles and terminates cleanly.
     - Test self-healing in watch loop: inject fault, heal to fixed/healthy, verify watch continues.
   - `tests/test_cli_watch_loop.py`:
     - Test CLI argument parsing for `--watch`, `--watch-interval`, `--max-watch-cycles`.
     - Test `run_cli(["--mode", "mock", "--watch", "--watch-interval", "0.001", "--max-watch-cycles", "2"])` exits with code 0.
7. Run full test suite `pytest tests` and ensure all 714 existing tests + new tests pass cleanly with 100% success and zero regressions!
8. Write handoff report to `e:\netops-ai-agent\.agents\teamwork\worker_m4\handoff.md`.
9. Send message to parent upon completion.
