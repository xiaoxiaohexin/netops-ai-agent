## 2026-09-27T11:03:12Z

You are a Worker subagent (teamwork_preview_worker) implementing Milestone 3 for NetOps AI Agent.
Your working directory is: `e:\netops-ai-agent\.agents\teamwork\worker_m3`
Your parent conversation ID is: `6ffd10a5-6718-4152-b29e-7560ee43cfce`
You MUST read the authoritative request file at:
`e:\netops-ai-agent\.agents\teamwork\ORIGINAL_REQUEST.md` (specifically `## Follow-up — 2026-09-27T10:37:02Z`).

You must also read:
- `e:\netops-ai-agent\PROJECT.md`
- `e:\netops-ai-agent\.agents\teamwork\worker_m1\handoff.md` (M1 models, probes, SOP-OVERLOAD-005, MockEngine)
- `e:\netops-ai-agent\.agents\teamwork\worker_m2\handoff.md` (M2 telemetry extraction & anomaly classification)

MANDATORY INTEGRITY WARNING:
DO NOT CHEAT. All implementations must be genuine. DO NOT hardcode test results, create dummy/facade implementations, or circumvent the intended task. A teamwork_preview_auditor will independently verify your work. Integrity violations WILL be detected and your work WILL be rejected.

Your Exclusive Write Ownership:
- `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py` (specifically `diagnostic_stage1_node`, `diagnostic_stage2_node`, `sandbox_validation_node`, `live_hot_patch_node`, `re_verification_node`)
- `langgraph_netagent/tests/test_overload_healing_full_cycle.py` (new tests)

Implementation Requirements:
1. `operational_nodes.py`:
   - In `diagnostic_stage1_node`:
     - If `anomaly_classification.get("category") == "external_overload"` or any discrepancy is `buffer_overlimit` or 5-tuple is `TRAFFIC_OVERLOAD`:
       - Infer RAG search keywords including `"overload"`, `"overlimits"`, `"buffer"`, `"tc"`, `"iptables"`, `"traffic_overload"`.
       - Dispatch read-only AAL tool calls for `tc -s qdisc show` and `ip -s link show` on the suspect bottleneck router/gateway.
   - In `diagnostic_stage2_node`:
     - Retrieve SOP from `SOPRetriever` with the enriched keywords (retrieving `SOP-OVERLOAD-005`).
     - When anomaly is `external_overload` or discrepancy is `buffer_overlimit`:
       - Target the bottleneck router (e.g. `bottleneck_node` from `anomaly_classification` or `suspect_devices[0]`).
       - Formulate candidate remediation commands using `iptables`:
         e.g., `f"iptables -I FORWARD -s {offending_source_ip} -j DROP"` (and/or `-p {protocol} --dport {port} -j DROP`).
       - Tag commands with `{current_step_tag}`.
       - Construct structured `RemediationPlan` and `DiagnosticReport`.
   - In `sandbox_validation_node`:
     - Validate candidate iptables commands in shadow replica sandbox. (AAL allows iptables in write mode; MockEngine executes iptables cleanly).
   - In `live_hot_patch_node`:
     - Apply candidate commands to live target node.
   - In `re_verification_node`:
     - Re-run telemetry probe matrix via `NetworkTelemetryCollector.collect(...)`.
     - Confirm all buffer anomalies, drops, and overlimits are cleared (cleared via `FaultInjector.on_remediation` in mock engine).
     - If all probes pass: set `status = "re_verified"`, leading `route_after_re_verification` to `end_fixed`.
   - Ensure 100% backward compatibility with all existing route flapping, interface down, and ping failure diagnosis flows!
2. Create `langgraph_netagent/tests/test_overload_healing_full_cycle.py`:
   - Integration test for Stage 1 context enrichment and Stage 2 SOP retrieval under buffer overlimits.
   - Full end-to-end integration test running `run_operational_workflow(auto_approve=True)` with injected `FaultRule(fault_type=FaultType.BUFFER_OVERLIMIT, node="dc-egress", source_ip="192.168.100.2")`.
   - Verify workflow traverses: `baseline_ingestion` -> `telemetry_extraction` -> `diagnostic_stage1` -> `diagnostic_stage2` -> `sandbox_validation` -> `human_approval` -> `live_hot_patch` -> `re_verification` -> `end_fixed`.
   - Verify final status is `"fixed"` and network health is restored.
   - Test non-auto-approve behavior: stops at `end_rejected` or `pending_approval` when `auto_approve=False` in non-interactive mode.
3. Run `pytest tests` to verify all 706 existing tests PLUS new tests pass cleanly with zero regressions.
4. Write handoff report to `e:\netops-ai-agent\.agents\teamwork\worker_m3\handoff.md`.
5. Use `send_message` to notify your parent when complete.
