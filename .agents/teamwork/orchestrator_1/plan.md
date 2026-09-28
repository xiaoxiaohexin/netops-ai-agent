# Implementation Plan — NetOps AI Agent R1-R4

## Execution Strategy
The implementation is executed across 5 milestones with strict gate verification at each step:

### Milestone 1: Models, Probes & Knowledge Base
- **Files**:
  - `langgraph_netagent/models/telemetry.py` (QdiscTelemetry, InterfaceStatsTelemetry, NetworkHealthReport fields)
  - `langgraph_netagent/models/operational.py` (AnomalyClassification, FiveTuple extension)
  - `langgraph_netagent/tools/probes.py` (QdiscProbe, InterfaceStatsProbe, NetworkTelemetryCollector integration)
  - `langgraph_netagent/tools/sop_retriever.py` (SOP-OVERLOAD-005)
  - `langgraph_netagent/tools/fault_injector.py` (FaultType.BUFFER_OVERLIMIT)
  - `langgraph_netagent/tools/mock_engine.py` (simulate_tc_command)
- **Gate**: Unit tests pass, existing 677 tests pass.

### Milestone 2: Telemetry Node & Anomaly Classifier
- **Files**:
  - `langgraph_netagent/workflow/operational_nodes.py` (`telemetry_extraction_node`)
  - Integration of Qdisc/Interface probes into anomaly detection
  - 5-tuple extraction from buffer overload / attack traffic
  - Anomaly classification (`single_exit_failure` vs `external_overload`)
- **Gate**: Anomaly detection unit tests pass, zero regressions across 677 tests.

### Milestone 3: Two-Stage Diagnosis, AAL Sandbox & Live Patching
- **Files**:
  - `langgraph_netagent/workflow/operational_nodes.py` (`diagnostic_stage1_node`, `diagnostic_stage2_node`, `sandbox_validation_node`, `live_hot_patch_node`, `re_verification_node`)
  - Support for `iptables` remediation commands generation and execution
  - Verification of buffer overlimits cleared in re-verification
- **Gate**: Full closed-loop self-healing test passes, zero regressions across 677 tests.

### Milestone 4: Continuous Monitoring Loop (`--watch`)
- **Files**:
  - `langgraph_netagent/workflow/operational_state.py` (watch_mode, watch_cycle, etc.)
  - `langgraph_netagent/workflow/operational_edges.py` (`route_after_healthy`)
  - `langgraph_netagent/workflow/operational_graph.py` (conditional edge on `end_healthy`)
  - `langgraph_netagent/workflow/operational_nodes.py` (`end_healthy_node`, baseline caching)
  - `langgraph_netagent/cli.py` (`--watch`, `--watch-interval`, `--max-watch-cycles`, watchdog loop)
- **Gate**: Continuous monitoring loop tests pass, one-shot runs exit normally, zero regressions across 677 tests.

### Milestone 5: E2E Testing, Adversarial Verification & Audit
- Full regression test run (all 677 existing + all new tests).
- Reviewer, Challenger, and Forensic Auditor verification.
- Gate Pass -> Final Victory confirmation.
