# Project: NetOps AI Agent — Continuous Monitoring & Closed-Loop Self-Healing

## Architecture
The system is an autonomous Network Operations (NetOps / AIOps) incident troubleshooting and closed-loop self-healing agent based on LangGraph:
- **Baseline Ingestion**: Extracts network topology and asset inventory (`inventory_pool`) with session caching.
- **Continuous Monitoring & Telemetry Extraction**: Probes ping reachability, routing tables, interface states, and Linux traffic control (`tc qdisc`) buffer overlimits/drops.
- **Multi-Dimensional Anomaly Sensing & 5-Tuple Extraction**: Captures connectivity drops, missing routes, and buffer overlimits. Extracts 5-tuple failure attributes and classifies anomalies into `single_exit_failure`, `external_overload`, or `internal_link_failure`.
- **Two-Stage Diagnosis Engine**:
  - Stage 1: Read-only context enrichment via AAL tool calls (`read_config`, `tc qdisc show`). Infers RAG keywords.
  - Stage 2: SOP retrieval (`SOPRetriever`) including border filtering (`SOP-OVERLOAD-005`), generating step-tagged remediation plans.
- **AAL & Shadow Sandbox Validation**: Enforces safety whitelist/policies on candidate CLI commands, executes patch in isolated sandbox replica before human approval.
- **Human Approval Gate (HITL)**: Interactive prompt or `--auto-approve` bypass.
- **Live Hot-Patching & Re-verification**: Deploys live patch to router/gateway (e.g. `iptables` drop rules), executes post-change telemetry probe to confirm network is restored to healthy.
- **Continuous Monitoring Loop (`--watch`)**: When healthy, maintains session context, waits configurable polling interval, and loops back to telemetry extraction without exiting.

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | Continuous Monitoring Loop (`--watch`) | State machine and CLI persistent polling loop in `end_healthy` with configurable interval and session context preservation | M4 | Follow-up R1 |
| 2 | Qdisc & Buffer Overlimits Telemetry | `tc -s qdisc show` probing, parsing dropped/overlimits counters | M1 | Follow-up R2 |
| 3 | Interface Stats Telemetry | `ip -s link show` hardware packet drop and error counter probing | M1 | Follow-up R2 |
| 4 | Multi-Dimensional Anomaly Detection | Detection of buffer overflow, queue overlimits, packet loss in `telemetry_extraction` | M2 | Follow-up R2 |
| 5 | Overload 5-Tuple Extraction | Extraction of src_ip, dst_ip, protocol, ports from volumetric attack/overload telemetry | M2 | Follow-up R2 |
| 6 | Anomaly Classification | Categorize anomaly into `single_exit_failure` vs `external_overload` | M2 | Follow-up R2 |
| 7 | SOP Knowledge Base Extension | `SOP-OVERLOAD-005` for border gateway iptables drop/rate-limiting | M1 | Follow-up R3 |
| 8 | Two-Stage Diagnosis for Overload | Stage 1 read-only qdisc inspection; Stage 2 iptables remediation plan synthesis | M3 | Follow-up R3 |
| 9 | Mock Engine Buffer Overlimit Simulation | Support `FaultType.BUFFER_OVERLIMIT` and `tc` command simulation in `MockEngine` | M1 | Follow-up R3 |
| 10 | Shadow Sandbox Validation for iptables | Validate candidate iptables remediation commands in sandbox replica | M3 | Follow-up R3 |
| 11 | Live Patch Deployment & Re-verification | Deploy iptables patch, verify qdisc drops cleared, transition to `end_fixed` | M3 | Follow-up R3 |
| 12 | CLI Flags & Parameter Support | Support `--watch`, `--watch-interval`, `--max-watch-cycles` | M4 | Follow-up R1 |
| 13 | Zero-Regression Across Test Suite | Ensure all existing 677 tests pass 100% | M5 | Follow-up R4 |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Models, Probes & SOP Knowledge | `models/telemetry.py`, `models/operational.py`, `tools/probes.py`, `tools/sop_retriever.py`, `tools/fault_injector.py`, `tools/mock_engine.py` | none | DONE |
| M2 | Telemetry Node & Anomaly Classifier | `workflow/operational_nodes.py` (telemetry extraction, buffer overlimit detection, 5-tuple extraction, classifier) | M1 | DONE |
| M3 | Two-Stage Diagnosis, Sandbox & Live Patching | `workflow/operational_nodes.py` (diagnosis stage 1/2, sandbox validation, live patch, re-verification for overload) | M2 | DONE |
| M4 | Continuous Monitoring Loop (`--watch`) | `workflow/operational_state.py`, `workflow/operational_edges.py`, `workflow/operational_graph.py`, `workflow/operational_nodes.py` (end_healthy), `cli.py` | M3 | DONE |
| M5 | E2E Testing & Zero Regression Verification | Pass 100% of all existing 677 tests + new tests (Tiers 1-4, 798 tests total) | M4 | DONE |

## Code Layout
- `langgraph_netagent/models/telemetry.py`: Qdisc and interface stats telemetry models
- `langgraph_netagent/models/operational.py`: FiveTuple extension and AnomalyClassification model
- `langgraph_netagent/tools/probes.py`: QdiscProbe, InterfaceStatsProbe, NetworkTelemetryCollector integration
- `langgraph_netagent/tools/sop_retriever.py`: SOP-OVERLOAD-005 definition
- `langgraph_netagent/tools/fault_injector.py`: FaultType.BUFFER_OVERLIMIT and rule clearing logic
- `langgraph_netagent/tools/mock_engine.py`: tc qdisc simulation
- `langgraph_netagent/workflow/operational_state.py`: watch_mode and watch_cycle state attributes
- `langgraph_netagent/workflow/operational_edges.py`: route_after_healthy conditional router
- `langgraph_netagent/workflow/operational_graph.py`: operational graph wiring for end_healthy loop
- `langgraph_netagent/workflow/operational_nodes.py`: telemetry_extraction, diagnostic_stage1/2, end_healthy
- `langgraph_netagent/cli.py`: --watch CLI options and persistent runner loop
- `langgraph_netagent/tests/`: unit and E2E test suites

## Interface Contracts
### Telemetry Extraction ↔ Stage 1 Diagnosis
- `failure_5tuples: List[FiveTuple]` with `alert_type="TRAFFIC_OVERLOAD"` or `"BUFFER_OVERFLOW"`
- `discrepancies: List[NetworkDiscrepancy]` with `discrepancy_type="buffer_overlimit"`
- `anomaly_classification: Optional[AnomalyClassification]` with `category="external_overload"` or `"single_exit_failure"`

### Stage 2 Diagnosis ↔ AAL & Sandbox
- `candidate_plan.remediation_commands`: structured CLI commands (e.g. `iptables -I FORWARD -s ... -j DROP`)
- Whitelisted in AAL when `read_only=False`
- Executed on target node in shadow replica sandbox with exit code 0
