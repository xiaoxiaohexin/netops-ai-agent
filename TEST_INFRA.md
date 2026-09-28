# E2E Test Infra: NetOps AI Agent Closed-Loop Self-Healing

## Test Philosophy
- Opaque-box, requirement-driven. No dependency on implementation design.
- Methodology: Category-Partition + Boundary Value Analysis + Pairwise + Real-World Workload Testing.
- Zero regression across all existing 677 test cases.

## Feature Inventory
| # | Feature | Source | Tier 1 | Tier 2 | Tier 3 |
|---|---------|--------|:------:|:------:|:------:|
| 1 | Continuous Monitoring Loop (`--watch`) | Follow-up R1 | 5 | 5 | ✓ |
| 2 | Qdisc & Buffer Overlimits Telemetry | Follow-up R2 | 5 | 5 | ✓ |
| 3 | Interface Stats Telemetry | Follow-up R2 | 5 | 5 | ✓ |
| 4 | Multi-Dimensional Anomaly Detection | Follow-up R2 | 5 | 5 | ✓ |
| 5 | Overload 5-Tuple Extraction | Follow-up R2 | 5 | 5 | ✓ |
| 6 | Anomaly Classification (Single-Exit vs External) | Follow-up R2 | 5 | 5 | ✓ |
| 7 | SOP Knowledge & Overload Mitigation | Follow-up R3 | 5 | 5 | ✓ |
| 8 | Two-Stage Diagnosis for Overload | Follow-up R3 | 5 | 5 | ✓ |
| 9 | AAL Sandbox Validation for iptables | Follow-up R3 | 5 | 5 | ✓ |
| 10 | Live Patch Deployment & Re-verification | Follow-up R3 | 5 | 5 | ✓ |
| 11 | CLI Flags & Parameter Support | Follow-up R1 | 5 | 5 | ✓ |

## Test Architecture
- Test runner: `pytest` inside `e:\netops-ai-agent\langgraph_netagent`
- Existing test suite: 677 tests across 40 test files in `langgraph_netagent/tests/`
- New test suites:
  - `tests/test_qdisc_overlimits_probe.py`: Qdisc and interface probe parsing, thresholds, overlimits detection
  - `tests/test_operational_r2_telemetry.py`: Multi-dimensional anomaly sensing, 5-tuple extraction, classification
  - `tests/test_overload_healing_full_cycle.py`: End-to-end two-stage diagnosis, sandbox validation, live patch, re-verification
  - `tests/test_operational_watch_loop.py`: Continuous monitoring loop, cycle counting, interval, context preservation
  - `tests/test_cli_watch_loop.py`: CLI arguments `--watch`, `--watch-interval`, `--max-watch-cycles`

## Real-World Application Scenarios (Tier 4)
| # | Scenario | Features Exercised | Complexity |
|---|----------|--------------------|------------|
| 1 | High-Volume Ingress Flood & Buffer Saturation | F2, F4, F5, F6, F7, F8, F9, F10 | High |
| 2 | Resident Watchdog Daemon Monitoring with Intermittent Spike | F1, F2, F4, F8, F10, F11, F12 | High |
| 3 | Single-Exit Route Flap vs External Overload Discrimination | F4, F5, F6, F8 | Medium |
| 4 | Non-Interactive Automated HITL Auto-Approve Self-Healing | F8, F9, F10, F11 | Medium |
| 5 | Multi-Cycle Persistent Session Context Preservation | F1, F11, F12 | Medium |
