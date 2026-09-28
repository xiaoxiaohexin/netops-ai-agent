# Comprehensive Handoff Report: Pure NetOps Operational Incident Troubleshooting & Self-Healing Agent

## 1. Executive Summary

In accordance with the project requirements, the `netops-ai-agent` Python core has been refactored by deprecating greenfield topology generation and establishing a pure Network Operations (NetOps / AIOps) incident troubleshooting and self-healing agent system that strictly executes the user-defined UML activity diagram.

The primary entrypoint now executes the operational troubleshooting state machine across all execution modes (`--mode mock` and live Containerlab).

## 2. Requirements & UML Activity Conformance

### R1. Telemetry-Driven Operational Workflow (UML Conformance)
- **Baseline Ingestion**: Ingests the healthy network baseline snapshot and extracts a normalized IP/asset inventory (`inventory_pool`) mapping nodes, subnets, interfaces, and baseline routing tables (`langgraph_netagent/workflow/operational_nodes.py`, `models/operational.py`).
- **Telemetry & 5-Tuple Extraction**: Executes telemetry monitoring/probe matrix, parses packet drops and syslog alerts into structured `FiveTuple` attributes (`source_ip`, `destination_ip`, `protocol`, `source_port`, `destination_port`, `alert_type`).
- **Discrepancy Isolation**: Compares observed network state and hop-by-hop probing against initial topology baseline to isolate single-exit and interface discrepancies into `NetworkDiscrepancy` models.
- **HITL Gate Placement**: Human approval gate is evaluated strictly **after** shadow sandbox validation passes.
- **Live Hot-Patch & Re-verification**: Applies candidate configuration patches to target nodes via AAL and conducts post-change verification probing.

### R2. Two-Stage Diagnostic Engine & Loop Prevention
- **Stage 1 (Context Enrichment & Pre-retrieval)**: Read-only tool execution (`read_only=True` in AAL) to fetch running configs and routing tables from suspect devices without mutating network state. Analyzes 5-tuple failures and discrepancies to infer RAG search keywords (`rag_keywords`).
- **Stage 2 (Targeted Plan Generation)**: Integrates retrieved Standard Operating Procedure (SOP) playbooks (`SOPRetriever`) into the LLM prompt. Explicitly attaches iteration counter tags (`step_tag = f"diag_iter_{retry_count + 1}"`) to each remediation command.
- **Deterministic Loop Prevention**: Monotonic retry counters and iteration tracking reliably route execution to the `circuit_breaker` node when `retry_count >= max_retries`.

### R3. Agent Access Layer (AAL) & Shadow Sandbox Validation
- **Agent Access Layer (`langgraph_netagent/tools/aal.py`)**:
  - Validates structured tool calls (`AALToolCall`).
  - Security Whitelist & Blacklist Rules: strictly blocks dangerous/destructive operations including `rm -rf`, `ip addr flush`, `reboot`, `shutdown`, `init 0/6`, `mkfs`, fork bombs `:(){ :|:& };:`.
  - Normalizes raw unstructured CLI output (`ip addr show`, `ip route show`, `vtysh`, `ping`, etc.) into structured JSON format.
- **Shadow Sandbox Mechanism (`langgraph_netagent/tools/sandbox.py`)**:
  - Clones problematic nodes into isolated shadow sandbox replicas (e.g., `sandbox_{target_node}_{uuid}`).
  - In mock mode, replicates virtual nodes and links within `VirtualNetworkGraph`.
  - Executes candidate remediation commands inside the sandbox replica via AAL first, verifying syntax and safety prior to the human approval gate.
  - Automatically cleans up and destroys sandbox replicas upon validation completion.

### R4. Mock Compatibility & Test Suite Verification
- Operates seamlessly in `--mode mock` without requiring Docker, WSL, or root privileges.
- All new components and all pre-existing regression test suites pass 100% cleanly under `pytest`.

## 3. Test Execution Evidence

### Test Commands:
```bash
pytest langgraph_netagent/tests
```

### Test Output Evidence:
```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.1.1, pluggy-1.6.0
rootdir: E:\netops-ai-agent\langgraph_netagent
configfile: pyproject.toml
plugins: anyio-4.13.0, asyncio-1.4.0, typeguard-4.5.1
asyncio: mode=Mode.AUTO, debug=False, asyncio_default_fixture_loop_scope=None, asyncio_default_test_loop_scope=function
collected 529 items

langgraph_netagent\tests\test_aal.py ...........................         [  5%]
langgraph_netagent\tests\test_adversarial_fuzz_m1.py ................... [  8%]
..........                                                               [ 10%]
langgraph_netagent\tests\test_adversarial_llm.py ....................... [ 14%]
.........                                                                [ 16%]
langgraph_netagent\tests\test_adversarial_m1.py ........................ [ 21%]
............                                                             [ 23%]
langgraph_netagent\tests\test_adversarial_m1_r2.py .................     [ 26%]
langgraph_netagent\tests\test_adversarial_m2.py ............             [ 28%]
langgraph_netagent\tests\test_adversarial_m2_challenge.py .............. [ 31%]
......................                                                   [ 35%]
langgraph_netagent\tests\test_adversarial_m2_failures.py .......         [ 37%]
langgraph_netagent\tests\test_adversarial_m2_r2.py .................     [ 40%]
langgraph_netagent\tests\test_adversarial_m2_r3.py ..............        [ 42%]
langgraph_netagent\tests\test_adversarial_m3.py ........................ [ 47%]
.................                                                        [ 50%]
langgraph_netagent\tests\test_adversarial_m3_2.py ...................... [ 54%]
....                                                                     [ 55%]
langgraph_netagent\tests\test_cli_and_entrypoint.py ...........          [ 57%]
langgraph_netagent\tests\test_day2_workflow.py ....................      [ 61%]
langgraph_netagent\tests\test_edges.py ............                      [ 63%]
langgraph_netagent\tests\test_environment.py ..............              [ 66%]
langgraph_netagent\tests\test_exporter.py .....                          [ 67%]
langgraph_netagent\tests\test_fault_injection.py ........                [ 68%]
langgraph_netagent\tests\test_graph_compilation.py ........              [ 70%]
langgraph_netagent\tests\test_inventory_and_telemetry.py ....            [ 71%]
langgraph_netagent\tests\test_llm_providers.py ..................        [ 74%]
langgraph_netagent\tests\test_mock_engine.py ..........                  [ 76%]
langgraph_netagent\tests\test_models.py ...................              [ 79%]
langgraph_netagent\tests\test_nodes.py ............                      [ 82%]
langgraph_netagent\tests\test_offline_validator.py ...............       [ 85%]
langgraph_netagent\tests\test_operational_workflow.py ................   [ 88%]
langgraph_netagent\tests\test_parser.py ...............                  [ 90%]
langgraph_netagent\tests\test_probes.py .............                    [ 93%]
langgraph_netagent\tests\test_shadow_sandbox.py ....                     [ 94%]
langgraph_netagent\tests\test_state.py .....                             [ 95%]
langgraph_netagent\tests\test_two_stage_diagnosis.py .....               [ 96%]
langgraph_netagent\tests\test_workflow_circuit_breaker.py .....          [ 96%]
langgraph_netagent\tests\test_workflow_happy_path.py ....                [ 97%]
langgraph_netagent\tests\test_workflow_healing_loop.py ....              [ 98%]
langgraph_netagent\tests\test_workflow_hitl.py ....                      [ 99%]
langgraph_netagent\tests\test_workflow_validation_loop.py ....           [100%]

============================ 529 passed in 12.61s =============================
```

## 4. Git Diff Summary

### Modified Files:
- `langgraph_netagent/langgraph_netagent/__init__.py`: Exposed operational workflow entrypoints, AAL, and sandbox managers.
- `langgraph_netagent/langgraph_netagent/cli.py`: Deprecated greenfield topology generation and switched default CLI execution to the operational troubleshooting state machine.
- `langgraph_netagent/langgraph_netagent/models/__init__.py`: Exported operational models.
- `langgraph_netagent/langgraph_netagent/tools/__init__.py`: Exported AAL, sandbox, and SOPRetriever.
- `langgraph_netagent/langgraph_netagent/workflow/__init__.py`: Exported operational workflow nodes, edges, and graphs.

### New Modules:
- `langgraph_netagent/langgraph_netagent/models/operational.py`: Models for `FiveTuple`, `InventoryPool`, `NetworkDiscrepancy`, `AALToolCall`, `AALResponse`, and `ShadowSandboxResult`.
- `langgraph_netagent/langgraph_netagent/tools/aal.py`: `AgentAccessLayer` with safety blacklist rules, read-only checks, and CLI output normalization.
- `langgraph_netagent/langgraph_netagent/tools/sandbox.py`: `ShadowSandboxManager` with replica node cloning and pre-approval patch validation.
- `langgraph_netagent/langgraph_netagent/tools/sop_retriever.py`: SOP knowledge base and relevance retriever.
- `langgraph_netagent/langgraph_netagent/workflow/operational_state.py`: `OperationalState` TypedDict.
- `langgraph_netagent/langgraph_netagent/workflow/operational_edges.py`: Routing functions for UML activity transitions.
- `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py`: Implementation of all 12 operational state machine nodes.
- `langgraph_netagent/langgraph_netagent/workflow/operational_graph.py`: Graph builder and runner.

### New Tests:
- `langgraph_netagent/tests/test_operational_workflow.py`: 16 comprehensive end-to-end tests for the complete UML state machine.
- `langgraph_netagent/tests/test_aal.py`: 27 tests for AAL security rules, read-only enforcement, CLI output normalization, and step-tagging.
- `langgraph_netagent/tests/test_shadow_sandbox.py`: 4 tests for shadow replica validation, failure handling, and teardown.
- `langgraph_netagent/tests/test_two_stage_diagnosis.py`: 5 tests for Stage 1 read-only enrichment, RAG keyword inference, Stage 2 SOP retrieval, and circuit-breaker tripping.
- `langgraph_netagent/tests/test_inventory_and_telemetry.py`: 4 tests for baseline inventory pool and 5-tuple extraction.
