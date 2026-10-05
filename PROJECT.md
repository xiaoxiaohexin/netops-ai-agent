# Project: NetOps Assistant Phases 2-4: Containerlab Experimental Loop, NetworkState Model & Agentic Execution

## Architecture
Implement Phases 2-4 of the NetOps Assistant per `ORIGINAL_REQUEST.md`:
1. **Containerlab Experimental Loop & Fault Injector (`tools/clab_fault_injector.py`, `tools/experimental_loop.py`, `tools/lab_isolation.py`)**:
   - `ContainerlabFaultInjector`: Live and mock fault injector for the 18-node `clos5` Containerlab topology (`leaf1..4`, `spine1..4`, `superspine1..2`, `dc-egress`, `ext-router`, `h1..4`, `attacker`, `sflow-rt`).
   - Standard fault catalog: Link Down (`ip link set dev <iface> down`), Route Failure (`ip route del` or BGP neighbor shutdown), Packet Loss/Latency (`tc qdisc netem`).
   - Symmetric rollback tokens (`InjectedFaultToken`) and context manager (`fault_context`) ensuring clean restoration.
   - `LabIsolationGuard`: Strict isolation barrier validating container names (`clab-clos5-*`) and blocking any command targeting host interfaces or routes.
   - `ExperimentalLoop`: End-to-end framework orchestrating baseline capture -> fault injection -> state diff detection -> agent reasoning & deterministic execution -> post-repair programmatic verification.
2. **Structured NetworkState Model & State Diff Engine (`models/network_state.py`, `tools/network_state_snapshotter.py`)**:
   - Pydantic models: `InterfaceState`, `RouteState`, `QdiscState`, `ReachabilityState`, `NodeState`, `LinkState`, `NetworkState`.
   - `NetworkStateSnapshotter`: Queries interface states, routing tables, traffic control qdiscs, and ping matrices via `BaseNetworkLabAdapter` (dual live & mock support).
   - `StateDiff`: Structured difference model comparing baseline vs current `NetworkState` (identifying added/removed/changed interfaces, routes, qdiscs, and reachability breaks).
   - `to_llm_markdown()`: Serializes state differences into concise (<500B / <200 tokens) high-density markdown, completely replacing multi-thousand-character raw CLI dumps.
3. **Agentic Reasoning & Deterministic Execution Engine (`models/reasoning.py`, `models/repair_plan.py`, `workflow/reasoning_engine.py`, `tools/deterministic_executor.py`, `workflow/programmatic_verifier.py`)**:
   - `DiagnosticStrategy` taxonomy: `LINK_RECOVERY`, `ROUTING_REPAIR`, `TRAFFIC_FILTERING_ACL`, `INTERFACE_RESTART`, `QDISC_RESET`.
   - `DiagnosticReasoningEngine`: Analyzes `StateDiff` + `DiscoveredTopology` + SOPs to select diagnostic strategy and formulate structured `RepairPlan`.
   - `RepairPlan` & `RepairAction`: Atomic steps specifying pre-check, command, post-check, and rollback commands.
   - `DeterministicExecutor`: Applies actions sequentially with pre/post condition assertions, transactional safety, and automatic LIFO rollbacks on failure.
   - `ProgrammaticVerifier`: Post-repair snapshotter and diff validator confirming all anomalies resolved and 100% reachability restored.
   - Backward-compatible integration with `OperationalState` and operational nodes in `operational_nodes.py`.
4. **Verification & Hardening Pipeline (`tests/`)**:
   - `tests/test_lab_isolation.py`: Programmatic tests verifying host protection and containerlab scoping.
   - `tests/test_network_state_model.py`: Unit and integration tests for `NetworkState`, snapshotting, and `StateDiff` computation.
   - `tests/test_clab_fault_injector.py`: Tests for fault injection, reversible tokens, and context manager in `clos5`.
   - `tests/test_agentic_reasoning_and_execution.py`: Tests for reasoning engine, repair plan formulation, and deterministic execution with rollback.
   - `tests/test_containerlab_experimental_loop.py`: End-to-end fault injection, detection, self-healing, and programmatic verification loop.
   - Zero-regression test validation ensuring all 1122+ existing tests remain 100% passing.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Containerlab Fault Injector | Live and mock fault injector for `clos5` with Link Down, Route Drop, and Packet Loss | M1 | explorer_survey_4_1 |
| F2 | Reversible Fault Tokens & Context Manager | `InjectedFaultToken` storing exact inverse rollback commands and `fault_context()` context manager | M1 | explorer_survey_4_1 |
| F3 | Lab Isolation Guard | Strict boundary enforcing execution only inside `clab-clos5-*` containers and intercepting host mutations | M1 | explorer_survey_4_1 |
| F4 | Containerlab Experimental Loop Runner | Automated loop orchestrating baseline -> injection -> diff -> agent remediation -> verification | M1 | explorer_survey_4_1 |
| F5 | Structured NetworkState Pydantic Models | Data models for `InterfaceState`, `RouteState`, `QdiscState`, `ReachabilityState`, `NodeState`, `NetworkState` | M2 | explorer_survey_4_2 |
| F6 | Network State Snapshotter | Collects interface, routing, qdisc, and reachability state via `BaseNetworkLabAdapter` | M2 | explorer_survey_4_2 |
| F7 | Deterministic StateDiff Computation Engine | Computes structured delta between baseline and current state (`InterfaceDiff`, `RouteDiff`, `StateDiff`) | M2 | explorer_survey_4_2 |
| F8 | Concise LLM StateDiff Serialization | Serializes `StateDiff` to concise (<500B) markdown summary for LLM context, replacing raw CLI dumps | M2 | explorer_survey_4_2 |
| F9 | Diagnostic Strategy Taxonomy | Formal enum `DiagnosticStrategy` (`LINK_RECOVERY`, `ROUTING_REPAIR`, etc.) with diff-based selector | M3 | explorer_survey_4_3 |
| F10 | Structured RepairPlan & Atomic RepairAction | Schema for atomic actions with pre-check, expected pre-state, command, post-check, and rollback | M3 | explorer_survey_4_3 |
| F11 | Diagnostic Reasoning Engine | LLM-driven reasoning loop analyzing `StateDiff` and generating `RepairPlan` with SOP integration | M3 | explorer_survey_4_3 |
| F12 | Transactional Deterministic Executor | Executes repair actions with pre/post validation, AAL security check, and automatic LIFO rollback | M3 | explorer_survey_4_3 |
| F13 | Programmatic Verifier & Operational Node Integration | Re-snapshots network state post-repair, verifies diff resolution, and integrates with `OperationalState` | M3 | explorer_survey_4_3 |
| F14 | Lab Isolation & Fault Injector Test Suite | Tests for `clab_fault_injector.py`, `lab_isolation.py`, and rollback guarantees | M1, M4 | explorer_survey_4_1 |
| F15 | NetworkState & StateDiff Test Suite | Tests for Pydantic models, snapshotting, and diff computation | M2, M4 | explorer_survey_4_2 |
| F16 | Agentic Reasoning & Execution Test Suite | Tests for reasoning engine, repair plan, and deterministic executor with rollback | M3, M4 | explorer_survey_4_3 |
| F17 | End-to-End Containerlab Experimental Loop Test | Automated test injecting fault, detecting diff, applying deterministic fix, and verifying recovery | M4 | explorer_survey_4_1 |
| F18 | Full Zero-Regression Suite Validation | Validate 100% pass across all 1122+ existing tests in `langgraph_netagent` | M4 | explorer_survey_4_3 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Containerlab Experimental Loop & Lab Isolation | Implement `clab_fault_injector.py`, `lab_isolation.py`, `experimental_loop.py`, and fault injector tests | none | DONE |
| M2 | Structured NetworkState Model & State Diff | Implement `models/network_state.py`, `network_state_snapshotter.py`, `state_diff_engine.py`, and state model tests | none | DONE |
| M3 | Agentic Reasoning & Deterministic Execution Engine | Implement `models/reasoning.py`, `models/repair_plan.py`, `reasoning_engine.py`, `deterministic_executor.py`, `programmatic_verifier.py`, and workflow integration | M1, M2 | DONE |
| M4 | E2E clos5 Fault Recovery, Verification & Zero Regression | Implement E2E test `test_containerlab_experimental_loop.py`, verify full test suite (1122+ tests), Review, Challenge, and Audit | M1, M2, M3 | DONE |

---

## Interface Contracts

### Containerlab Fault Injector ↔ Experimental Loop
- **Module**: `langgraph_netagent/tools/clab_fault_injector.py`
- **Class**: `ContainerlabFaultInjector`
- **Methods**:
  ```python
  def inject_fault(self, scenario: FaultScenario) -> InjectedFaultToken: ...
  def revert_fault(self, token: InjectedFaultToken) -> bool: ...
  def revert_all(self) -> int: ...
  @contextmanager
  def fault_context(self, scenario: FaultScenario): ...
  ```

### Lab Isolation Guard
- **Module**: `langgraph_netagent/tools/lab_isolation.py`
- **Class**: `LabIsolationGuard`
- **Methods**:
  ```python
  def assert_container_isolated(self, container_name: str) -> None: ...
  def validate_command_safety(self, command: str, container_name: str) -> bool: ...
  ```

### NetworkState Snapshotter & State Diff Engine
- **Module**: `langgraph_netagent/tools/network_state_snapshotter.py`
- **Class**: `NetworkStateSnapshotter`
- **Methods**:
  ```python
  def capture_snapshot(self, target_nodes: Optional[List[str]] = None) -> NetworkState: ...
  ```
- **Module**: `langgraph_netagent/models/network_state.py`
- **Functions**:
  ```python
  def compute_state_diff(baseline: NetworkState, current: NetworkState) -> StateDiff: ...
  ```

### Diagnostic Reasoning Engine ↔ Deterministic Executor
- **Module**: `langgraph_netagent/workflow/reasoning_engine.py`
- **Class**: `DiagnosticReasoningEngine`
- **Methods**:
  ```python
  def analyze_diff_and_plan(self, state_diff: StateDiff, topology: DiscoveredTopology, sops: Optional[List[Any]] = None) -> RepairPlan: ...
  ```
- **Module**: `langgraph_netagent/tools/deterministic_executor.py`
- **Class**: `DeterministicExecutor`
- **Methods**:
  ```python
  def execute_plan(self, plan: RepairPlan) -> ExecutionResult: ...
  def rollback_plan(self, plan: RepairPlan, executed_actions: List[RepairAction]) -> bool: ...
  ```

### Programmatic Verifier
- **Module**: `langgraph_netagent/workflow/programmatic_verifier.py`
- **Class**: `ProgrammaticVerifier`
- **Methods**:
  ```python
  def verify_repair(self, baseline: NetworkState, post_repair: NetworkState, target_fault: Optional[StateDiff] = None) -> VerificationResult: ...
  ```

---

## Code Layout
- `langgraph_netagent/langgraph_netagent/tools/clab_fault_injector.py`: Containerlab fault injector supporting Link Down, Route Failure, Packet Loss, Latency with reversible tokens.
- `langgraph_netagent/langgraph_netagent/tools/lab_isolation.py`: Strict isolation guard enforcing container boundaries and blocking host modification.
- `langgraph_netagent/langgraph_netagent/tools/experimental_loop.py`: Automated experimental loop framework.
- `langgraph_netagent/langgraph_netagent/models/network_state.py`: Structured Pydantic models for `NetworkState`, `InterfaceState`, `RouteState`, `QdiscState`, `ReachabilityState`, `StateDiff`.
- `langgraph_netagent/langgraph_netagent/tools/network_state_snapshotter.py`: Snapshotter querying topology state across live and mock adapters.
- `langgraph_netagent/langgraph_netagent/models/reasoning.py`: `DiagnosticStrategy` taxonomy and strategy selection models.
- `langgraph_netagent/langgraph_netagent/models/repair_plan.py`: `RepairPlan` and atomic `RepairAction` models with pre/post checks and rollback commands.
- `langgraph_netagent/langgraph_netagent/workflow/reasoning_engine.py`: LLM-driven reasoning loop analyzing `StateDiff` and generating `RepairPlan`.
- `langgraph_netagent/langgraph_netagent/tools/deterministic_executor.py`: Transactional executor with pre/post validation and LIFO rollback.
- `langgraph_netagent/langgraph_netagent/workflow/programmatic_verifier.py`: Programmatic verification engine comparing post-repair state diff against baseline.
- `langgraph_netagent/langgraph_netagent/workflow/operational_state.py`: Enhanced `OperationalState` integrating `network_state`, `baseline_network_state`, `state_diff`, `repair_plan`.
- `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py`: Operational nodes refactored to consume `StateDiff` and execute deterministic repair.
- `langgraph_netagent/tests/test_clab_fault_injector.py`: Test suite for Containerlab fault injection, token rollback, and context manager.
- `langgraph_netagent/tests/test_lab_isolation.py`: Test suite for host protection and container isolation.
- `langgraph_netagent/tests/test_network_state_model.py`: Test suite for `NetworkState`, `StateDiff`, and snapshotter.
- `langgraph_netagent/tests/test_agentic_reasoning_and_execution.py`: Test suite for reasoning engine, repair plan, and deterministic executor with rollback.
- `langgraph_netagent/tests/test_containerlab_experimental_loop.py`: Automated end-to-end test validating fault injection, state diff detection, deterministic repair, and recovery.
