# Handoff Report: R2 Telemetry Collection, Anomaly Detection & 5-Tuple Extraction Survey

**Target Subsystem**: `langgraph_netagent` Telemetry & Anomaly Processing Engine  
**Author**: Explorer Subagent (`explorer_survey_2`)  
**Date**: 2026-09-27  
**Working Directory**: `e:\netops-ai-agent\.agents\teamwork\explorer_survey_2`  
**Reference Request**: `e:\netops-ai-agent\.agents\teamwork\ORIGINAL_REQUEST.md` (`## Follow-up — 2026-09-27T10:37:02Z`)

---

## 1. Observation

### 1.1 Test Suite & Baseline Execution
- Executing `pytest tests -q` inside `e:\netops-ai-agent\langgraph_netagent` yields:
  ```
  677 passed in 8.59s
  ```
  All 677 existing automated tests are currently passing 100%. Any R2 enhancements must strictly maintain zero regressions across all 677 tests.

### 1.2 Telemetry Extraction Node & State Machine Wiring
- **State Machine Wiring**:
  - `langgraph_netagent/langgraph_netagent/workflow/operational_graph.py`:
    - Line 100-101: `graph.add_edge(START, "baseline_ingestion")` and `graph.add_edge("baseline_ingestion", "telemetry_extraction")`
    - Line 104-111:
      ```python
      graph.add_conditional_edges(
          "telemetry_extraction",
          route_after_telemetry,
          {
              "end_healthy": "end_healthy",
              "diagnostic_stage1": "diagnostic_stage1",
          },
      )
      ```
  - `langgraph_netagent/langgraph_netagent/workflow/operational_edges.py`:
    - Lines 14-38: `route_after_telemetry(state: OperationalState)` routes to `"end_healthy"` only if `telemetry_results.get("all_passed") is True` AND `failure_5tuples == []` AND `discrepancies == []`; otherwise routes to `"diagnostic_stage1"`.
- **Node Implementation**:
  - `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py`:
    - Lines 124-338: `telemetry_extraction_node(state: OperationalState) -> Dict[str, Any]`
    - Line 135-151: Builds Ping probe matrix between all Linux PC nodes and invokes `NetworkTelemetryCollector.collect(...)`.
    - Lines 159-172: Ingests `initial_alerts` from state, parsing each with `FiveTuple.from_syslog(...)`.
    - Lines 174-185: Ingests ping failures and converts them via `FiveTuple.from_ping_failure(...)`.
    - Lines 203-241: Executes adjacent hop-by-hop segment pings between nodes in `topology_path` to isolate link drops.
    - Lines 250-306: Checks routers for missing routes against subnets in `inventory_pool` using `ipaddress.IPv4Network.subnet_of`.
    - Lines 328-338: Returns `{telemetry_results, probe_results, failure_5tuples, discrepancies, suspect_devices, affected_segments, status, execution_logs}`.

### 1.3 Currently Collected Telemetry Metrics & Gaps
1. **Connectivity (Ping)**:
   - `langgraph_netagent/langgraph_netagent/models/telemetry.py` (lines 9-25) & `tools/probes.py` (`PingProbe`, lines 18-110).
   - Metrics: `src_node`, `dst_ip`, `transmitted`, `received`, `loss_pct`, `rtt_min_ms`, `rtt_avg_ms`, `rtt_max_ms`, `rtt_mdev_ms`, `is_reachable`, `error_message`.
2. **Routing Tables**:
   - `models/telemetry.py` (`RouteEntry`, `RouteTableTelemetry`, lines 27-58) & `tools/probes.py` (`RouteTableProbe`, lines 112-306).
   - Metrics: `destination`, `next_hop`, `interface`, `protocol` (static, connected, bgp, ospf), `has_default_route`.
3. **Interface State**:
   - `models/telemetry.py` (`InterfaceTelemetry`, lines 59-72) & `tools/probes.py` (`InterfaceProbe`, lines 308-386).
   - Metrics: `admin_state` (UP/DOWN), `oper_state` (UP/DOWN/LOWER_UP/UNKNOWN), `ip_addresses`, `mtu`, `mac_address`, `is_healthy`.
4. **Syslog / Alert 5-Tuples**:
   - `models/operational.py` (`FiveTuple`, lines 19-224).
   - Parsed patterns: IPTables/Netfilter (`SRC=... DST=... PROTO=... SPT=... DPT=...`), Cisco ACL denied, Juniper flow, BGP/OSPF/ISIS adjacency down.
5. **Observed Gaps vs R2 Architecture**:
   - **No Qdisc / Buffer Overlimit Telemetry**: No probe queries `tc -s qdisc show` or collects `overlimits`, `dropped`, or `backlog`.
   - **No Hardware / Interface Packet Loss**: `InterfaceProbe` only parses `ip addr show` (flags/IPs), not `ip -s link show` (RX/TX dropped, overruns, errors).
   - **No Traffic Overload / Flow Saturation Sensing**: No socket or conntrack summary (`ss -s`, `conntrack -L`) to detect SYN floods or bandwidth saturation.
   - **No Anomaly Classification**: The current code flags discrepancies as `"missing_route"`, `"reachability_loss"`, or `"interface_down"`, but lacks logic to classify whether an incident is `"single_exit_failure"` vs `"external_overload"`.

### 1.4 Real-World Environment & Attack Suite Ground Truth
- Investigation of `e:\netops-ai-agent\setup_real_network.sh` and `/home/zbr/Containerlab/containerlab/run_realistic_attack_suite.py`:
  - **Topology**: `clos5` with `attacker` (192.168.100.2), `ext-router` (203.0.113.2 / 192.168.100.1), `dc-egress` (203.0.113.1, VIPs 203.0.113.10~40 DNAT to `h1~h4`), and FRR Clos fabric.
  - **Traffic Control Constraints** (`setup_real_network.sh` lines 37-55):
    - `ext-router:eth1`: `tc qdisc add dev eth1 root handle 1: netem delay 8ms 1ms; tc qdisc add dev eth1 parent 1: handle 10: tbf rate 50mbit burst 16kbit limit 32k`
    - `dc-egress:eth2`: `tc qdisc add dev eth2 root handle 1: netem delay 8ms 1ms; tc qdisc add dev eth2 parent 1: handle 10: tbf rate 50mbit burst 16kbit limit 32k`
  - **Observed Behavior During Attack** (`attack_logs/attack_report_realistic.json` & `attack_logs/attack_execution_realistic.log`):
    - During Phase 2 (HTTP flood), Phase 3 (TCP SYN flood), Phase 4 (150M UDP blast vs 50M WAN pipe), and Phase 5 (Hybrid storm):
      - **ICMP Ping packet loss remained at 0%** (`PING 203.0.113.10: 0% packet loss, RTT ~24-27ms`).
      - But `tc -s qdisc show dev eth1` showed massive queue drops and buffer overlimits:
        ```
        qdisc tbf 10: parent 1: rate 50Mbit burst 2Kb lat 4.9ms 
         Sent 426714991 bytes 4281816 pkt (dropped 1957605, overlimits 14508935 requeues 0)
        ```
        `overlimits` surged from 14,071,085 to 17,386,933, and dropped packets exceeded 1,957,605.
    - **Crucial Ground Truth**: Ping alone **completely fails** to detect buffer saturation and external traffic floods when ICMP is unthrottled or low volume. Only inspecting `tc qdisc` overlimits/drops and interface drop counters reveals the incident.

---

## 2. Logic Chain

```
[Observation 1.1: 677 tests pass] + [Observation 1.3: Gaps in Qdisc/Buffer]
  │
  ├─► Step 1: Any extension must be additive and optional in schema to preserve 677 passing tests.
  │
[Observation 1.4: Real attack logs show tc overlimits rise while ping = 0% loss]
  │
  ├─► Step 2: `telemetry_extraction` must incorporate `QdiscProbe` (`tc -s qdisc show`)
  │   and `InterfaceStatsProbe` (`ip -s link show`) alongside `PingProbe` and `RouteTableProbe`.
  │
[Observation 1.2: telemetry_extraction extracts 5-tuples and discrepancies]
  │
  ├─► Step 3: When overlimits/drops exceed threshold, `telemetry_extraction` must:
  │   (a) Generate `NetworkDiscrepancy(discrepancy_type="buffer_overlimit")`.
  │   (b) Extract `FiveTuple` representing the overload (target IP/port from VIP/conntrack, source from attacker prefix).
  │
[Requirement R2: Classify single-exit vs external overload]
  │
  ├─► Step 4: Classify anomaly root cause:
  │   - IF route missing or egress link down, and traffic is normal/zero:
  │     => "single_exit_failure" (egress path failure).
  │   - IF route is intact, but tc overlimits/drops surge and source is external:
  │     => "external_overload" (volumetric flood / attack).
  │
  └─► Step 5: Route downstream into Stage-1/Stage-2 diagnosis with classification context.
```

---

## 3. Caveats

1. **Live Container Privilege**: In live mode on Linux/WSL, executing `tc -s qdisc show` requires standard non-root execution inside container namespaces, but modifying `tc` or `iptables` requires `NET_ADMIN` privileges in Docker. In mock mode, this is simulated hermetically without any privileges.
2. **Mock Mode Fidelity**: Mock engine currently returns `mock: executed '...' successfully` for `tc`. To test the complete closed-loop self-healing in unit tests, `MockEngine` must be enhanced to simulate `tc -s qdisc show` based on injected `FaultRule(fault_type=BUFFER_OVERLIMIT)`.
3. **Threshold Tuning**: In real networks, `overlimits` is a cumulative counter since interface creation. Anomaly detection should evaluate either `overlimits > 0` (for initial probe) or delta `(overlimits_now - overlimits_baseline) > threshold` (for continuous monitoring).

---

## 4. Conclusion & R2 Specification

### 4.1 Required Data Model Additions

#### In `langgraph_netagent/langgraph_netagent/models/telemetry.py`:
```python
class QdiscTelemetry(BaseModel):
    """Structured telemetry output from Linux traffic control (tc) queue inspection."""
    model_config = ConfigDict(populate_by_name=True)

    node: str = Field(..., description="Node name where qdisc was queried")
    interface: str = Field(..., description="Network interface name")
    qdisc_type: str = Field(..., description="Qdisc algorithm: tbf, netem, fq_codel, pfifo_fast")
    handle: str = Field(default="", description="Qdisc handle ID (e.g. 1:, 10:)")
    parent: Optional[str] = Field(None, description="Parent handle if nested")
    bytes_sent: int = Field(default=0, ge=0)
    packets_sent: int = Field(default=0, ge=0)
    dropped: int = Field(default=0, ge=0, description="Packets dropped by queue or buffer overflow")
    overlimits: int = Field(default=0, ge=0, description="Buffer overlimits / rate throttle occurrences")
    requeues: int = Field(default=0, ge=0)
    backlog_bytes: int = Field(default=0, ge=0)
    backlog_packets: int = Field(default=0, ge=0)
    raw_output: str = Field(default="", description="Raw command stdout")


class InterfaceStatsTelemetry(BaseModel):
    """Hardware/kernel interface packet counters from 'ip -s link show'."""
    model_config = ConfigDict(populate_by_name=True)

    node: str
    interface: str
    rx_packets: int = 0
    rx_bytes: int = 0
    rx_errors: int = 0
    rx_dropped: int = 0
    tx_packets: int = 0
    tx_bytes: int = 0
    tx_errors: int = 0
    tx_dropped: int = 0
```

Add to `NetworkHealthReport`:
- `qdisc_stats: Dict[str, List[QdiscTelemetry]] = Field(default_factory=dict)`
- `interface_stats: Dict[str, List[InterfaceStatsTelemetry]] = Field(default_factory=dict)`
- `buffer_anomalies: List[Dict[str, Any]] = Field(default_factory=list)`

#### In `langgraph_netagent/langgraph_netagent/models/operational.py`:
```python
class AnomalyClassification(BaseModel):
    """Categorization of detected network anomaly."""
    category: Literal["single_exit_failure", "external_overload", "internal_link_failure", "healthy"]
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    reason: str
    bottleneck_node: Optional[str] = None
    bottleneck_interface: Optional[str] = None
    offending_source_ip: Optional[str] = None
    victim_destination_ip: Optional[str] = None
    recommended_action: str
```

Enhance `FiveTuple`:
- Add constructor:
  ```python
  @classmethod
  def from_traffic_overload(
      cls,
      src_ip: str,
      dst_ip: str,
      protocol: str = "TCP",
      src_port: int = 0,
      dst_port: int = 80,
      overlimits: int = 0,
      dropped: int = 0,
      raw_log: Optional[str] = None,
  ) -> "FiveTuple":
      return cls(
          source_ip=src_ip,
          destination_ip=dst_ip,
          protocol=protocol.upper(),
          source_port=src_port,
          destination_port=dst_port,
          alert_type="TRAFFIC_OVERLOAD",
          raw_log=raw_log or f"Buffer overload: {dropped} dropped, {overlimits} overlimits on path {src_ip} -> {dst_ip}:{dst_port}",
      )
  ```

---

### 4.2 Probes Implementation in `tools/probes.py`

#### `QdiscProbe`:
```python
class QdiscProbe:
    """Probes Linux traffic control (tc) qdiscs for buffer overlimits and packet drops."""

    QDISC_HEADER_RE = re.compile(
        r"qdisc\s+(?P<type>\w+)\s+(?P<handle>[\w:]+)(?:\s+parent\s+(?P<parent>[\w:]+)|(?:\s+root))?",
        re.IGNORECASE,
    )
    STATS_RE = re.compile(
        r"Sent\s+(?P<bytes>\d+)\s+bytes\s+(?P<pkts>\d+)\s+pkt\s+\(dropped\s+(?P<dropped>\d+),\s+overlimits\s+(?P<overlimits>\d+)(?:,\s+requeues\s+(?P<requeues>\d+))?",
        re.IGNORECASE,
    )
    BACKLOG_RE = re.compile(
        r"backlog\s+(?P<b_bytes>\d+)[bB]\s+(?P<b_pkts>\d+)[pP]",
        re.IGNORECASE,
    )

    @classmethod
    def run(
        cls,
        adapter: BaseNetworkLabAdapter,
        node: str,
        interface: Optional[str] = None,
        timeout: int = 5,
    ) -> List[QdiscTelemetry]:
        cmd = f"tc -s qdisc show dev {interface}" if interface else "tc -s qdisc show"
        res = adapter.exec_command(node_name=node, command=cmd, timeout=timeout)
        return cls.parse_tc_output(node=node, raw_output=res.stdout)

    @classmethod
    def parse_tc_output(cls, node: str, raw_output: str) -> List[QdiscTelemetry]:
        # Parses multiline tc output into List[QdiscTelemetry]
```

#### Integration in `NetworkTelemetryCollector.collect(...)`:
- For each router/gateway node in `router_nodes`:
  - Run `QdiscProbe.run(...)`.
  - If any qdisc has `dropped > 0` or `overlimits > 0`:
    - Record anomaly in `buffer_anomalies`.
    - Append to `failures`: `f"Buffer overlimit on {node}:{qdisc.interface}: {qdisc.dropped} dropped, {qdisc.overlimits} overlimits"`.
    - Append to `recommendations`: `f"Apply border filtering / rate-limiting on {node} for high-volume ingress flows"`.
    - Set `all_passed = False`.

---

### 4.3 5-Tuple Extraction & Anomaly Classifier Logic

#### In `telemetry_extraction_node`:
1. **Extraction Sources**:
   - (1) Ping reachability failure: extracts `src_ip`, `dst_ip`, ICMP.
   - (2) Syslog / alerts: parsed by `FiveTuple.from_syslog`.
   - (3) Buffer Overlimits / High Traffic:
     - Target VIP / destination extracted from node interfaces / DNAT rules (e.g. `203.0.113.10`).
     - Port identified from active sockets (`ss -tan`, `conntrack -L`, or default 80/5201).
     - Source IP: external untrusted prefix (e.g. `192.168.100.0/24` or `192.168.100.2`).
     - Produces `FiveTuple.from_traffic_overload(...)`.
2. **Decision Matrix: Single-Exit Failure vs External Overload**:
   ```python
   def classify_anomaly(
       report: NetworkHealthReport,
       discrepancies: List[NetworkDiscrepancy],
       failure_5tuples: List[FiveTuple],
       inventory: Dict[str, Any],
   ) -> AnomalyClassification:
       has_missing_route = any(d.discrepancy_type == "missing_route" for d in discrepancies)
       has_iface_down = any(d.discrepancy_type == "interface_down" for d in discrepancies)
       has_buffer_overlimit = any(
           d.discrepancy_type in ("buffer_overlimit", "traffic_overload") for d in discrepancies
       ) or (len(report.buffer_anomalies) > 0)

       # Rule 1: External Volumetric Overload
       if has_buffer_overlimit:
           # Routes are intact; queue buffer is overflowing
           top_5t = next((f for f in failure_5tuples if f.alert_type == "TRAFFIC_OVERLOAD"), None)
           src = top_5t.source_ip if top_5t else "external"
           dst = top_5t.destination_ip if top_5t else "internal_vip"
           return AnomalyClassification(
               category="external_overload",
               confidence=0.95,
               reason="Qdisc buffer overlimits and packet drops detected under high ingress traffic with valid routing table",
               bottleneck_node=report.buffer_anomalies[0]["node"] if report.buffer_anomalies else "gateway",
               bottleneck_interface=report.buffer_anomalies[0]["interface"] if report.buffer_anomalies else "eth1",
               offending_source_ip=src,
               victim_destination_ip=dst,
               recommended_action="Deploy border iptables packet filtering and rate-limiting at ingress edge router/gateway",
           )

       # Rule 2: Single-Exit Failure
       if has_missing_route or has_iface_down:
           missing_d = next((d for d in discrepancies if d.discrepancy_type in ("missing_route", "interface_down")), None)
           return AnomalyClassification(
               category="single_exit_failure",
               confidence=0.95,
               reason=f"Routing or egress interface missing on exit device '{missing_d.node if missing_d else 'router'}'",
               bottleneck_node=missing_d.node if missing_d else None,
               bottleneck_interface=missing_d.affected_interface if missing_d else None,
               recommended_action="Inject missing route into FIB or restore interface operstate via AAL",
           )

       # Rule 3: Internal Segment Link Failure
       if any(d.discrepancy_type == "reachability_loss" for d in discrepancies):
           return AnomalyClassification(
               category="internal_link_failure",
               confidence=0.85,
               reason="Adjacent hop link drop detected between internal fabric nodes",
               recommended_action="Verify physical link and restart interface",
           )

       return AnomalyClassification(
           category="healthy",
           confidence=1.0,
           reason="All connectivity, route tables, and queue buffers operating within healthy baselines",
           recommended_action="No remediation needed",
       )
   ```

---

### 4.4 Mock Engine Support & Hermetic Test Fixtures

#### In `tools/fault_injector.py`:
- Add `FaultType.BUFFER_OVERLIMIT = "buffer_overlimit"` and `FaultType.TRAFFIC_OVERLOAD = "traffic_overload"`.
- Add fields in `FaultRule`:
  - `overlimits: int = 15000`
  - `dropped: int = 5000`
  - `source_ip: Optional[str] = None`
  - `dest_port: Optional[int] = None`
- In `on_remediation(...)`:
  - If candidate patch executes an `iptables` drop rule matching `rule.source_ip` or `rule.dest_port`, auto-clear the `BUFFER_OVERLIMIT` fault rule.

#### In `tools/mock_engine.py`:
- In `exec_command(self, node_name: str, command: str, ...)`:
  - If `command.startswith("tc ")` or `" tc "` in command:
    - Route to `simulate_tc_command(node_name, command)`.
    - If `node_name` has an active `BUFFER_OVERLIMIT` rule:
      ```
      qdisc tbf 10: parent 1: rate 50Mbit burst 2Kb lat 4.9ms 
       Sent 426714991 bytes 4281816 pkt (dropped 5000, overlimits 15000 requeues 0) 
       backlog 0b 0p requeues 0
      ```
    - Otherwise, return clean zero-drop qdisc stats:
      ```
      qdisc fq_codel 0: dev eth1 root refcnt 2 limit 10240p flows 1024 quantum 1514 
       Sent 1024 bytes 12 pkt (dropped 0, overlimits 0 requeues 0)
      ```

---

### 4.5 SOP Knowledge Playbook Addition (`tools/sop_retriever.py`)
Add `SOP-OVERLOAD-005` to `DEFAULT_SOPS`:
- **ID**: `SOP-OVERLOAD-005`
- **Title**: `Border Gateway Buffer Overlimit and External Traffic Overload Mitigation`
- **Category**: `TRAFFIC_OVERLOAD`
- **Keywords**: `["overlimits", "buffer", "qdisc", "tc", "ddos", "traffic_overload", "packet_drop", "external_overload", "syn_flood", "udp_blast"]`
- **Remediation Template**:
  - `iptables -I FORWARD -s {source_ip} -d {destination_ip} -p {protocol} --dport {destination_port} -j DROP`
  - `iptables -I FORWARD -s {source_ip} -j DROP`
- **Rollback Template**:
  - `iptables -D FORWARD -s {source_ip} -d {destination_ip} -p {protocol} --dport {destination_port} -j DROP`

---

## 5. Verification Method

### 5.1 Independent Test Commands
Execute the complete test suite in `e:\netops-ai-agent\langgraph_netagent`:
```powershell
pytest tests -q
```
*Expected Result*: All 677 existing tests must pass with zero failures or regressions.

Execute targeted R2 telemetry tests:
```powershell
pytest tests/test_operational_r2_telemetry.py -v
```
*Test Cases to Include*:
1. `test_qdisc_probe_parsing`: Verifies `QdiscProbe.parse_tc_output` accurately parses multi-line `tc -s qdisc show` output with drops, overlimits, handles, and backlog.
2. `test_interface_stats_probe_parsing`: Verifies `InterfaceStatsProbe` parses `ip -s link show` packets/drops.
3. `test_telemetry_extraction_node_detects_buffer_overlimit`: Injects `FaultRule(fault_type=BUFFER_OVERLIMIT)` into mock adapter, runs `telemetry_extraction_node`, verifies `NetworkDiscrepancy(discrepancy_type="buffer_overlimit")` is populated, and status becomes `"fault_detected"`.
4. `test_5tuple_extraction_from_overload`: Verifies `FiveTuple` is populated with `alert_type="TRAFFIC_OVERLOAD"`, source IP, destination VIP, protocol, and port.
5. `test_anomaly_classifier_single_exit_vs_external_overload`:
   - Case A: Missing route -> classified as `"single_exit_failure"` with confidence >= 0.9.
   - Case B: Overlimits > 0 -> classified as `"external_overload"` with confidence >= 0.9.
6. `test_closed_loop_self_healing_for_buffer_overload`: Runs the complete operational state machine with `auto_approve=True`, verifies Stage 2 generates `iptables` drop patch, shadow sandbox validates it, live hot-patch applies it, fault rule clears, and post-verification transitions state to `"fixed"`.

### 5.2 Invalidation Conditions
- Invalidation occurs if:
  1. Any of the existing 677 tests fail.
  2. `tc -s qdisc show` execution causes command blocking in AAL. (Verified: `tc` is not in `BLOCKED_PATTERNS`).
  3. `telemetry_extraction_node` falsely flags normal zero-drop networks as overlimits. (Guarded by `dropped > 0` or `overlimits > 0` checks).
