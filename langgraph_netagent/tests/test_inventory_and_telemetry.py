"""Unit Tests for Inventory Pool Extraction, Telemetry 5-Tuple, and Discrepancy Isolation.

Verifies:
1. Baseline ingestion & asset/IP inventory pool extraction.
2. 5-Tuple parsing from ping reachability drop and syslog alerts.
3. Observed network state comparison against baseline to isolate single-exit discrepancies.
"""

from pathlib import Path
import pytest

from langgraph_netagent.models.operational import FiveTuple, InventoryPool
from langgraph_netagent.tools.baseline import BaselineCollector
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter


@pytest.fixture
def deployed_adapter():
    adapter = MockContainerlabAdapter()
    for candidate in [
        Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
        Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
    ]:
        if candidate.exists():
            adapter.deploy(candidate)
            break
    return adapter


class TestInventoryPool:
    """Verify inventory pool extraction from baseline snapshot."""

    def test_extract_inventory_pool_from_baseline(self, deployed_adapter):
        baseline = BaselineCollector.collect(adapter=deployed_adapter)
        pool = InventoryPool.from_baseline(baseline)

        assert len(pool.assets) >= 3
        assert "pc1" in pool.assets
        assert "frr1" in pool.assets
        assert "pc2" in pool.assets
        # Subnets extracted
        assert any("10.1.1.0/24" in s for s in pool.subnets)
        # Interfaces mapped
        assert "eth1" in pool.interfaces.get("pc1", [])
        assert "eth1" in pool.interfaces.get("frr1", [])
        assert "eth2" in pool.interfaces.get("frr1", [])
        # Baseline routes populated
        assert "frr1" in pool.baseline_routes


class TestFiveTupleExtraction:
    """Verify 5-tuple failure extraction from probes and syslog."""

    def test_from_ping_failure(self):
        five_tuple = FiveTuple.from_ping_failure(
            src_ip="10.1.1.2",
            dst_ip="10.2.2.2",
            failure_msg="100% packet loss",
        )
        assert five_tuple.source_ip == "10.1.1.2"
        assert five_tuple.destination_ip == "10.2.2.2"
        assert five_tuple.protocol == "ICMP"
        assert five_tuple.alert_type == "PACKET_DROP"

    def test_from_syslog_drop(self):
        log = "DROP 10.1.1.2:54321 -> 10.2.2.2:80 proto=TCP"
        five_tuple = FiveTuple.from_syslog(log)
        assert five_tuple is not None
        assert five_tuple.source_ip == "10.1.1.2"
        assert five_tuple.destination_ip == "10.2.2.2"
        assert five_tuple.source_port == 54321
        assert five_tuple.destination_port == 80
        assert five_tuple.protocol == "TCP"

    def test_from_syslog_bgp_alert(self):
        log = "%BGP-5-ADJCHANGE: neighbor 10.1.12.2 Down - Peer closed connection"
        five_tuple = FiveTuple.from_syslog(log)
        assert five_tuple is not None
        assert five_tuple.destination_ip == "10.1.12.2"
        assert five_tuple.protocol == "TCP"
        assert five_tuple.destination_port == 179
        assert five_tuple.alert_type == "BGP_SESSION_DOWN"
