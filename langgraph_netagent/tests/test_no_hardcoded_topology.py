"""Static and AST Grep Scanner Test for Zero Hardcoded Topology Assumptions.

Strictly verifies:
1. Absence of forbidden hardcoded IP literals:
   - 192.168.100.2
   - 203.0.113.10
   - 10.1.12.2
   - 10.2.2.0/24
   used as diagnostic fallback defaults across workflow/*.py.
2. Absence of hardcoded router/node names:
   - "dc-egress" (as routing target fallback)
   - "frr1" (as target node fallback)
3. Absence of hardcoded node-to-IP lookup tables in workflow source code.
4. Active dynamic resolution via `state["discovered_topology"]`, `state["inventory"]`,
   or telemetry data rather than static fallback rules.
"""

from __future__ import annotations

import ast
from pathlib import Path
import re
from typing import Any, Dict, List, Set, Tuple
import pytest

from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.models.intent import IntentAction
from langgraph_netagent.models.remediation import RemediationActionType, RemediationPlan
from langgraph_netagent.models.telemetry import NetworkHealthReport, QdiscTelemetry
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.workflow.operational_nodes import (
    classify_anomaly,
    create_operational_nodes,
)
from langgraph_netagent.workflow.operational_state import (
    OperationalState,
    create_operational_initial_state,
)

WORKFLOW_DIR = Path(__file__).resolve().parent.parent / "langgraph_netagent" / "workflow"


class WorkflowASTScanner(ast.NodeVisitor):
    """AST visitor to detect string constants and dictionary mappings in Python code."""

    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.string_constants: List[Tuple[int, str]] = []
        self.dict_node_ip_tables: List[Tuple[int, Dict[str, str]]] = []
        self.discovered_topology_references: List[int] = []
        self.inventory_references: List[int] = []

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.string_constants.append((node.lineno, node.value))
            if "discovered_topology" in node.value:
                self.discovered_topology_references.append(node.lineno)
            if "inventory" in node.value:
                self.inventory_references.append(node.lineno)
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in ("discovered_topology", "inventory", "inventory_pool"):
            self.discovered_topology_references.append(node.lineno)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        # Check if dict looks like a hardcoded node -> IP lookup table
        potential_table: Dict[str, str] = {}
        ip_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d+)?$")
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    if ip_regex.match(v.value):
                        # Filter out general configs like {"ipv4-subnet": "..."} or {"HOSTNET": "..."}
                        if k.value not in (
                            "ipv4-subnet", "ipv6-subnet", "HOSTNET", "HOSTNET6",
                            "ip_cidr", "subnet", "source_ip", "destination_ip",
                            "mgmt_ip", "gateway", "next_hop", "ip_addr",
                        ):
                            potential_table[k.value] = v.value
        if len(potential_table) >= 2:
            self.dict_node_ip_tables.append((node.lineno, potential_table))
        self.generic_visit(node)


class TestNoHardcodedTopologyWorkflowScanner:
    """Audit suite to strictly enforce zero hardcoded IPs, router names, and lookup tables."""

    @pytest.fixture(scope="class")
    def workflow_files(self) -> List[Path]:
        """Collect all .py source files in workflow directory."""
        assert WORKFLOW_DIR.is_dir(), f"Workflow directory not found at {WORKFLOW_DIR}"
        files = sorted(WORKFLOW_DIR.glob("*.py"))
        assert len(files) >= 10, f"Expected at least 10 workflow files, found {len(files)}"
        return files

    def test_workflow_directory_exists_and_contains_operational_nodes(self, workflow_files: List[Path]):
        """Ensure operational_nodes.py and related workflow files are present."""
        filenames = [f.name for f in workflow_files]
        assert "operational_nodes.py" in filenames
        assert "operational_state.py" in filenames
        assert "operational_edges.py" in filenames
        assert "operational_graph.py" in filenames

    def test_no_hardcoded_ip_literals_in_workflow(self, workflow_files: List[Path]):
        """Scans all workflow files for forbidden diagnostic fallback IP literals.
        
        Forbidden IPs:
        - 192.168.100.2 (previous hardcoded attacker / offending IP)
        - 203.0.113.10 (previous hardcoded VIP / target IP)
        - 10.1.12.2 (previous hardcoded next-hop IP)
        - 10.2.2.0/24 (previous hardcoded target subnet)
        """
        forbidden_ips = [
            "192.168.100.2",
            "203.0.113.10",
            "10.1.12.2",
            "10.2.2.0/24",
        ]

        violations: List[str] = []

        for py_file in workflow_files:
            source = py_file.read_text(encoding="utf-8")
            lines = source.splitlines()

            for line_no, line in enumerate(lines, start=1):
                clean_line = line.strip()
                # Skip comments
                if clean_line.startswith("#"):
                    continue

                for ip in forbidden_ips:
                    if ip in line:
                        violations.append(
                            f"{py_file.name}:{line_no}: Found forbidden IP '{ip}' in: {clean_line}"
                        )

        assert not violations, "\n".join(violations)

    def test_no_dc_egress_router_name_in_workflow(self, workflow_files: List[Path]):
        """Asserts that 'dc-egress' does NOT appear as a fallback router name in any workflow file."""
        violations: List[str] = []

        for py_file in workflow_files:
            source = py_file.read_text(encoding="utf-8")
            lines = source.splitlines()

            for line_no, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if clean_line.startswith("#"):
                    continue

                if "dc-egress" in line:
                    violations.append(
                        f"{py_file.name}:{line_no}: Found forbidden router name 'dc-egress' in: {clean_line}"
                    )

        assert not violations, "\n".join(violations)

    def test_no_frr1_target_fallback_in_operational_nodes(self, workflow_files: List[Path]):
        """Asserts that 'frr1' is completely absent from operational_nodes.py."""
        op_nodes_file = WORKFLOW_DIR / "operational_nodes.py"
        assert op_nodes_file.exists()

        source = op_nodes_file.read_text(encoding="utf-8")
        lines = source.splitlines()

        violations: List[str] = []
        for line_no, line in enumerate(lines, start=1):
            clean_line = line.strip()
            if clean_line.startswith("#"):
                continue
            if "frr1" in line:
                violations.append(
                    f"operational_nodes.py:{line_no}: Found 'frr1' in: {clean_line}"
                )

        assert not violations, "\n".join(violations)

    def test_no_frr1_as_fallback_default_in_any_workflow_file(self, workflow_files: List[Path]):
        """Asserts that 'frr1' is never used as an unconditional target fallback in any workflow file."""
        fallback_patterns = [
            re.compile(r'or\s+["\']frr1["\']'),
            re.compile(r'else\s+["\']frr1["\']'),
            re.compile(r'target_node\s*=\s*["\']frr1["\']'),
            re.compile(r'suspects\[0\]\s*if\s+suspects\s+else\s+["\']frr1["\']'),
        ]

        violations: List[str] = []
        for py_file in workflow_files:
            source = py_file.read_text(encoding="utf-8")
            lines = source.splitlines()
            for line_no, line in enumerate(lines, start=1):
                clean_line = line.strip()
                if clean_line.startswith("#"):
                    continue
                for pattern in fallback_patterns:
                    if pattern.search(line):
                        violations.append(
                            f"{py_file.name}:{line_no}: Found 'frr1' fallback pattern in: {clean_line}"
                        )

        assert not violations, "\n".join(violations)

    def test_no_hardcoded_node_to_ip_lookup_tables(self, workflow_files: List[Path]):
        """AST inspection ensuring no dictionary statically maps node names to IPs."""
        violations: List[str] = []

        for py_file in workflow_files:
            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source, filename=str(py_file))
            except SyntaxError as e:
                pytest.fail(f"Syntax error in {py_file.name}: {e}")

            scanner = WorkflowASTScanner(py_file.name)
            scanner.visit(tree)

            for line_no, table in scanner.dict_node_ip_tables:
                violations.append(
                    f"{py_file.name}:{line_no}: Found static node-to-IP lookup table: {table}"
                )

        assert not violations, "\n".join(violations)

    def test_ast_constant_scan_operational_nodes(self):
        """Parse operational_nodes.py AST and assert absence of forbidden string constants."""
        op_nodes_file = WORKFLOW_DIR / "operational_nodes.py"
        source = op_nodes_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(op_nodes_file))

        scanner = WorkflowASTScanner("operational_nodes.py")
        scanner.visit(tree)

        forbidden_strings = {
            "192.168.100.2",
            "203.0.113.10",
            "10.1.12.2",
            "10.2.2.0/24",
            "dc-egress",
            "frr1",
        }

        found_forbidden = [
            (lineno, val) for lineno, val in scanner.string_constants
            if val in forbidden_strings
        ]

        assert not found_forbidden, f"Found forbidden constants in operational_nodes.py AST: {found_forbidden}"

    def test_operational_nodes_contains_dynamic_resolution_references(self):
        """Verifies operational_nodes.py uses discovered_topology and inventory for resolution."""
        op_nodes_file = WORKFLOW_DIR / "operational_nodes.py"
        source = op_nodes_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(op_nodes_file))

        scanner = WorkflowASTScanner("operational_nodes.py")
        scanner.visit(tree)

        # Confirm multiple references to discovered_topology and inventory
        assert len(scanner.discovered_topology_references) >= 5, (
            f"Expected at least 5 references to discovered_topology in operational_nodes.py, "
            f"found {len(scanner.discovered_topology_references)}"
        )
        assert len(scanner.inventory_references) >= 5, (
            f"Expected at least 5 references to inventory in operational_nodes.py, "
            f"found {len(scanner.inventory_references)}"
        )

        # Check key helper method calls exist in source
        assert "resolve_next_hop" in source
        assert "node_roles" in source
        assert "find_peer_interfaces" in source
        assert "get_node_subnets" in source

    def test_runtime_resolution_with_arbitrary_topology_no_fallback(self):
        """Functional verification: operational_nodes processes arbitrary custom topology names and IPs.
        
        Uses synthetic node 'core-gw-alpha' and IPs '198.18.10.1' / '198.18.20.99'.
        Confirms anomaly classification and remediation plan output dynamically derived values
        without falling back to any static names.
        """
        synth_iface_gw = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["198.18.10.1/24"]),
            "eth2": DiscoveredInterface(name="eth2", ipv4_addresses=["198.18.20.1/24"]),
        }
        gw_node = DiscoveredNode(
            name="core-gw-alpha",
            kind="linux",
            role="router",
            interfaces=synth_iface_gw,
            ips=["198.18.10.1/24", "198.18.20.1/24"],
        )

        synth_iface_bad = {
            "eth1": DiscoveredInterface(name="eth1", ipv4_addresses=["198.18.10.77/24"]),
        }
        bad_node = DiscoveredNode(
            name="rogue-client-77",
            kind="linux",
            role="attacker",
            interfaces=synth_iface_bad,
            ips=["198.18.10.77/24"],
        )

        synth_links = [
            DiscoveredLink(
                endpoints=[("rogue-client-77", "eth1"), ("core-gw-alpha", "eth1")],
                local_node="rogue-client-77",
                local_iface="eth1",
                remote_node="core-gw-alpha",
                remote_iface="eth1",
            ),
        ]

        topo = DiscoveredTopology(
            name="synth-verification-lab",
            nodes={"core-gw-alpha": gw_node, "rogue-client-77": bad_node},
            links=synth_links,
            subnets=["198.18.10.0/24", "198.18.20.0/24"],
            ip_to_node={
                "198.18.10.1": "core-gw-alpha",
                "198.18.20.1": "core-gw-alpha",
                "198.18.10.77": "rogue-client-77",
            },
            vips=["198.18.20.99"],
            node_roles={"core-gw-alpha": "router", "rogue-client-77": "attacker"},
            routers=["core-gw-alpha"],
            hosts=["rogue-client-77"],
        )

        health_report = NetworkHealthReport(
            all_passed=False,
            failures=["Buffer overlimit on core-gw-alpha:eth1"],
            buffer_anomalies=[
                {
                    "node": "core-gw-alpha",
                    "interface": "eth1",
                    "dropped": 500,
                    "overlimits": 1200,
                }
            ],
            qdisc_stats={
                "core-gw-alpha": [
                    QdiscTelemetry(
                        node="core-gw-alpha",
                        interface="eth1",
                        qdisc_type="tbf",
                        dropped=500,
                        overlimits=1200,
                    )
                ]
            },
        )

        anomaly = classify_anomaly(health_report, discovered_topology=topo)
        assert anomaly.category == "external_overload"
        assert anomaly.bottleneck_node == "core-gw-alpha"
        assert anomaly.bottleneck_interface == "eth1"
        assert anomaly.offending_source_ip == "198.18.10.77"
        assert anomaly.victim_destination_ip == "198.18.20.99"

        # Explicitly assert absence of any old hardcoded values
        assert anomaly.bottleneck_node != "dc-egress"
        assert anomaly.bottleneck_node != "frr1"
        assert anomaly.offending_source_ip != "192.168.100.2"
        assert anomaly.victim_destination_ip != "203.0.113.10"
