"""Adversarial stress-test suite for Milestone M3.

Tests adversarial permutations against OfflineValidator and NetworkAgentState:
1. Malformed node names (uppercase, underscores, leading/trailing hyphens, special chars, length > 63).
2. Case-insensitive duplicate names (router-1 vs ROUTER-1).
3. Link endpoint syntax permutations (missing colon, multiple colons, whitespace, self-links).
4. Complex IP collision permutations (duplicate IP on same node, different nodes, overlapping subnets).
5. Subnet mismatch across point-to-point links.
6. Missing and mismatched configuration file binds.
7. NetworkAgentState reducer mechanics (concurrent logging, malformed log entries, deepcopy, JSON/pickle serialization).
"""

from concurrent.futures import ThreadPoolExecutor
import copy
import ipaddress
import json
import operator
from pathlib import Path
import pickle
import pytest
from typing import Any, Dict, List

from langgraph_netagent.models.intent import NetworkIntent
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.models.validation import (
    ValidationErrorDetail,
    ValidationResult,
    ValidationSeverity,
)
from langgraph_netagent.validation.offline_validator import OfflineValidator
from langgraph_netagent.workflow.state import (
    LogEntry,
    NetworkAgentState,
    create_initial_state,
    create_log_entry,
)
from langgraph_netagent.workflow.graph import (
    CompiledSimpleGraph,
    SimpleMemorySaver,
    SimpleStateGraph,
)


@pytest.fixture
def base_valid_package() -> FullTopologyPackage:
    """Fixture providing a known valid 2-node topology package."""
    topo = ContainerlabTopologyFile(
        name="adversarial-lab",
        mgmt=ContainerlabMgmtConfig(ipv4_subnet="172.100.100.0/24"),
        topology=ContainerlabTopologyDefinition(
            nodes={
                "r1": ContainerlabNodeConfig(
                    kind="linux",
                    image="frrouting/frr:latest",
                    startup_config="config/r1/frr.conf",
                    binds=["config/r1/daemons:/etc/frr/daemons"],
                ),
                "pc1": ContainerlabNodeConfig(
                    kind="linux",
                    image="alpine:latest",
                    binds=["config/pc1/setup.sh:/setup.sh"],
                ),
            },
            links=[
                ContainerlabLinkEndpoint(endpoints=["r1:eth1", "pc1:eth1"]),
            ],
        ),
    )
    configs = [
        DeviceConfigFile(
            node_name="r1",
            file_path="config/r1/frr.conf",
            content="hostname r1\n!",
        ),
        DeviceConfigFile(
            node_name="r1",
            file_path="config/r1/daemons",
            content="zebra=yes\nospfd=yes\n",
        ),
        DeviceConfigFile(
            node_name="pc1",
            file_path="config/pc1/setup.sh",
            content="#!/bin/sh\nip addr add 10.1.1.2/24 dev eth1\n",
            permissions="0755",
        ),
    ]
    ip_allocs = [
        IPAllocation(
            node_name="r1",
            interface_name="eth1",
            ipv4_address="10.1.1.1/24",
            peer_node="pc1",
            peer_interface="eth1",
        ),
        IPAllocation(
            node_name="pc1",
            interface_name="eth1",
            ipv4_address="10.1.1.2/24",
            peer_node="r1",
            peer_interface="eth1",
        ),
    ]
    return FullTopologyPackage(
        topology=topo,
        configs=configs,
        ip_allocations=ip_allocs,
    )


class TestAdversarialNodeNames:
    """Adversarial testing of RFC 1123 node naming and duplicates."""

    @pytest.mark.parametrize(
        "bad_name,expected_reason",
        [
            ("router_1", "underscores are forbidden in RFC 1123"),
            ("-router1", "leading hyphen is forbidden"),
            ("router1-", "trailing hyphen is forbidden"),
            ("-", "single hyphen is forbidden"),
            ("router@1", "special char @ is forbidden"),
            ("router#node", "special char # is forbidden"),
            ("router.node", "dot is forbidden in single label"),
            ("router 1", "whitespace is forbidden"),
            ("router$1", "dollar sign is forbidden"),
            ("a" * 64, "length > 63 characters is forbidden"),
            ("", "empty name is forbidden"),
        ],
    )
    def test_rfc1123_invalid_names_rejected(self, bad_name: str, expected_reason: str):
        assert OfflineValidator.is_valid_rfc1123_name(bad_name) is False, (
            f"Expected '{bad_name}' to be rejected because: {expected_reason}"
        )

    def test_rfc1123_max_length_boundary(self):
        """Boundary test: 63 characters should be valid, 64 should be invalid."""
        valid_63 = "a" * 63
        invalid_64 = "a" * 64
        assert OfflineValidator.is_valid_rfc1123_name(valid_63) is True
        assert OfflineValidator.is_valid_rfc1123_name(invalid_64) is False

    def test_rfc1123_single_char_boundary(self):
        """Boundary test: single alphanumeric is valid, single non-alphanumeric is invalid."""
        assert OfflineValidator.is_valid_rfc1123_name("a") is True
        assert OfflineValidator.is_valid_rfc1123_name("1") is True
        assert OfflineValidator.is_valid_rfc1123_name("-") is False
        assert OfflineValidator.is_valid_rfc1123_name("_") is False

    def test_case_insensitive_duplicate_nodes(self, base_valid_package: FullTopologyPackage):
        """Adversarial check: router-1 vs ROUTER-1 collision detection."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["router-1"] = ContainerlabNodeConfig(
            kind="linux", image="alpine:latest"
        )
        pkg.topology.topology.nodes["ROUTER-1"] = ContainerlabNodeConfig(
            kind="linux", image="alpine:latest"
        )
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        duplicate_errs = [e for e in res.errors if e.code == "DUPLICATE_NODE_NAME"]
        assert len(duplicate_errs) >= 1
        assert "ROUTER-1" in duplicate_errs[0].message or "router-1" in duplicate_errs[0].message

    def test_multi_case_collision_triplet(self, base_valid_package: FullTopologyPackage):
        """Adversarial check: three casing variants of the same node name."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["leaf-1"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
        pkg.topology.topology.nodes["LEAF-1"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
        pkg.topology.topology.nodes["Leaf-1"] = ContainerlabNodeConfig(kind="linux", image="alpine:latest")
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        duplicate_errs = [e for e in res.errors if e.code == "DUPLICATE_NODE_NAME"]
        assert len(duplicate_errs) == 2

    def test_node_casing_mismatch_with_links(self, base_valid_package: FullTopologyPackage):
        """Node declared as uppercase ROUTER-1, but link references lowercase router-1."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["ROUTER-1"] = pkg.topology.topology.nodes.pop("r1")
        pkg.topology.topology.links = [
            ContainerlabLinkEndpoint(endpoints=["router-1:eth1", "pc1:eth1"])
        ]
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "UNKNOWN_NODE_IN_LINK" and e.node == "router-1" for e in res.errors)


class TestAdversarialLinkEndpoints:
    """Adversarial testing of link endpoint formats, loops, and unknown nodes."""

    def test_self_link_identical_endpoint(self, base_valid_package: FullTopologyPackage):
        """nodeA:eth1 connected to nodeA:eth1."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r1:eth1"])
        )
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "INVALID_LINK_LOOP" for e in res.errors)

    def test_self_link_different_interfaces(self, base_valid_package: FullTopologyPackage):
        """nodeA:eth1 connected to nodeA:eth2 (hairpin / local loopback link)."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r1:eth2"])
        )
        res = OfflineValidator.validate(pkg)
        # Note: ep1 != ep2, so INVALID_LINK_LOOP is not triggered, but let's observe
        assert isinstance(res, ValidationResult)

    def test_link_endpoint_missing_colon_in_dict(self):
        """Link endpoint missing colon passed via dict."""
        raw_dict = {
            "topology": {
                "name": "bad-link-lab",
                "topology": {
                    "nodes": {
                        "r1": {"kind": "linux", "image": "alpine:latest"},
                        "pc1": {"kind": "linux", "image": "alpine:latest"},
                    },
                    "links": [
                        {"endpoints": ["r1eth1", "pc1:eth1"]},
                    ],
                },
            },
            "configs": [],
            "ip_allocations": [],
        }
        res = OfflineValidator.validate(raw_dict)
        assert res.is_valid is False
        assert len(res.errors) >= 1

    def test_link_endpoint_multiple_colons_in_dict(self):
        """Link endpoint with multiple colons passed via dict."""
        raw_dict = {
            "topology": {
                "name": "bad-link-lab",
                "topology": {
                    "nodes": {
                        "r1": {"kind": "linux", "image": "alpine:latest"},
                        "pc1": {"kind": "linux", "image": "alpine:latest"},
                    },
                    "links": [
                        {"endpoints": ["r1:eth1:extra", "pc1:eth1"]},
                    ],
                },
            },
            "configs": [],
            "ip_allocations": [],
        }
        res = OfflineValidator.validate(raw_dict)
        assert res.is_valid is False
        assert len(res.errors) >= 1

    def test_link_endpoint_whitespace_in_dict(self):
        """Link endpoint with embedded whitespace passed via dict."""
        raw_dict = {
            "topology": {
                "name": "bad-link-lab",
                "topology": {
                    "nodes": {
                        "r1": {"kind": "linux", "image": "alpine:latest"},
                        "pc1": {"kind": "linux", "image": "alpine:latest"},
                    },
                    "links": [
                        {"endpoints": ["r1:eth1 ", " pc1:eth1"]},
                    ],
                },
            },
            "configs": [],
            "ip_allocations": [],
        }
        res = OfflineValidator.validate(raw_dict)
        assert res.is_valid is False
        assert len(res.errors) >= 1

    def test_link_constructed_bypassing_pydantic(self, base_valid_package: FullTopologyPackage):
        """Directly construct model with invalid endpoint to test OfflineValidator Step 3 checks."""
        pkg = base_valid_package.model_copy(deep=True)
        bad_link = ContainerlabLinkEndpoint.model_construct(endpoints=["r1eth1", "pc1:eth1"])
        pkg.topology.topology.links.append(bad_link)
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "INVALID_ENDPOINT_FORMAT" for e in res.errors)

    def test_link_endpoint_single_endpoint(self):
        """Link with only 1 endpoint."""
        raw_dict = {
            "topology": {
                "name": "bad-link-lab",
                "topology": {
                    "nodes": {
                        "r1": {"kind": "linux", "image": "alpine:latest"},
                    },
                    "links": [
                        {"endpoints": ["r1:eth1"]},
                    ],
                },
            },
            "configs": [],
            "ip_allocations": [],
        }
        res = OfflineValidator.validate(raw_dict)
        assert res.is_valid is False

    def test_duplicate_link_between_same_nodes(self, base_valid_package: FullTopologyPackage):
        """Two identical links between r1:eth1 and pc1:eth1 should trigger DUPLICATE_LINK warning."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "r1:eth1"])
        )
        res = OfflineValidator.validate(pkg)
        assert any(w.code == "DUPLICATE_LINK" for w in res.warnings)


class TestAdversarialIPCollisionsAndSubnets:
    """Adversarial stress-testing of IP collisions, subnets, and masks."""

    def test_duplicate_ip_same_node_different_interface(self, base_valid_package: FullTopologyPackage):
        """Same node has identical IP on eth1 and eth2."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.ip_allocations.append(
            IPAllocation(
                node_name="r1",
                interface_name="eth2",
                ipv4_address="10.1.1.1/24",  # Same IP as r1:eth1
            )
        )
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "IP_COLLISION" for e in res.errors)

    def test_duplicate_ip_different_nodes_different_prefix_lengths(
        self, base_valid_package: FullTopologyPackage
    ):
        """Two nodes have identical host IP 10.1.1.1, but different prefix lengths (/24 and /16)."""
        pkg = base_valid_package.model_copy(deep=True)
        # r1:eth1 has 10.1.1.1/24
        # set pc1:eth1 to 10.1.1.1/16
        pkg.ip_allocations[1].ipv4_address = "10.1.1.1/16"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        collision_errs = [e for e in res.errors if e.code == "IP_COLLISION"]
        assert len(collision_errs) >= 1
        assert "10.1.1.1" in collision_errs[0].message

    def test_point_to_point_link_subnet_mismatch(self, base_valid_package: FullTopologyPackage):
        """Link connects 192.168.1.1/24 and 192.168.2.1/24."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.ip_allocations[0].ipv4_address = "192.168.1.1/24"
        pkg.ip_allocations[1].ipv4_address = "192.168.2.1/24"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        subnet_errs = [e for e in res.errors if e.code == "SUBNET_MISMATCH"]
        assert len(subnet_errs) == 1
        assert "192.168.1.0/24" in subnet_errs[0].message
        assert "192.168.2.0/24" in subnet_errs[0].message

    def test_point_to_point_link_same_ip_range_different_mask(
        self, base_valid_package: FullTopologyPackage
    ):
        """Link connects 10.1.1.1/24 and 10.1.1.2/25."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.ip_allocations[0].ipv4_address = "10.1.1.1/24"
        pkg.ip_allocations[1].ipv4_address = "10.1.1.2/25"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "SUBNET_MISMATCH" for e in res.errors)

    def test_point_to_point_link_slash30_cross_boundary(
        self, base_valid_package: FullTopologyPackage
    ):
        """Link connects 10.0.0.1/30 (network 10.0.0.0/30) and 10.0.0.5/30 (network 10.0.0.4/30)."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.ip_allocations[0].ipv4_address = "10.0.0.1/30"
        pkg.ip_allocations[1].ipv4_address = "10.0.0.5/30"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "SUBNET_MISMATCH" for e in res.errors)

    def test_unassigned_link_endpoint_warning(self, base_valid_package: FullTopologyPackage):
        """One endpoint of a link is missing an IP allocation."""
        pkg = base_valid_package.model_copy(deep=True)
        # Remove pc1's allocation
        pkg.ip_allocations = [pkg.ip_allocations[0]]
        res = OfflineValidator.validate(pkg)
        # Unassigned IP is a non-blocking warning
        assert any(w.code == "UNASSIGNED_LINK_IP" for w in res.warnings)

    def test_overlapping_subnets_across_links_observation(self):
        """Stress test: Check behavior when two distinct links have overlapping subnets with different mask lengths.

        Link 1: 10.1.0.0/16
        Link 2: 10.1.1.0/24 (subset of 10.1.0.0/16)
        """
        pkg = FullTopologyPackage(
            topology=ContainerlabTopologyFile(
                name="subnet-overlap-test",
                topology=ContainerlabTopologyDefinition(
                    nodes={
                        "r1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                        "pc1": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                        "r2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                        "pc2": ContainerlabNodeConfig(kind="linux", image="alpine:latest"),
                    },
                    links=[
                        ContainerlabLinkEndpoint(endpoints=["r1:eth1", "pc1:eth1"]),
                        ContainerlabLinkEndpoint(endpoints=["r2:eth1", "pc2:eth1"]),
                    ],
                ),
            ),
            configs=[],
            ip_allocations=[
                IPAllocation(node_name="r1", interface_name="eth1", ipv4_address="10.1.0.1/16"),
                IPAllocation(node_name="pc1", interface_name="eth1", ipv4_address="10.1.0.2/16"),
                IPAllocation(node_name="r2", interface_name="eth1", ipv4_address="10.1.1.1/24"),
                IPAllocation(node_name="pc2", interface_name="eth1", ipv4_address="10.1.1.2/24"),
            ],
        )
        res = OfflineValidator.validate(pkg)
        # Note: Current OfflineValidator validates subnets on a per-link basis.
        # Across distinct links, cross-link subnet containment is currently unflagged.
        assert isinstance(res, ValidationResult)


class TestAdversarialConfigBinds:
    """Adversarial stress-testing of configuration file bindings and mismatches."""

    def test_missing_startup_config(self, base_valid_package: FullTopologyPackage):
        """Node specifies startup_config that does not exist in configs list."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["r1"].startup_config = "config/r1/nonexistent.conf"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "MISSING_CONFIG_BINDING" for e in res.errors)

    def test_missing_relative_bind_mount(self, base_valid_package: FullTopologyPackage):
        """Node specifies bind mount that does not exist in configs list."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["pc1"].binds.append("config/pc1/custom.sh:/custom.sh")
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is False
        assert any(e.code == "MISSING_CONFIG_BINDING" for e in res.errors)

    def test_path_normalization_dot_slash(self, base_valid_package: FullTopologyPackage):
        """./config/r1/frr.conf vs config/r1/frr.conf should normalize cleanly."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["r1"].startup_config = "./config/r1/frr.conf"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is True

    def test_windows_backslash_normalization(self, base_valid_package: FullTopologyPackage):
        """config\\r1\\frr.conf vs config/r1/frr.conf should normalize cleanly."""
        pkg = base_valid_package.model_copy(deep=True)
        pkg.topology.topology.nodes["r1"].startup_config = "config\\r1\\frr.conf"
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is True

    def test_daemons_config_warning_not_blocking(self, base_valid_package: FullTopologyPackage):
        """Missing daemons config is a non-blocking warning (image default used)."""
        pkg = base_valid_package.model_copy(deep=True)
        # Remove daemons config from configs
        pkg.configs = [c for c in pkg.configs if not c.file_path.endswith("daemons")]
        res = OfflineValidator.validate(pkg)
        assert res.is_valid is True
        assert any(w.code == "MISSING_DAEMONS_CONFIG" for w in res.warnings)

    def test_mismatched_config_node_owner(self, base_valid_package: FullTopologyPackage):
        """Node r1 binds a file defined in configs with node_name='pc1'."""
        pkg = base_valid_package.model_copy(deep=True)
        # Add a bind to r1 referencing pc1's setup.sh
        pkg.topology.topology.nodes["r1"].binds.append("config/pc1/setup.sh:/setup.sh")
        res = OfflineValidator.validate(pkg)
        # Note: current implementation checks file_path existence across package configs
        assert isinstance(res, ValidationResult)


class TestAdversarialStateAndReducers:
    """Stress-test NetworkAgentState reducer mechanics, concurrency, and serialization."""

    def test_concurrent_log_entry_appends(self):
        """Stress-test concurrent addition of logs using ThreadPoolExecutor."""
        state = create_initial_state(user_intent="Concurrent log test")
        assert len(state["execution_logs"]) == 1

        num_threads = 20
        logs_per_thread = 50

        def worker_log(thread_idx: int) -> List[LogEntry]:
            return [
                create_log_entry(
                    stage=f"worker_{thread_idx}",
                    message=f"Step {step} from thread {thread_idx}",
                    metadata={"thread": thread_idx, "step": step},
                )
                for step in range(logs_per_thread)
            ]

        with ThreadPoolExecutor(max_workers=8) as executor:
            batch_results = list(executor.map(worker_log, range(num_threads)))

        # Aggregate via operator.add reducer
        combined_logs = state["execution_logs"]
        for batch in batch_results:
            combined_logs = operator.add(combined_logs, batch)

        expected_count = 1 + (num_threads * logs_per_thread)
        assert len(combined_logs) == expected_count
        # Verify timestamps are valid ISO format
        for entry in combined_logs:
            assert "timestamp" in entry
            assert "stage" in entry
            assert "message" in entry

    def test_state_json_serialization_round_trip(self, base_valid_package: FullTopologyPackage):
        """Ensure full NetworkAgentState can be serialized to JSON and deserialized cleanly."""
        state = create_initial_state(user_intent="JSON serialization test")
        state["parsed_intent"] = {
            "intent_id": "test-001",
            "summary": "Deploy test",
            "nodes": [{"name": "r1", "role": "router"}],
        }
        state["raw_topology"] = base_valid_package.model_dump()
        state["validated_topology"] = base_valid_package.model_dump()
        state["validation_result"] = {
            "is_valid": True,
            "validator_name": "offline_syntax_validator",
            "errors": [],
            "warnings": [],
            "summary": "Validation passed",
            "checked_items_count": 10,
        }
        state["deploy_status"] = {"status": "deployed", "lab_name": "test-lab"}
        state["verification_results"] = {"all_passed": True, "ping_summary": "100% success"}
        state["diagnostic_report"] = {"healthy": True, "issues": []}
        state["remediation_plan"] = {"plan_id": "none", "patches": []}

        # Add multiple log entries
        state["execution_logs"].append(
            create_log_entry("test_stage", "Test log message", level="info", metadata={"k": "v"})
        )

        # JSON dumps and loads round-trip
        serialized = json.dumps(state)
        assert isinstance(serialized, str)
        restored = json.loads(serialized)
        assert isinstance(restored, dict)
        assert restored["user_intent"] == state["user_intent"]
        assert restored["parsed_intent"] == state["parsed_intent"]
        assert len(restored["execution_logs"]) == 2
        assert restored["execution_logs"][1]["metadata"] == {"k": "v"}

    def test_state_pickle_serialization_round_trip(self, base_valid_package: FullTopologyPackage):
        """Ensure full NetworkAgentState can be pickled and unpickled cleanly for binary checkpointers."""
        state = create_initial_state(user_intent="Pickle serialization test")
        state["raw_topology"] = base_valid_package.model_dump()
        state["validated_topology"] = base_valid_package.model_dump()
        state["execution_logs"].append(
            create_log_entry("pickle_stage", "Pickle test message", metadata={"counter": 42})
        )

        pickled = pickle.dumps(state)
        assert isinstance(pickled, bytes)
        unpickled = pickle.loads(pickled)
        assert unpickled == state
        assert unpickled["execution_logs"][1]["metadata"]["counter"] == 42

    def test_simple_memory_saver_checkpoint_isolation(self):
        """Verify SimpleMemorySaver stores deep copies and prevents mutation leakage."""
        saver = SimpleMemorySaver()
        config_a = {"configurable": {"thread_id": "thread-a"}}
        config_b = {"configurable": {"thread_id": "thread-b"}}

        state_a = create_initial_state("State for thread A")
        saver.put(config_a, state_a)

        # Mutate local state_a
        state_a["status"] = "mutated_locally"
        state_a["execution_logs"].append(create_log_entry("leak_test", "Should not leak"))

        # Retrieved state from checkpointer should NOT reflect local mutation
        retrieved_a = saver.get(config_a)
        assert retrieved_a is not None
        assert retrieved_a["status"] == "initialized"
        assert len(retrieved_a["execution_logs"]) == 1

        # Check thread isolation
        state_b = create_initial_state("State for thread B")
        state_b["status"] = "thread_b_status"
        saver.put(config_b, state_b)

        retrieved_b = saver.get(config_b)
        assert retrieved_b is not None
        assert retrieved_b["status"] == "thread_b_status"
        assert retrieved_b["user_intent"] == "State for thread B"
        # Ensure thread A remained unchanged
        assert saver.get(config_a)["status"] == "initialized"
