"""Unit tests for Offline Pre-Flight Topology Validator."""

import pytest
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.models.validation import ValidationSeverity
from langgraph_netagent.validation.offline_validator import OfflineValidator


class TestOfflineValidatorRFC1123:
    """Test RFC 1123 hostname naming compliance."""

    def test_rfc1123_valid_names(self):
        valid_names = ["pc1", "frr-1", "srl123", "a", "router-node-99", "host-01"]
        for name in valid_names:
            assert OfflineValidator.is_valid_rfc1123_name(name) is True, f"Expected {name} to be valid"

    def test_rfc1123_invalid_names(self):
        invalid_names = [
            "pc_1",          # contains underscore
            "-pc1",          # starts with hyphen
            "pc1-",          # ends with hyphen
            "router@node",   # contains special char
            "",              # empty
            "a" * 64,        # exceeds 63 characters
        ]
        for name in invalid_names:
            assert OfflineValidator.is_valid_rfc1123_name(name) is False, f"Expected {name} to be invalid"


class TestOfflineValidatorTopologyChecks:
    """Test node names, links, IP allocations, subnets, and config bindings."""

    def test_offline_validator_healthy_package(self, sample_topology_package: FullTopologyPackage):
        result = OfflineValidator.validate(sample_topology_package)
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.checked_items_count > 0
        assert "Offline validation passed" in result.summary

    def test_invalid_node_name_detected(self, sample_topology_package: FullTopologyPackage):
        # Add an invalid node name with an underscore
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["pc_invalid"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "INVALID_NODE_NAME" in error_codes
        err = next(e for e in result.errors if e.code == "INVALID_NODE_NAME")
        assert err.node == "pc_invalid"

    def test_duplicate_node_name_case_collision(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["PC1"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "DUPLICATE_NODE_NAME" in error_codes

    def test_unknown_node_in_link_endpoint(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["pc1:eth2", "unknown_node:eth1"])
        )
        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "UNKNOWN_NODE_IN_LINK" in error_codes
        err = next(e for e in result.errors if e.code == "UNKNOWN_NODE_IN_LINK")
        assert err.node == "unknown_node"

    def test_self_loop_link_endpoint(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        # Link connecting pc1:eth1 to itself
        pkg.topology.topology.links.append(
            ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "pc1:eth1"])
        )
        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "INVALID_LINK_LOOP" in error_codes

    def test_ip_collision_detected(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        # Assign duplicate IP 10.1.1.1 to both pc1 and frr1
        pkg.ip_allocations[0].ipv4_address = "10.1.1.1/24"
        pkg.ip_allocations[1].ipv4_address = "10.1.1.1/24"

        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "IP_COLLISION" in error_codes
        err = next(e for e in result.errors if e.code == "IP_COLLISION")
        assert "10.1.1.1" in err.message

    def test_link_subnet_mismatch_detected(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        # Put pc1 and frr1 on different subnets across the same link
        pkg.ip_allocations[0].ipv4_address = "10.1.1.2/24"
        pkg.ip_allocations[1].ipv4_address = "10.2.1.1/24"

        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "SUBNET_MISMATCH" in error_codes
        err = next(e for e in result.errors if e.code == "SUBNET_MISMATCH")
        assert "10.1.1.0/24" in err.message
        assert "10.2.1.0/24" in err.message

    def test_missing_startup_config_binding(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["frr1"].startup_config = "config/frr/missing_startup.conf"

        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "MISSING_CONFIG_BINDING" in error_codes
        err = next(e for e in result.errors if e.code == "MISSING_CONFIG_BINDING")
        assert err.node == "frr1"

    def test_missing_bind_mount_binding(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["pc1"].binds.append("config/pc1/missing.sh:/missing.sh")

        result = OfflineValidator.validate(pkg)
        assert result.is_valid is False
        error_codes = [e.code for e in result.errors]
        assert "MISSING_CONFIG_BINDING" in error_codes

    def test_system_bind_mounts_ignored(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["pc1"].binds.append("/lib/modules:/lib/modules:ro")

        result = OfflineValidator.validate(pkg)
        assert result.is_valid is True

    def test_isolated_node_warning(self, sample_topology_package: FullTopologyPackage):
        pkg = sample_topology_package.model_copy(deep=True)
        pkg.topology.topology.nodes["pc3"] = ContainerlabNodeConfig(
            kind="linux",
            image="alpine:latest",
        )
        result = OfflineValidator.validate(pkg)
        # Non-blocking warning: is_valid should still be True
        assert result.is_valid is True
        warning_codes = [w.code for w in result.warnings]
        assert "ISOLATED_NODE" in warning_codes

    def test_validate_dictionary_input(self, sample_topology_package: FullTopologyPackage):
        pkg_dict = sample_topology_package.model_dump()
        result = OfflineValidator.validate(pkg_dict)
        assert result.is_valid is True
        assert result.checked_items_count > 0

    def test_validate_malformed_input_failure(self):
        result = OfflineValidator.validate({"invalid": "data"})
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert result.errors[0].code == "SCHEMA_VALIDATION_ERROR"
