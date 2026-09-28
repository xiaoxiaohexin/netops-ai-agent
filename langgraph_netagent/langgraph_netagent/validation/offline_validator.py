"""Offline Pre-Flight Syntax and Topology Validator.

Validates Containerlab topologies, IP assignments, link consistency,
RFC 1123 naming compliance, and configuration bindings before deployment.
"""

from __future__ import annotations
import ipaddress
import re
from typing import Any, Dict, List, Optional, Set, Union

from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
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


class OfflineValidator:
    """Static / offline pre-flight validator for Containerlab topologies."""

    # RFC 1123: alphanumeric and hyphens, no consecutive hyphens, cannot start or end with hyphen, 1-63 chars
    RFC1123_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    # Single character alphanumeric is also valid RFC 1123
    RFC1123_SINGLE_CHAR_REGEX = re.compile(r"^[a-zA-Z0-9]$")

    ENDPOINT_FORMAT_REGEX = re.compile(r"^[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\.\-]+$")

    @classmethod
    def is_valid_rfc1123_name(cls, name: str) -> bool:
        """Check if node name conforms to RFC 1123 naming conventions."""
        if not name or len(name) > 63:
            return False
        if len(name) == 1:
            return bool(cls.RFC1123_SINGLE_CHAR_REGEX.match(name))
        return bool(cls.RFC1123_REGEX.match(name))

    @classmethod
    def _normalize_path(cls, path_str: str) -> str:
        """Normalize relative configuration file paths."""
        clean = path_str.strip().replace("\\", "/")
        while clean.startswith("./"):
            clean = clean[2:]
        return clean

    @classmethod
    def validate(
        cls,
        package_or_data: Union[FullTopologyPackage, Dict[str, Any]],
    ) -> ValidationResult:
        """Perform comprehensive offline validation of a topology package or dictionary.

        Args:
            package_or_data: FullTopologyPackage instance or dictionary representation.

        Returns:
            ValidationResult with detailed error/warning breakdown and summary.
        """
        findings: List[ValidationErrorDetail] = []
        checked_count = 0

        # Step 1: Reconstruct or coerce into FullTopologyPackage
        pkg: Optional[FullTopologyPackage] = None
        if isinstance(package_or_data, FullTopologyPackage):
            pkg = package_or_data
        elif isinstance(package_or_data, dict):
            # Check if this dict has a top-level "topology" key (FullTopologyPackage structure)
            if "topology" in package_or_data and isinstance(package_or_data["topology"], dict) and "name" in package_or_data["topology"]:
                try:
                    pkg = FullTopologyPackage.model_validate(package_or_data)
                except Exception as exc:
                    findings.append(
                        ValidationErrorDetail(
                            code="SCHEMA_VALIDATION_ERROR",
                            message=f"Failed to parse topology package: {exc}",
                            field="package",
                            severity=ValidationSeverity.ERROR,
                            suggested_fix="Correct schema attributes to match FullTopologyPackage",
                        )
                    )
            elif "name" in package_or_data and "topology" in package_or_data:
                # Direct ContainerlabTopologyFile dictionary
                try:
                    top_file = ContainerlabTopologyFile.model_validate(package_or_data)
                    pkg = FullTopologyPackage(topology=top_file, configs=[], ip_allocations=[])
                except Exception as exc:
                    findings.append(
                        ValidationErrorDetail(
                            code="SCHEMA_VALIDATION_ERROR",
                            message=f"Failed to parse topology file: {exc}",
                            field="topology",
                            severity=ValidationSeverity.ERROR,
                            suggested_fix="Correct schema attributes to match ContainerlabTopologyFile",
                        )
                    )
            else:
                try:
                    pkg = FullTopologyPackage.model_validate(package_or_data)
                except Exception as exc:
                    findings.append(
                        ValidationErrorDetail(
                            code="SCHEMA_VALIDATION_ERROR",
                            message=f"Invalid topology input data format: {exc}",
                            field="package",
                            severity=ValidationSeverity.ERROR,
                            suggested_fix="Ensure input contains valid topology, configs, and ip_allocations",
                        )
                    )
        else:
            findings.append(
                ValidationErrorDetail(
                    code="INVALID_INPUT_TYPE",
                    message=f"Expected FullTopologyPackage or dict, got {type(package_or_data).__name__}",
                    field="input",
                    severity=ValidationSeverity.ERROR,
                    suggested_fix="Pass a FullTopologyPackage instance or dictionary",
                )
            )

        if pkg is None:
            errors = [f for f in findings if f.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)]
            warnings = [f for f in findings if f.severity in (ValidationSeverity.WARNING, ValidationSeverity.INFO)]
            return ValidationResult(
                is_valid=False,
                validator_name="offline_syntax_validator",
                errors=errors,
                warnings=warnings,
                summary=f"Validation failed: input schema error ({len(errors)} error(s))",
                checked_items_count=0,
            )

        topology = pkg.topology
        nodes = topology.topology.nodes
        links = topology.topology.links
        configs = pkg.configs
        ip_allocations = pkg.ip_allocations

        # Step 2: Validate Node Names (RFC 1123 and Duplicates)
        seen_node_names_lower: Dict[str, str] = {}
        for node_name in nodes.keys():
            checked_count += 1
            # RFC 1123 Syntax check
            if not cls.is_valid_rfc1123_name(node_name):
                findings.append(
                    ValidationErrorDetail(
                        code="INVALID_NODE_NAME",
                        message=(
                            f"Node name '{node_name}' violates RFC 1123 standards. "
                            "It must consist only of alphanumeric characters and hyphens, "
                            "cannot start or end with a hyphen, and must be 1 to 63 characters long."
                        ),
                        node=node_name,
                        field=f"topology.nodes.{node_name}",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix=f"Rename '{node_name}' to adhere to RFC 1123 (e.g. replace '_' with '-')",
                    )
                )

            # Case-insensitive duplicate check
            lower_name = node_name.lower()
            if lower_name in seen_node_names_lower and seen_node_names_lower[lower_name] != node_name:
                findings.append(
                    ValidationErrorDetail(
                        code="DUPLICATE_NODE_NAME",
                        message=f"Node name '{node_name}' collides with '{seen_node_names_lower[lower_name]}' (case-insensitive collision).",
                        node=node_name,
                        field=f"topology.nodes.{node_name}",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix="Ensure all node names are uniquely distinct regardless of case",
                    )
                )
            else:
                seen_node_names_lower[lower_name] = node_name

        # Step 3: Validate Links and Endpoint Formats
        node_link_counts: Dict[str, int] = {name: 0 for name in nodes.keys()}
        seen_links: Set[str] = set()

        for link_idx, link in enumerate(links):
            checked_count += 1
            if len(link.endpoints) != 2:
                findings.append(
                    ValidationErrorDetail(
                        code="INVALID_LINK_ENDPOINTS_COUNT",
                        message=f"Link at index {link_idx} has {len(link.endpoints)} endpoints, expected exactly 2.",
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix="Specify exactly 2 endpoints for each link",
                    )
                )
                continue

            ep1, ep2 = link.endpoints[0], link.endpoints[1]

            # Format check
            for ep in (ep1, ep2):
                if not cls.ENDPOINT_FORMAT_REGEX.match(ep):
                    findings.append(
                        ValidationErrorDetail(
                            code="INVALID_ENDPOINT_FORMAT",
                            message=f"Endpoint '{ep}' does not match required format '<node>:<interface>' (e.g. 'pc1:eth1').",
                            field=f"topology.links[{link_idx}]",
                            severity=ValidationSeverity.ERROR,
                            suggested_fix="Format endpoint string as '<node_name>:<interface_name>'",
                        )
                    )

            # Extract node and interface
            node1 = ep1.split(":", 1)[0] if ":" in ep1 else ep1
            node2 = ep2.split(":", 1)[0] if ":" in ep2 else ep2

            # Check if nodes exist
            if node1 not in nodes:
                findings.append(
                    ValidationErrorDetail(
                        code="UNKNOWN_NODE_IN_LINK",
                        message=f"Link endpoint '{ep1}' references undeclared node '{node1}'.",
                        node=node1,
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix=f"Declare node '{node1}' in topology.nodes or fix endpoint reference",
                    )
                )
            else:
                node_link_counts[node1] += 1

            if node2 not in nodes:
                findings.append(
                    ValidationErrorDetail(
                        code="UNKNOWN_NODE_IN_LINK",
                        message=f"Link endpoint '{ep2}' references undeclared node '{node2}'.",
                        node=node2,
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix=f"Declare node '{node2}' in topology.nodes or fix endpoint reference",
                    )
                )
            else:
                node_link_counts[node2] += 1

            # Self-loop check (same interface on same node)
            if ep1 == ep2:
                findings.append(
                    ValidationErrorDetail(
                        code="INVALID_LINK_LOOP",
                        message=f"Link cannot connect interface to itself: '{ep1}' <-> '{ep2}'.",
                        node=node1,
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix="Connect link between two distinct interfaces",
                    )
                )

            # Duplicate link check
            sorted_link_key = tuple(sorted([ep1, ep2]))
            if sorted_link_key in seen_links:
                findings.append(
                    ValidationErrorDetail(
                        code="DUPLICATE_LINK",
                        message=f"Duplicate link detected between '{ep1}' and '{ep2}'.",
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.WARNING,
                        suggested_fix="Remove redundant link definition",
                    )
                )
            else:
                seen_links.add(sorted_link_key)

        # Isolated nodes warning
        for node_name, count in node_link_counts.items():
            if count == 0 and len(nodes) > 1:
                findings.append(
                    ValidationErrorDetail(
                        code="ISOLATED_NODE",
                        message=f"Node '{node_name}' is not connected to any links in the topology.",
                        node=node_name,
                        field=f"topology.nodes.{node_name}",
                        severity=ValidationSeverity.WARNING,
                        suggested_fix=f"Attach at least one link connecting '{node_name}' to other nodes",
                    )
                )

        # Step 4: Validate IP Address Assignment and Collisions
        ip_alloc_map: Dict[str, IPAllocation] = {}  # key: "node:interface"
        assigned_ips_map: Dict[str, List[str]] = {}  # key: "ip_without_prefix" -> list of "node:interface"

        for alloc_idx, alloc in enumerate(ip_allocations):
            checked_count += 1
            ep_key = f"{alloc.node_name}:{alloc.interface_name}"
            ip_alloc_map[ep_key] = alloc

            # Parse and validate IP syntax
            try:
                iface_obj = ipaddress.IPv4Interface(alloc.ipv4_address)
                pure_ip = str(iface_obj.ip)

                # Check duplicate IP assignments (IP collisions)
                if pure_ip not in assigned_ips_map:
                    assigned_ips_map[pure_ip] = []
                assigned_ips_map[pure_ip].append(ep_key)

            except Exception as exc:
                findings.append(
                    ValidationErrorDetail(
                        code="INVALID_IP_FORMAT",
                        message=f"Invalid IPv4 address format '{alloc.ipv4_address}' on {ep_key}: {exc}",
                        node=alloc.node_name,
                        field=f"ip_allocations[{alloc_idx}].ipv4_address",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix="Provide a valid IPv4 address in CIDR notation (e.g. '10.1.1.2/24')",
                    )
                )

        # Record IP collisions
        for pure_ip, ep_list in assigned_ips_map.items():
            if len(ep_list) > 1:
                findings.append(
                    ValidationErrorDetail(
                        code="IP_COLLISION",
                        message=f"Duplicate IP address '{pure_ip}' assigned to multiple interfaces: {', '.join(ep_list)}.",
                        field="ip_allocations",
                        severity=ValidationSeverity.ERROR,
                        suggested_fix=f"Reassign unique IP addresses to {', '.join(ep_list)} to avoid collisions",
                    )
                )

        # Step 5: Validate Link Subnet Consistency
        for link_idx, link in enumerate(links):
            if len(link.endpoints) != 2:
                continue
            ep1, ep2 = link.endpoints[0], link.endpoints[1]
            alloc1 = ip_alloc_map.get(ep1)
            alloc2 = ip_alloc_map.get(ep2)

            if alloc1 is not None and alloc2 is not None:
                checked_count += 1
                try:
                    if1_obj = ipaddress.IPv4Interface(alloc1.ipv4_address)
                    if2_obj = ipaddress.IPv4Interface(alloc2.ipv4_address)

                    if if1_obj.network != if2_obj.network:
                        findings.append(
                            ValidationErrorDetail(
                                code="SUBNET_MISMATCH",
                                message=(
                                    f"Link endpoints '{ep1}' ({alloc1.ipv4_address}) and '{ep2}' ({alloc2.ipv4_address}) "
                                    f"belong to different subnets: {if1_obj.network} vs {if2_obj.network}."
                                ),
                                field=f"topology.links[{link_idx}]",
                                severity=ValidationSeverity.ERROR,
                                suggested_fix=(
                                    f"Reconfigure '{ep1}' and '{ep2}' so both IP addresses share the same subnet prefix"
                                ),
                            )
                        )
                except Exception:
                    pass  # already captured under INVALID_IP_FORMAT
            elif (alloc1 is None or alloc2 is None) and ip_allocations:
                # One or both endpoints missing IP allocation while IP allocations list is present
                missing = []
                if alloc1 is None:
                    missing.append(ep1)
                if alloc2 is None:
                    missing.append(ep2)
                findings.append(
                    ValidationErrorDetail(
                        code="UNASSIGNED_LINK_IP",
                        message=f"Link '{ep1}' <-> '{ep2}' has unassigned IP for endpoint(s): {', '.join(missing)}.",
                        field=f"topology.links[{link_idx}]",
                        severity=ValidationSeverity.WARNING,
                        suggested_fix=f"Add IPAllocation entries for {', '.join(missing)}",
                    )
                )

        # Step 6: Validate Node Configuration Bindings
        available_config_paths: Set[str] = set()
        for cfg in configs:
            checked_count += 1
            norm_path = cls._normalize_path(cfg.file_path)
            available_config_paths.add(norm_path)

        for node_name, node_cfg in nodes.items():
            checked_count += 1

            # Check startup_config binding
            if node_cfg.startup_config:
                checked_count += 1
                norm_sc = cls._normalize_path(node_cfg.startup_config)
                if norm_sc not in available_config_paths:
                    findings.append(
                        ValidationErrorDetail(
                            code="MISSING_CONFIG_BINDING",
                            message=(
                                f"Node '{node_name}' specifies startup-config '{node_cfg.startup_config}', "
                                "but no matching DeviceConfigFile was found in package configs."
                            ),
                            node=node_name,
                            field=f"topology.nodes.{node_name}.startup_config",
                            severity=ValidationSeverity.ERROR,
                            suggested_fix=f"Add a DeviceConfigFile with file_path='{node_cfg.startup_config}'",
                        )
                    )

            # Check volume binds
            for bind_idx, bind in enumerate(node_cfg.binds):
                checked_count += 1
                parts = bind.split(":")
                host_path = parts[0].strip()
                # Skip absolute system paths (e.g. /etc/timezone, /lib/modules)
                if host_path.startswith("/") or host_path.startswith("\\"):
                    continue

                norm_host = cls._normalize_path(host_path)
                if norm_host not in available_config_paths:
                    if norm_host.endswith("daemons"):
                        findings.append(
                            ValidationErrorDetail(
                                code="MISSING_DAEMONS_CONFIG",
                                message=(
                                    f"Node '{node_name}' bind mount references '{host_path}', "
                                    "which is not explicitly defined in package configs (image default will be used)."
                                ),
                                node=node_name,
                                field=f"topology.nodes.{node_name}.binds[{bind_idx}]",
                                severity=ValidationSeverity.WARNING,
                                suggested_fix=f"Provide a DeviceConfigFile for '{host_path}' if custom daemon toggles are required",
                            )
                        )
                    else:
                        findings.append(
                            ValidationErrorDetail(
                                code="MISSING_CONFIG_BINDING",
                                message=(
                                    f"Node '{node_name}' bind mount #{bind_idx} references '{host_path}', "
                                    "but no matching DeviceConfigFile exists in package configs."
                                ),
                                node=node_name,
                                field=f"topology.nodes.{node_name}.binds[{bind_idx}]",
                                severity=ValidationSeverity.ERROR,
                                suggested_fix=f"Provide a DeviceConfigFile for '{host_path}' in package.configs",
                            )
                        )

        # Step 7: Construct Aggregated ValidationResult
        errors = [f for f in findings if f.severity in (ValidationSeverity.ERROR, ValidationSeverity.CRITICAL)]
        warnings = [f for f in findings if f.severity in (ValidationSeverity.WARNING, ValidationSeverity.INFO)]
        is_valid = (len(errors) == 0)

        if is_valid:
            summary = (
                f"Offline validation passed: 0 errors, {len(warnings)} warning(s) "
                f"across {checked_count} checked items."
            )
        else:
            summary = (
                f"Offline validation failed: {len(errors)} error(s), {len(warnings)} warning(s) "
                f"across {checked_count} checked items."
            )

        return ValidationResult(
            is_valid=is_valid,
            validator_name="offline_syntax_validator",
            errors=errors,
            warnings=warnings,
            summary=summary,
            checked_items_count=checked_count,
        )
