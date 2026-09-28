"""Adversarial stress-test suite for Milestone M1 models and parser.

Crafted by challenger_net_m1_1 to test edge cases, syntax flaws, malformed JSON,
and extreme Pydantic boundary conditions.
"""

from __future__ import annotations
import json
import re
import pytest
from pydantic import ValidationError

from langgraph_netagent.llm.parser import (
    clean_json_syntax,
    extract_json_substring,
    parse_and_validate,
    build_reflection_prompt,
)
from langgraph_netagent.models.intent import (
    IsolationMode,
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    ProtocolType,
    QoSLevel,
)
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
from langgraph_netagent.models.diagnostic import (
    DiagnosticReport,
    ErrorCategory,
    SeverityLevel,
)
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
)
from langgraph_netagent.models.telemetry import (
    InterfaceTelemetry,
    NetworkHealthReport,
    PingTelemetry,
    RouteEntry,
    RouteTableTelemetry,
)
from langgraph_netagent.models.validation import (
    ValidationErrorDetail,
    ValidationResult,
    ValidationSeverity,
)


# ==============================================================================
# SECTION 1: Adversarial Testing of extract_json_substring & clean_json_syntax
# ==============================================================================

class TestParserAdversarialInputs:
    """Stress-test JSON extraction and syntax cleaning against tricky LLM outputs."""

    def test_nested_markdown_code_blocks_multiple(self):
        """Scenario: LLM outputs an explanatory markdown block before the actual JSON block."""
        text = (
            "Here is an example format that you should NOT follow:\n"
            "```\n"
            "Note: please avoid legacy syntax.\n"
            "```\n\n"
            "Here is the valid topology JSON:\n"
            "```json\n"
            "{\n"
            '  "name": "valid-lab",\n'
            '  "topology": {"nodes": {}, "links": []}\n'
            "}\n"
            "```"
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert data["name"] == "valid-lab"

    def test_markdown_with_backticks_inside_json_string(self):
        """Scenario: JSON string value contains markdown backticks (e.g. bash commands)."""
        text = (
            "```json\n"
            "{\n"
            '  "name": "lab-with-code",\n'
            '  "description": "Run ```bash\\nip link\\n``` to check interfaces"\n'
            "}\n"
            "```"
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert "ip link" in data["description"]

    def test_unclosed_markdown_fence(self):
        """Scenario: LLM output was truncated or omitted closing triple backticks."""
        text = (
            "Here is your configuration:\n"
            "```json\n"
            "{\n"
            '  "name": "truncated-fence",\n'
            '  "topology": {"nodes": {}, "links": []}\n'
            "}"
            # Missing closing ```
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert data["name"] == "truncated-fence"

    def test_conversational_text_with_curly_braces_before_json(self):
        """Scenario: Conversational preamble contains curly braces (e.g. {1} or {router})."""
        text = (
            "I have analyzed your requirement {1} and {node-x}.\n"
            "Here is the resulting object:\n"
            '{"name": "real-topo", "topology": {"nodes": {}, "links": []}}'
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert data.get("name") == "real-topo"

    def test_conversational_text_with_trailing_curly_braces(self):
        """Scenario: Conversational postamble contains curly braces."""
        text = (
            '{"name": "topo-tail", "topology": {"nodes": {}, "links": []}}\n'
            "Hope this works! If you encounter issues, refer to {section-4}."
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert data["name"] == "topo-tail"

    def test_deeply_nested_objects_depth_100(self):
        """Scenario: Extremely deep JSON nesting (depth 100)."""
        depth = 100
        nested = '{"key": ' * depth + '"value"' + "}" * depth
        extracted = extract_json_substring(f"Prefix text {nested} suffix text")
        data = json.loads(extracted)
        curr = data
        for _ in range(depth):
            assert "key" in curr
            curr = curr["key"]
        assert curr == "value"

    def test_deeply_nested_arrays_depth_100(self):
        """Scenario: Extremely deep JSON array nesting (depth 100)."""
        depth = 100
        nested = "[" * depth + '"nested_val"' + "]" * depth
        extracted = extract_json_substring(f"Here is the matrix: {nested}")
        data = json.loads(extracted)
        curr = data
        for _ in range(depth):
            assert isinstance(curr, list)
            curr = curr[0]
        assert curr == "nested_val"

    def test_strings_with_escaped_quotes_and_brackets(self):
        """Scenario: Strings containing escaped quotes, braces, brackets, and slashes."""
        tricky_json = (
            "{\n"
            '  "raw_intent": "Connect {pc1} to [frr1] via \\"eth1\\" with \\\\ path",\n'
            '  "summary": "Escaped \\"quotes\\" and {braces} and [brackets]",\n'
            '  "nodes": [{"name": "pc1", "role": "host"}]\n'
            "}"
        )
        extracted = extract_json_substring(f"LLM Response:\n{tricky_json}\nEnd of response.")
        data = json.loads(extracted)
        assert "{pc1}" in data["raw_intent"]
        assert '[brackets]' in data["summary"]

    def test_clean_trailing_comma_before_brace_and_bracket(self):
        """Scenario: Trailing commas in objects and arrays with various whitespace."""
        raw = '{\n  "a": [1, 2, 3,  ], \n  "b": {"x": 10, \t }, \n}'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["a"] == [1, 2, 3]
        assert data["b"]["x"] == 10

    def test_clean_trailing_comma_hazard_inside_string_literal(self):
        """CRITICAL CHECK: clean_json_syntax corrupts commas inside string literals."""
        raw = '{"description": "values are 1, } and 2, ] finished"}'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["description"] == "values are 1, } and 2, ] finished"

    def test_clean_json_syntax_with_tabs_newlines_and_spaces(self):
        """Scenario: Excessive whitespace, newlines, and tabs around trailing commas."""
        raw = '{\n\t"nodes": [\n\t\t"r1",\n\t\t"r2",\t\n\t]\n}'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["nodes"] == ["r1", "r2"]

    def test_unicode_and_special_characters(self):
        """Scenario: Unicode characters (Chinese, Japanese, Emoji, Greek)."""
        raw = {
            "name": "拓扑实验_🚀_αβγ",
            "summary": "東京ルータ - 100% 连通",
            "nodes": [{"name": "node-1", "role": "host"}]
        }
        json_str = json.dumps(raw, ensure_ascii=False)
        extracted = extract_json_substring(f"Here is your topology: {json_str}")
        data = json.loads(extracted)
        assert data["name"] == "拓扑实验_🚀_αβγ"
        assert data["summary"] == "東京ルータ - 100% 连通"

    def test_json_with_inline_comments(self):
        """Scenario: LLM outputs comments inside JSON (`//` or `/* ... */`)."""
        raw_text = (
            "{\n"
            '  "name": "r1", // router 1\n'
            '  "role": "router" /* edge router */\n'
            "}"
        )
        instance, err = parse_and_validate(raw_text, NodeIntent)
        assert instance is not None, f"Failed to parse JSON with comments: {err}"

    def test_single_quoted_json(self):
        """Scenario: LLM returns python dict / single-quoted JSON representation."""
        raw_text = "{'name': 'r1', 'role': 'router'}"
        instance, err = parse_and_validate(raw_text, NodeIntent)
        assert instance is not None, f"Failed to parse single-quoted JSON: {err}"

    def test_literal_newlines_in_json_strings(self):
        """Scenario: LLM produces unescaped literal newline inside a JSON string."""
        raw_text = (
            '{\n'
            '  "name": "r1",\n'
            '  "role": "router with\n'  # literal newline unescaped
            'multiple lines"\n'
            '}'
        )
        instance, err = parse_and_validate(raw_text, NodeIntent)
        assert instance is not None, f"Failed to parse literal newlines: {err}"


# ==============================================================================
# SECTION 2: Adversarial Testing of Pydantic Models Validation
# ==============================================================================

class TestModelBoundaryAdversarial:
    """Stress-test Pydantic model validation on extreme edge cases."""

    # --------------------------------------------------------------------------
    # 2.1 ContainerlabLinkEndpoint
    # --------------------------------------------------------------------------

    def test_link_endpoint_empty_strings(self):
        """Empty strings in endpoint pair must be rejected."""
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["", ""])

    def test_link_endpoint_missing_colon(self):
        """Endpoint without colon must be rejected."""
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["pc1-eth1", "r1:eth1"])

    def test_link_endpoint_extra_colons(self):
        """Endpoint with multiple colons must be rejected."""
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["pc1:eth1:extra", "r1:eth1"])

    def test_link_endpoint_srlinux_slash_syntax(self):
        """Containerlab interface names: e1/1 (Nokia SRL style) vs e1-1."""
        # Containerlab uses e1-1, but LLMs often output e1/1 from SRL CLI!
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["srl1:e1/1", "r1:eth1"])

    def test_link_endpoint_whitespace_inside(self):
        """Endpoints with whitespace inside must be rejected."""
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["pc1 :eth1", "r1:eth1"])

    def test_link_endpoint_invalid_lengths(self):
        """Endpoints list with length != 2 must be rejected."""
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=[])
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["r1:eth1"])
        with pytest.raises(ValidationError):
            ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r2:eth1", "r3:eth1"])

    def test_link_endpoint_self_loop(self):
        """Endpoint connecting identical interface to itself."""
        ep = ContainerlabLinkEndpoint(endpoints=["r1:eth1", "r1:eth1"])
        assert ep.endpoints[0] == ep.endpoints[1]

    # --------------------------------------------------------------------------
    # 2.2 NodeIntent & LinkIntent
    # --------------------------------------------------------------------------

    def test_node_intent_whitespace_only_name(self):
        """Node name consisting only of whitespace must raise."""
        with pytest.raises(ValidationError):
            NodeIntent(name="   \t\n  ", role="host")

    def test_node_intent_empty_name(self):
        """Empty string node name must raise."""
        with pytest.raises(ValidationError):
            NodeIntent(name="", role="host")

    def test_node_intent_extreme_long_name(self):
        """Node name with 5000 characters."""
        long_name = "node_" + "a" * 5000
        node = NodeIntent(name=long_name, role="router")
        assert node.name == long_name

    def test_node_intent_case_normalization(self):
        """Node name should be stripped and lowercased."""
        node = NodeIntent(name="  ROUTER_ALPHA_1  ", role="router")
        assert node.name == "router_alpha_1"

    def test_link_intent_empty_nodes_allowed_or_rejected(self):
        """Check that LinkIntent rejects empty or whitespace-only source and target nodes."""
        with pytest.raises(ValidationError):
            LinkIntent(source_node="   ", target_node="")
        with pytest.raises(ValidationError):
            LinkIntent(source_node="pc1", target_node="   ")

    def test_link_intent_negative_constraints_allowed_or_rejected(self):
        """Check that LinkIntent rejects negative bandwidth or latency."""
        with pytest.raises(ValidationError):
            LinkIntent(source_node="n1", target_node="n2", bandwidth_mbps=-100)
        with pytest.raises(ValidationError):
            LinkIntent(source_node="n1", target_node="n2", latency_ms=-5.0)

    # --------------------------------------------------------------------------
    # 2.3 Enums: ProtocolType, QoSLevel, IsolationMode
    # --------------------------------------------------------------------------

    def test_protocol_type_uppercase_handling(self):
        """Uppercase protocol string e.g. 'OSPF' is seamlessly coerced to ProtocolType.OSPF."""
        ni = NetworkIntent(
            raw_intent="test",
            summary="test",
            nodes=[NodeIntent(name="r1", role="router")],
            protocols=["OSPF", "BGP"],  # type: ignore
        )
        assert ni.protocols == [ProtocolType.OSPF, ProtocolType.BGP]
        assert ProtocolType("OSPF") == ProtocolType.OSPF

    def test_qos_level_invalid_enum(self):
        """Invalid QoS level must raise ValidationError."""
        with pytest.raises(ValidationError):
            NetworkIntent(
                raw_intent="test",
                summary="test",
                nodes=[NodeIntent(name="r1", role="router")],
                qos="ultra_premium"  # type: ignore
            )

    # --------------------------------------------------------------------------
    # 2.4 Topology Model Boundaries
    # --------------------------------------------------------------------------

    def test_topology_file_empty_name(self):
        """Check that ContainerlabTopologyFile rejects whitespace-only or empty name."""
        with pytest.raises(ValidationError):
            ContainerlabTopologyFile(
                name="   ",
                topology=ContainerlabTopologyDefinition(nodes={}, links=[])
            )
        with pytest.raises(ValidationError):
            ContainerlabTopologyFile(
                name="",
                topology=ContainerlabTopologyDefinition(nodes={}, links=[])
            )

    def test_device_config_file_arbitrary_permissions(self):
        """Check that DeviceConfigFile validates octal file permissions."""
        with pytest.raises(ValidationError):
            DeviceConfigFile(
                node_name="r1",
                file_path="config/r1.sh",
                content="#!/bin/sh",
                permissions="9999"
            )
        with pytest.raises(ValidationError):
            DeviceConfigFile(
                node_name="r1",
                file_path="config/r1.sh",
                content="#!/bin/sh",
                permissions="xyz"
            )

    def test_ip_allocation_malformed_ip(self):
        """Check that IPAllocation validates CIDR/IP syntax."""
        with pytest.raises(ValidationError):
            IPAllocation(
                node_name="r1",
                interface_name="eth1",
                ipv4_address="999.999.999.999/99"
            )
        with pytest.raises(ValidationError):
            IPAllocation(
                node_name="r1",
                interface_name="eth1",
                ipv4_address="not_an_ip"
            )

    # --------------------------------------------------------------------------
    # 2.5 Diagnostic & Telemetry Boundaries
    # --------------------------------------------------------------------------

    def test_diagnostic_report_confidence_score_boundaries(self):
        """Confidence score must be strictly between 0.0 and 1.0."""
        r0 = DiagnosticReport(
            telemetry_trigger="loss",
            root_cause="cause",
            affected_nodes=["n1"],
            error_category=ErrorCategory.ROUTING_MISCONFIG,
            confidence_score=0.0
        )
        assert r0.confidence_score == 0.0

        with pytest.raises(ValidationError):
            DiagnosticReport(
                telemetry_trigger="loss",
                root_cause="cause",
                affected_nodes=["n1"],
                error_category=ErrorCategory.ROUTING_MISCONFIG,
                confidence_score=1.5
            )

    def test_ping_telemetry_boundaries(self):
        """Ping loss percentage bounds (0.0 to 100.0) and packet count bounds (>= 0)."""
        with pytest.raises(ValidationError):
            PingTelemetry(
                src_node="pc1",
                dst_ip="10.1.1.1",
                transmitted=5,
                received=5,
                loss_pct=-1.0,
                is_reachable=True
            )

        with pytest.raises(ValidationError):
            PingTelemetry(
                src_node="pc1",
                dst_ip="10.1.1.1",
                transmitted=5,
                received=0,
                loss_pct=105.0,
                is_reachable=False
            )

    # --------------------------------------------------------------------------
    # 2.6 Large Topology Scalability Test
    # --------------------------------------------------------------------------

    def test_large_topology_package_scale(self):
        """Stress-test FullTopologyPackage with 150 nodes and 300 links."""
        nodes = {}
        links = []
        configs = []
        allocations = []

        num_nodes = 150
        for i in range(num_nodes):
            name = f"node_{i}"
            nodes[name] = ContainerlabNodeConfig(
                kind="linux",
                image="alpine:latest",
                exec=[f"ip addr add 10.0.{i}.1/24 dev eth1"]
            )
            configs.append(DeviceConfigFile(
                node_name=name,
                file_path=f"config/{name}/setup.sh",
                content=f"#!/bin/sh\necho Setup {name}\n"
            ))

        for i in range(num_nodes):
            next_i = (i + 1) % num_nodes
            links.append(ContainerlabLinkEndpoint(
                endpoints=[f"node_{i}:eth1", f"node_{next_i}:eth1"]
            ))
            links.append(ContainerlabLinkEndpoint(
                endpoints=[f"node_{i}:eth2", f"node_{(i + 2) % num_nodes}:eth2"]
            ))
            allocations.append(IPAllocation(
                node_name=f"node_{i}",
                interface_name="eth1",
                ipv4_address=f"10.0.{i}.1/24",
                peer_node=f"node_{next_i}",
                peer_interface="eth1"
            ))

        topo_file = ContainerlabTopologyFile(
            name="large-scale-topology",
            mgmt=ContainerlabMgmtConfig(ipv4_subnet="172.50.0.0/16"),
            topology=ContainerlabTopologyDefinition(nodes=nodes, links=links)
        )

        pkg = FullTopologyPackage(
            topology=topo_file,
            configs=configs,
            ip_allocations=allocations
        )

        assert len(pkg.topology.topology.nodes) == 150
        assert len(pkg.topology.topology.links) == 300
        assert len(pkg.configs) == 150

        # Test YAML export roundtrip
        yaml_str = pkg.topology.to_yaml()
        assert "large-scale-topology" in yaml_str
        assert "node_149" in yaml_str

        restored_topo = ContainerlabTopologyFile.from_yaml(yaml_str)
        assert len(restored_topo.topology.nodes) == 150
        assert len(restored_topo.topology.links) == 300
