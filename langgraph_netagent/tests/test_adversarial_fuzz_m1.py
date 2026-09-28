"""Adversarial Fuzzing and Stress-Test Suite for Milestone M1 Hardening.

Constructed by empirical challenger (challenger_net_m1_r2_2) to stress-test:
1. clean_json_syntax: complex combinations of comments, escaped quotes, multiline strings, trailing commas.
2. extract_json_substring: heavily polluted conversational prefixes, nested markdown, partial JSON.
3. Pydantic validation: randomized fuzzing on LinkIntent, ContainerlabTopologyFile, DeviceConfigFile, IPAllocation.
"""

from __future__ import annotations
import json
import random
import string
import pytest
from pydantic import ValidationError

from langgraph_netagent.llm.parser import (
    clean_json_syntax,
    extract_json_substring,
    parse_and_validate,
    build_reflection_prompt,
)
from langgraph_netagent.models.intent import (
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    ProtocolType,
)
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)


# ==============================================================================
# SECTION 1: Stress & Fuzz Testing clean_json_syntax
# ==============================================================================

class TestCleanJsonSyntaxAdversarial:
    """Stress tests verifying clean_json_syntax preserves data while cleaning syntax flaws."""

    def test_combined_comments_escaped_quotes_and_trailing_commas(self):
        """Complex scenario: inline comments, block comments, escaped quotes, and trailing commas."""
        raw = """
        {
            // Header comment: Router specification
            "node_name": "r1", /* inline comment */
            "description": "Router \\"core-1\\" with // not a comment inside string",
            "metadata": {
                "tags": ["edge", "bgp", /* block in array */ ],
                "config_snippet": "hostname r1; /* comment in str */ end",
            }, // trailing comma after object
            "interfaces": [
                "eth1",
                "eth2", // trailing comma with comment
            ],
        }
        """
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["node_name"] == "r1"
        assert 'Router "core-1" with // not a comment inside string' == data["description"]
        assert data["metadata"]["tags"] == ["edge", "bgp"]
        assert "/* comment in str */" in data["metadata"]["config_snippet"]
        assert data["interfaces"] == ["eth1", "eth2"]

    def test_url_and_path_slashes_not_stripped(self):
        """Ensure HTTP URLs and file paths with slashes are not corrupted as comments."""
        raw = """
        {
            "repo_url": "https://github.com/srl-labs/containerlab.git",
            "file_path": "/etc/frr/daemons",
            "sed_pattern": "s//replace/g",
            "escaped_quote_before_slash": "test \\"quote\\" // still string",
        }
        """
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["repo_url"] == "https://github.com/srl-labs/containerlab.git"
        assert data["file_path"] == "/etc/frr/daemons"
        assert data["sed_pattern"] == "s//replace/g"
        assert data["escaped_quote_before_slash"] == 'test "quote" // still string'

    def test_multiple_consecutive_trailing_commas(self):
        """Ensure multiple redundant trailing commas before brackets are stripped."""
        raw = """
        {
            "items": [1, 2, 3, , , ],
            "nested": {
                "a": "val", , ,
            }, , ,
        }
        """
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["items"] == [1, 2, 3]
        assert data["nested"]["a"] == "val"

    def test_trailing_comma_hazard_in_strings_with_escaped_quotes(self):
        """CRITICAL: Comma followed by brace inside strings with escaped quotes must be untouched."""
        raw = """
        {
            "regex1": "value, } should survive",
            "regex2": "bracket, ] should survive",
            "mixed": "escaped \\"quote\\" with , } brace",
            "double_escaped": "path\\\\with\\\\comma, } brace",
            "list": ["item1, }", "item2, ]",],
        }
        """
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["regex1"] == "value, } should survive"
        assert data["regex2"] == "bracket, ] should survive"
        assert data["mixed"] == 'escaped "quote" with , } brace'
        assert data["double_escaped"] == "path\\with\\comma, } brace"
        assert data["list"] == ["item1, }", "item2, ]"]

    def test_multiline_string_with_raw_newlines_and_tabs(self):
        """Ensure literal unescaped newlines and tabs inside strings are safely escaped."""
        raw = (
            '{\n'
            '  "config": "interface eth1\n  ip address 10.1.1.1/24\n\tshutdown",\n'
            '  "status": "pending",\n'
            '}'
        )
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert "ip address 10.1.1.1/24" in data["config"]
        assert "\t" in data["config"] or "\\t" in cleaned
        assert data["status"] == "pending"

    def test_single_quoted_dict_with_url_slashes_and_comments(self):
        """Test single-quoted dict containing URL slashes // or /*."""
        raw = "{'url': 'https://example.com/api//v1', 'name': 'test'}"
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["url"] == "https://example.com/api//v1"
        assert data["name"] == "test"

    def test_single_quoted_dict_with_trailing_comma_hazard(self):
        """Test single-quoted dict containing ', }' inside string literal."""
        raw = "{'desc': 'values are 1, } and 2, ] finished', 'name': 'test'}"
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["desc"] == "values are 1, } and 2, ] finished"
        assert data["name"] == "test"

    def test_single_quoted_dict_with_mixed_types_and_booleans(self):
        """Verify Python dict representations with single quotes, booleans, and None are sanitized."""
        raw = "{'name': 'clab-demo', 'enabled': True, 'asn': None, 'peers': ['r1', 'r2'], 'count': 42}"
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["name"] == "clab-demo"
        assert data["enabled"] is True
        assert data["asn"] is None
        assert data["peers"] == ["r1", "r2"]
        assert data["count"] == 42

    def test_block_comment_at_eof_without_trailing_newline(self):
        """Ensure block comments at EOF or unclosed comments do not trigger infinite loops or crashes."""
        raw = '{"name": "test"} /* comment at end */'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["name"] == "test"

    def test_empty_and_whitespace_inputs(self):
        """Ensure empty and whitespace-only strings do not crash clean_json_syntax."""
        assert clean_json_syntax("") == ""
        assert clean_json_syntax("   ") == ""


# ==============================================================================
# SECTION 2: Stress Testing extract_json_substring
# ==============================================================================

class TestExtractJsonSubstringAdversarial:
    """Stress tests for extracting JSON from heavily polluted LLM responses."""

    def test_heavily_polluted_conversational_prefix_with_math_and_braces(self):
        """LLM response contains math notation, format strings, and fake braces before JSON."""
        response = (
            "Thinking Process:\n"
            "1. The topology requires N={2} routers and K={3} hosts.\n"
            "2. Bandwidth constraint is set: {b | b >= 100Mbps}.\n"
            "3. Format string to use: f'{node}:{port}'.\n"
            "4. Intermediate candidate: {invalid: true, missing quotes}.\n"
            "Now here is the generated network topology:\n"
            "```json\n"
            "{\n"
            '  "name": "math-lab",\n'
            '  "topology": {"nodes": {}, "links": []}\n'
            "}\n"
            "```\n"
            "End of generation."
        )
        extracted = extract_json_substring(response)
        data = json.loads(extracted)
        assert data["name"] == "math-lab"

    def test_multiple_code_blocks_with_first_block_non_json(self):
        """LLM provides bash script and YAML blocks before providing valid JSON block."""
        response = (
            "First, execute this command on the host:\n"
            "```bash\nsudo clab deploy -t lab.clab.yml\n```\n\n"
            "Next, verify YAML definition:\n"
            "```yaml\nname: lab\ntopology:\n  nodes:\n    r1: linux\n```\n\n"
            "Here is the machine-readable JSON specification:\n"
            "```json\n"
            "{\n"
            '  "name": "multi-block-lab",\n'
            '  "topology": {"nodes": {}, "links": []}\n'
            "}\n"
            "```"
        )
        extracted = extract_json_substring(response)
        data = json.loads(extracted)
        assert data["name"] == "multi-block-lab"

    def test_nested_markdown_fence_inside_json_string_literal(self):
        """JSON payload contains triple-backtick markdown blocks inside a string value."""
        response = (
            "Here is the generated topology with deployment guide in description:\n"
            "```json\n"
            "{\n"
            '  "name": "embedded-fence-lab",\n'
            '  "description": "To test connectivity:\\n```bash\\nping 10.1.1.2\\n```\\nCheck output.",\n'
            '  "topology": {"nodes": {}, "links": []}\n'
            "}\n"
            "```"
        )
        extracted = extract_json_substring(response)
        cleaned = clean_json_syntax(extracted)
        data = json.loads(cleaned)
        assert data["name"] == "embedded-fence-lab"
        assert "ping 10.1.1.2" in data["description"]

    def test_network_intent_with_embedded_backticks_in_raw_intent(self):
        """Test extracting NetworkIntent JSON when raw_intent has markdown backticks."""
        response = (
            "Here is the network intent:\n"
            "```json\n"
            "{\n"
            '  "raw_intent": "Configure nodes to test with ```ping -c 3 10.1.1.1``` command",\n'
            '  "summary": "Ping test intent",\n'
            '  "nodes": [\n'
            '    {"name": "r1", "role": "router"}\n'
            '  ]\n'
            "}\n"
            "```"
        )
        extracted = extract_json_substring(response)
        cleaned = clean_json_syntax(extracted)
        data = json.loads(cleaned)
        assert data.get("summary") == "Ping test intent"
        assert "nodes" in data
        assert data["nodes"][0]["name"] == "r1"

    def test_generic_code_fence_without_json_tag(self):
        """Code block without language identifier should still be extracted."""
        response = (
            "Here is the output:\n"
            "```\n"
            '{"name": "generic-fence-lab", "topology": {"nodes": {}, "links": []}}\n'
            "```"
        )
        extracted = extract_json_substring(response)
        data = json.loads(extracted)
        assert data["name"] == "generic-fence-lab"

    def test_root_level_json_array_in_markdown(self):
        """JSON root is an array instead of an object."""
        response = (
            "Here are the requested node intents:\n"
            "```json\n"
            "[\n"
            '  {"name": "r1", "role": "router"},\n'
            '  {"name": "pc1", "role": "host"}\n'
            "]\n"
            "```"
        )
        extracted = extract_json_substring(response)
        data = json.loads(extracted)
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["name"] == "r1"

    def test_no_json_opening_bracket_raises_value_error(self):
        """Plain text without any '{' or '[' must raise ValueError."""
        response = "I am unable to fulfill the request because the topology requirements are conflicting."
        with pytest.raises(ValueError, match="No JSON opening bracket"):
            extract_json_substring(response)

    def test_partial_truncated_json_without_closing_bracket(self):
        """Truncated JSON without any closing bracket must raise ValueError."""
        response = '```json\n{\n  "name": "truncated-lab",\n  "topology": '
        with pytest.raises(ValueError, match="Could not extract balanced JSON"):
            extract_json_substring(response)

    def test_empty_string_raises_value_error(self):
        """Empty or whitespace-only string must raise ValueError."""
        with pytest.raises(ValueError, match="Input text is empty"):
            extract_json_substring("   \n\t   ")


# ==============================================================================
# SECTION 3: Randomized Fuzzing on Pydantic Data Contracts
# ==============================================================================

class TestPydanticModelRandomizedFuzzing:
    """Adversarial randomized fuzzing on LinkIntent, TopologyFile, DeviceConfigFile, and IPAllocation."""

    def test_link_intent_fuzz_invalid_nodes(self):
        """Fuzz LinkIntent with 50 randomized whitespace and invalid string node identifiers."""
        random.seed(42)
        whitespace_chars = [" ", "\t", "\n", "\r", "\v", "\f"]

        for _ in range(50):
            # Generate random whitespace string of length 1..10
            length = random.randint(1, 10)
            bad_node = "".join(random.choice(whitespace_chars) for _ in range(length))

            # Test invalid source_node
            with pytest.raises(ValidationError):
                LinkIntent(source_node=bad_node, target_node="r2")

            # Test invalid target_node
            with pytest.raises(ValidationError):
                LinkIntent(source_node="r1", target_node=bad_node)

    def test_link_intent_fuzz_negative_metrics(self):
        """Fuzz LinkIntent with 50 randomized negative values for bandwidth and latency."""
        random.seed(43)

        for _ in range(50):
            neg_bw = random.randint(-1_000_000, -1)
            with pytest.raises(ValidationError):
                LinkIntent(source_node="r1", target_node="r2", bandwidth_mbps=neg_bw)

            neg_lat = -random.uniform(0.001, 10000.0)
            with pytest.raises(ValidationError):
                LinkIntent(source_node="r1", target_node="r2", latency_ms=neg_lat)

    def test_containerlab_topology_file_fuzz_invalid_names(self):
        """Fuzz ContainerlabTopologyFile with 50 randomized whitespace names."""
        random.seed(44)
        whitespace_chars = [" ", "\t", "\n", "\r"]

        for _ in range(50):
            length = random.randint(1, 12)
            bad_name = "".join(random.choice(whitespace_chars) for _ in range(length))
            with pytest.raises(ValidationError):
                ContainerlabTopologyFile(
                    name=bad_name,
                    topology=ContainerlabTopologyDefinition(nodes={}),
                )

    def test_containerlab_topology_file_fuzz_invalid_endpoints(self):
        """Fuzz ContainerlabLinkEndpoint with randomized malformed endpoint pairs."""
        random.seed(45)

        invalid_endpoints = [
            [],
            ["r1:eth1"],
            ["r1:eth1", "r2:eth1", "r3:eth1"],
            ["r1eth1", "r2:eth1"],
            ["r1:eth1:sub", "r2:eth1"],
            ["r1:eth 1", "r2:eth1"],
            ["r1:eth1", "r2/eth1"],
            [" :eth1", "r2:eth1"],
            ["r1: ", "r2:eth1"],
            ["r1::eth1", "r2:eth1"],
        ]

        for ep_list in invalid_endpoints:
            with pytest.raises(ValidationError):
                ContainerlabLinkEndpoint(endpoints=ep_list)

    def test_device_config_file_fuzz_invalid_permissions(self):
        """Fuzz DeviceConfigFile with 50 randomized non-octal and malformed permission strings."""
        random.seed(46)

        non_octal_digits = ["8", "9", "a", "x", "!", "Z", " "]
        for _ in range(50):
            # Mix valid octal and non-octal
            length = random.choice([1, 2, 3, 4, 5, 6])
            perm = "".join(random.choice(string.digits + string.ascii_letters) for _ in range(length))
            # If accidentally a valid 3-4 digit octal, skip
            if len(perm) in (3, 4) and all(c in "01234567" for c in perm):
                continue
            with pytest.raises(ValidationError):
                DeviceConfigFile(
                    node_name="r1",
                    file_path="config/frr/frr.conf",
                    content="hostname r1",
                    permissions=perm,
                )

    def test_ip_allocation_fuzz_invalid_ipv4(self):
        """Fuzz IPAllocation with 50 randomized malformed IPv4 CIDR addresses."""
        random.seed(47)

        malformed_ips = [
            "256.1.1.1/24",
            "10.300.1.1/24",
            "10.1.1.1/33",
            "10.1.1.1/-1",
            "10.1.1.1/abc",
            "fe80::1/64",
            "2001:db8::1",
            "999.999.999.999",
            "10.1.1.1/24/24",
            "10.1.1",
            "10.1.1.1.1/24",
            "not-an-ip",
            "   ",
            "",
        ]

        for bad_ip in malformed_ips:
            with pytest.raises(ValidationError):
                IPAllocation(
                    node_name="r1",
                    interface_name="eth1",
                    ipv4_address=bad_ip,
                )

    def test_ip_allocation_fuzz_invalid_gateway(self):
        """Fuzz IPAllocation gateway_ipv4 with invalid IP formats and CIDR notation."""
        invalid_gateways = [
            "10.1.1.254/24",  # Gateway must NOT have CIDR mask
            "256.0.0.1",
            "999.999.999.999",
            "fe80::1",
            "gateway.local",
            "10.1.1.1/32",
        ]

        for bad_gw in invalid_gateways:
            with pytest.raises(ValidationError):
                IPAllocation(
                    node_name="r1",
                    interface_name="eth1",
                    ipv4_address="10.1.1.1/24",
                    gateway_ipv4=bad_gw,
                )

    def test_full_pipeline_parse_and_validate_fuzz(self):
        """End-to-end parse_and_validate with simulated noisy LLM output into Pydantic models."""
        noisy_output = (
            "Certainly! Based on your specification, here is the network intent:\n"
            "```json\n"
            "{\n"
            '  // User intent definition\n'
            '  "raw_intent": "Connect r1 to r2 with OSPF",\n'
            '  "summary": "Point-to-point OSPF link between r1 and r2",\n'
            '  "nodes": [\n'
            '    {"name": "R1", "role": "router", "device_kind": "frr"},\n'
            '    {"name": "R2", "role": "router", "device_kind": "frr",}\n'
            '  ],\n'
            '  "links": [\n'
            '    {"source_node": "R1", "target_node": "R2", "bandwidth_mbps": 1000, "latency_ms": 5.0,}\n'
            '  ],\n'
            '  "protocols": ["OSPF",], // case insensitive protocol coercion test\n'
            "}\n"
            "```\n"
            "Let me know if you would like me to deploy this!"
        )

        instance, err = parse_and_validate(noisy_output, NetworkIntent)
        assert err is None, f"Expected successful parse and validate, got error: {err}"
        assert instance is not None
        assert instance.summary == "Point-to-point OSPF link between r1 and r2"
        assert len(instance.nodes) == 2
        assert instance.nodes[0].name == "r1"  # normalized to lowercase
        assert instance.links[0].source_node == "r1"
        assert instance.links[0].target_node == "r2"
        assert instance.protocols == [ProtocolType.OSPF]

    def test_containerlab_topology_from_yaml_adversarial(self):
        """Test from_yaml with non-dict YAML, empty YAML, and syntax errors."""
        with pytest.raises(ValueError, match="YAML content must resolve to a dictionary"):
            ContainerlabTopologyFile.from_yaml("")

        with pytest.raises(ValueError, match="YAML content must resolve to a dictionary"):
            ContainerlabTopologyFile.from_yaml("- item1\n- item2")

        with pytest.raises(ValueError, match="YAML content must resolve to a dictionary"):
            ContainerlabTopologyFile.from_yaml("just a string")

    def test_full_topology_package_invalid_nested_members(self):
        """Test FullTopologyPackage rejects invalid nested topology and invalid configs."""
        with pytest.raises(ValidationError):
            FullTopologyPackage(
                topology={"name": "   ", "topology": {"nodes": {}}},
                configs=[],
            )

        with pytest.raises(ValidationError):
            FullTopologyPackage(
                topology={
                    "name": "valid-name",
                    "topology": {"nodes": {}},
                },
                configs=[
                    {"node_name": "r1", "file_path": "path", "content": "c", "permissions": "0999"}
                ],
            )
