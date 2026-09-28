"""Empirical challenger stress harness for Milestone M1 remediation.

Written by challenger_net_m1_r2_1 to probe edge cases in the hardened parser and models.
"""

import json
import pytest
from pydantic import ValidationError

from langgraph_netagent.llm.parser import (
    clean_json_syntax,
    extract_json_substring,
    parse_and_validate,
)
from langgraph_netagent.models.intent import (
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    ProtocolType,
)
from langgraph_netagent.models.topology import (
    ContainerlabTopologyFile,
    ContainerlabTopologyDefinition,
    DeviceConfigFile,
    IPAllocation,
)


class TestHardenedParserEdgeCases:
    """Aggressively stress-test the hardened parser."""

    def test_escaped_quote_before_comma_brace(self):
        """Escaped quotes inside strings must not disrupt quote tracking."""
        raw = '{"script": "echo \\"test\\", }", "valid": true, }'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["script"] == 'echo "test", }'
        assert data["valid"] is True

    def test_escaped_backslash_before_quote(self):
        """Escaped backslash before quote must be tracked as backslash, not escaping quote."""
        # String ending with an escaped backslash: \\
        # In JSON: "path\\", so the quote closes the string
        raw = '{"path": "C:\\\\", "trailing": 123, }'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert data["path"] == "C:\\"
        assert data["trailing"] == 123

    def test_complex_mixed_comments_and_trailing_commas(self):
        """Multiple line and block comments mixed with trailing commas in nested arrays."""
        raw = """
        // Header comment
        {
            /* block comment */
            "nodes": [
                {"name": "r1", }, // router 1
                {"name": "r2", /* inline */ },
            ],
            "links": [
                /* list of links */
                ["r1:eth1", "r2:eth1", ],
            ],
        }
        """
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert len(data["nodes"]) == 2
        assert len(data["links"]) == 1
        assert data["links"][0] == ["r1:eth1", "r2:eth1"]

    def test_unquoted_conversational_brace_with_colon_is_skipped(self):
        """Conversational text with {foo: bar} without quotes must be rejected in favor of real JSON."""
        text = (
            "Observation: {status: failed, code: 500}\n"
            "Action output:\n"
            '{"name": "resolved-topo", "topology": {"nodes": {}, "links": []}}'
        )
        extracted = extract_json_substring(text)
        data = json.loads(extracted)
        assert data["name"] == "resolved-topo"

    def test_empty_objects_and_arrays(self):
        """Empty objects and arrays should extract and clean cleanly."""
        assert extract_json_substring("Result: {}") == "{}"
        assert extract_json_substring("Result: []") == "[]"
        assert clean_json_syntax("{}") == "{}"
        assert clean_json_syntax("[]") == "[]"

    def test_multiline_string_with_literal_tabs_and_newlines(self):
        """Literal tabs and newlines inside strings are escaped for valid JSON."""
        raw = '{"config": "interface eth0\n\tip address 10.0.0.1/24\n"}'
        cleaned = clean_json_syntax(raw)
        data = json.loads(cleaned)
        assert "interface eth0" in data["config"]
        assert "10.0.0.1/24" in data["config"]


class TestHardenedModelEdgeCases:
    """Stress-test hardened Pydantic model invariants."""

    @pytest.mark.parametrize("proto", ["ospf", "OSPF", "Ospf", "bgp", "BGP", "static", "STATIC"])
    def test_protocol_case_insensitivity(self, proto):
        """All variations of protocol case must parse successfully."""
        p = ProtocolType(proto)
        assert p in (ProtocolType.OSPF, ProtocolType.BGP, ProtocolType.STATIC)

    def test_ip_allocation_valid_interfaces(self):
        """Valid CIDR notation interfaces must pass."""
        ipa = IPAllocation(node_name="r1", interface_name="eth1", ipv4_address="192.168.1.1/24")
        assert ipa.ipv4_address == "192.168.1.1/24"

        ipa2 = IPAllocation(node_name="r1", interface_name="lo", ipv4_address="10.0.0.1/32")
        assert ipa2.ipv4_address == "10.0.0.1/32"

    def test_ip_allocation_invalid_ips(self):
        """Malformed IP strings must be rejected."""
        with pytest.raises(ValidationError):
            IPAllocation(node_name="r1", interface_name="eth1", ipv4_address="300.1.1.1/24")
        with pytest.raises(ValidationError):
            IPAllocation(node_name="r1", interface_name="eth1", ipv4_address="10.0.0.1/33")
        with pytest.raises(ValidationError):
            IPAllocation(node_name="r1", interface_name="eth1", ipv4_address="not-an-ip")

    def test_link_intent_zero_bandwidth_latency(self):
        """Zero bandwidth or zero latency is non-negative and valid."""
        li = LinkIntent(source_node="n1", target_node="n2", bandwidth_mbps=0, latency_ms=0.0)
        assert li.bandwidth_mbps == 0
        assert li.latency_ms == 0.0

    def test_device_config_permissions(self):
        """Octal permissions boundary checks."""
        # 3 or 4 octal digits allowed
        cfg1 = DeviceConfigFile(node_name="r1", file_path="a.sh", content="echo 1", permissions="755")
        assert cfg1.permissions == "755"
        cfg2 = DeviceConfigFile(node_name="r1", file_path="b.sh", content="echo 1", permissions="0644")
        assert cfg2.permissions == "0644"

        # Invalid digits or lengths
        with pytest.raises(ValidationError):
            DeviceConfigFile(node_name="r1", file_path="c.sh", content="echo 1", permissions="778")
        with pytest.raises(ValidationError):
            DeviceConfigFile(node_name="r1", file_path="d.sh", content="echo 1", permissions="75")
        with pytest.raises(ValidationError):
            DeviceConfigFile(node_name="r1", file_path="e.sh", content="echo 1", permissions="07777")
