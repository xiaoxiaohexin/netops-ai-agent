"""Comprehensive tests for Pydantic v2 data models in langgraph_netagent."""

import json
import pytest
from pydantic import ValidationError
import yaml
from langgraph_netagent.data import load_sft_samples
from langgraph_netagent.models import (
    ConfigurationPatch,
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    DiagnosticReport,
    ErrorCategory,
    FullTopologyPackage,
    IPAllocation,
    InterfaceTelemetry,
    IsolationMode,
    LinkIntent,
    NetworkHealthReport,
    NetworkIntent,
    NodeIntent,
    PingTelemetry,
    ProtocolType,
    QoSLevel,
    RemediationActionType,
    RemediationPlan,
    RollbackStep,
    RouteEntry,
    RouteTableTelemetry,
    SeverityLevel,
    ValidationErrorDetail,
    ValidationResult,
    ValidationSeverity,
)


class TestIntentModels:
    """Test suite for Network Intent models."""

    def test_node_intent_valid(self):
        node = NodeIntent(name=" PC1 ", role="host", device_kind="linux", subnets=["10.1.1.0/24"])
        assert node.name == "pc1"  # auto-stripped and lowercased
        assert node.role == "host"
        assert node.device_kind == "linux"
        assert node.subnets == ["10.1.1.0/24"]

    def test_node_intent_empty_name_raises(self):
        with pytest.raises(ValidationError) as exc:
            NodeIntent(name="   ", role="host")
        assert "Node name cannot be empty" in str(exc.value)

    def test_link_intent_valid(self):
        link = LinkIntent(source_node="pc1", target_node="frr1", subnet="10.1.1.0/24", bandwidth_mbps=1000)
        assert link.source_node == "pc1"
        assert link.target_node == "frr1"
        assert link.bandwidth_mbps == 1000

    def test_network_intent_full_cycle(self, sample_network_intent: NetworkIntent):
        dumped_json = sample_network_intent.model_dump_json()
        assert "pc1" in dumped_json
        assert "frr1" in dumped_json
        assert "static" in dumped_json

        loaded = NetworkIntent.model_validate_json(dumped_json)
        assert loaded.intent_id == sample_network_intent.intent_id
        assert len(loaded.nodes) == 4
        assert len(loaded.links) == 3
        assert loaded.protocols == [ProtocolType.STATIC]
        assert loaded.qos == QoSLevel.STANDARD
        assert loaded.isolation == IsolationMode.NONE


class TestTopologyModels:
    """Test suite for Containerlab topology and device config models."""

    def test_link_endpoints_valid(self):
        link = ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "frr1:eth1"])
        assert link.endpoints == ["pc1:eth1", "frr1:eth1"]

    def test_link_endpoints_invalid_count_raises(self):
        with pytest.raises(ValidationError) as exc:
            ContainerlabLinkEndpoint(endpoints=["pc1:eth1"])
        assert "Link must connect exactly 2 endpoints" in str(exc.value)

        with pytest.raises(ValidationError) as exc2:
            ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "frr1:eth1", "srl1:eth1"])
        assert "Link must connect exactly 2 endpoints" in str(exc2.value)

    def test_link_endpoints_invalid_format_raises(self):
        with pytest.raises(ValidationError) as exc:
            ContainerlabLinkEndpoint(endpoints=["pc1", "frr1:eth1"])
        assert "does not match required format '<node>:<interface>'" in str(exc.value)

    def test_topology_file_yaml_serialization_aliases(self):
        topo = ContainerlabTopologyFile(
            name="test-lab",
            mgmt=ContainerlabMgmtConfig(network="clab", ipv4_subnet="172.100.100.0/24"),
            topology=ContainerlabTopologyDefinition(
                nodes={
                    "srl1": ContainerlabNodeConfig(
                        kind="nokia_srlinux",
                        image="ghcr.io/nokia/srlinux",
                        startup_config="config/srl/srl.cfg",
                    )
                },
                links=[ContainerlabLinkEndpoint(endpoints=["srl1:e1-1", "srl1:e1-2"])],
            ),
        )

        yaml_output = topo.to_yaml()
        # Verify alias keys appear in YAML output
        assert "ipv4-subnet: 172.100.100.0/24" in yaml_output
        assert "startup-config: config/srl/srl.cfg" in yaml_output

        # Verify round-trip parsing from YAML string
        parsed = ContainerlabTopologyFile.from_yaml(yaml_output)
        assert parsed.name == "test-lab"
        assert parsed.mgmt.ipv4_subnet == "172.100.100.0/24"
        assert parsed.topology.nodes["srl1"].startup_config == "config/srl/srl.cfg"

    def test_topology_file_from_yaml_invalid_type_raises(self):
        with pytest.raises(ValueError) as exc:
            ContainerlabTopologyFile.from_yaml("['a', 'list', 'not', 'dict']")
        assert "must resolve to a dictionary" in str(exc.value)

    def test_full_topology_package(self, sample_topology_package: FullTopologyPackage):
        dumped = sample_topology_package.model_dump_json(by_alias=True)
        assert "ipv4-subnet" in dumped
        reloaded = FullTopologyPackage.model_validate_json(dumped)
        assert len(reloaded.configs) == 2
        assert len(reloaded.ip_allocations) == 2
        assert reloaded.configs[0].node_name == "pc1"
        assert reloaded.configs[0].permissions == "0755"


class TestValidationModels:
    """Test suite for pre-flight validation models."""

    def test_validation_result_valid(self):
        vr = ValidationResult(
            is_valid=True,
            validator_name="offline_syntax_validator",
            errors=[],
            warnings=[],
            summary="All syntax and semantic checks passed.",
            checked_items_count=8,
        )
        assert vr.is_valid is True
        assert len(vr.errors) == 0

    def test_validation_result_with_errors(self):
        err = ValidationErrorDetail(
            code="IP_OVERLAP",
            message="Duplicate IP 10.1.1.1 assigned to multiple interfaces",
            node="pc1",
            field="ip_allocations",
            severity=ValidationSeverity.ERROR,
            suggested_fix="Assign unique IP address to pc1:eth1",
        )
        vr = ValidationResult(
            is_valid=False,
            validator_name="offline_syntax_validator",
            errors=[err],
            warnings=[],
            summary="Pre-flight check failed with 1 error.",
            checked_items_count=5,
        )
        assert vr.is_valid is False
        assert len(vr.errors) == 1
        assert vr.errors[0].code == "IP_OVERLAP"
        assert vr.errors[0].severity == ValidationSeverity.ERROR


class TestDiagnosticAndRemediationModels:
    """Test suite for diagnostic reports and remediation plans."""

    def test_diagnostic_report_cycle(self, sample_diagnostic_report: DiagnosticReport):
        assert sample_diagnostic_report.error_category == ErrorCategory.ROUTING_MISCONFIG
        assert sample_diagnostic_report.severity == SeverityLevel.HIGH
        assert sample_diagnostic_report.confidence_score == 0.95

        dumped = sample_diagnostic_report.model_dump_json()
        reloaded = DiagnosticReport.model_validate_json(dumped)
        assert reloaded.report_id == sample_diagnostic_report.report_id
        assert reloaded.root_cause == sample_diagnostic_report.root_cause

    def test_remediation_plan_cycle(self, sample_remediation_plan: RemediationPlan):
        assert sample_remediation_plan.action_type == RemediationActionType.PATCH_CONFIG_FILE
        assert sample_remediation_plan.configuration_patch is not None
        assert sample_remediation_plan.configuration_patch.file_path == "config/frr/frr.conf"
        assert len(sample_remediation_plan.rollback_steps) == 1
        assert sample_remediation_plan.rollback_steps[0].step_order == 1

        dumped = sample_remediation_plan.model_dump_json()
        reloaded = RemediationPlan.model_validate_json(dumped)
        assert reloaded.plan_id == sample_remediation_plan.plan_id
        assert reloaded.expected_outcome == sample_remediation_plan.expected_outcome


class TestTelemetryModels:
    """Test suite for network telemetry contracts and query helpers."""

    def test_ping_telemetry(self):
        ping_pass = PingTelemetry(
            src_node="pc1",
            dst_ip="10.1.1.1",
            transmitted=3,
            received=3,
            loss_pct=0.0,
            rtt_avg_ms=0.08,
            is_reachable=True,
            raw_output="3 packets transmitted, 3 received, 0% packet loss",
        )
        assert ping_pass.is_reachable is True
        assert ping_pass.loss_pct == 0.0

        ping_fail = PingTelemetry(
            src_node="pc1",
            dst_ip="10.2.2.2",
            transmitted=3,
            received=0,
            loss_pct=100.0,
            is_reachable=False,
            error_message="100% packet loss",
            raw_output="3 packets transmitted, 0 received, 100% packet loss",
        )
        assert ping_fail.is_reachable is False
        assert ping_fail.loss_pct == 100.0

    def test_route_table_telemetry_helpers(self):
        rt = RouteTableTelemetry(
            node="frr1",
            routes=[
                RouteEntry(destination="10.1.1.0/24", next_hop=None, interface="eth1", protocol="connected"),
                RouteEntry(destination="10.2.2.0/24", next_hop="10.1.12.2", interface="eth2", protocol="static"),
            ],
            has_default_route=False,
            raw_output="dummy dump",
        )
        assert rt.has_route_to("10.1.1.0/24") is True
        assert rt.has_route_to("10.2.2.0/24") is True
        assert rt.has_route_to("192.168.1.0/24") is False
        assert rt.get_nexthop("10.2.2.0/24") == "10.1.12.2"
        assert rt.get_nexthop("10.1.1.0/24") is None

    def test_interface_telemetry(self):
        intf = InterfaceTelemetry(
            node="pc1",
            interface_name="eth1",
            admin_state="UP",
            oper_state="UP",
            ip_addresses=["10.1.1.2/24"],
            is_healthy=True,
        )
        assert intf.is_healthy is True
        assert intf.admin_state == "UP"

    def test_network_health_report_summary_markdown(self, sample_health_report: NetworkHealthReport):
        markdown = sample_health_report.to_summary_markdown()
        assert "Network Verification Summary" in markdown
        assert "Status: ✅ PASSED" in markdown
        assert "Pings Checked: 1" in markdown


class TestSFTSamplesDataset:
    """Test suite ensuring SFT training samples conform to ms-swift / LLaMA-Factory standards."""

    def test_load_sft_samples(self):
        samples = load_sft_samples()
        assert len(samples) >= 4

        for sample in samples:
            assert "messages" in sample
            messages = sample["messages"]
            assert len(messages) >= 3
            assert messages[0]["role"] == "system"
            assert messages[1]["role"] == "user"
            assert messages[2]["role"] == "assistant"
            # Verify assistant payload is valid JSON
            assistant_content = messages[2]["content"]
            parsed_json = json.loads(assistant_content)
            assert isinstance(parsed_json, dict)
