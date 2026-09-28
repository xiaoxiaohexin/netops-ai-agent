"""Shared pytest fixtures for langgraph_netagent test suite."""

import pytest
from langgraph_netagent.llm import LLMConfig, MockLLMProvider
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


@pytest.fixture
def mock_llm() -> MockLLMProvider:
    """Fixture providing a fresh deterministic MockLLMProvider."""
    config = LLMConfig(provider_type="mock", model_name="test-mock-llm", max_retries=3)
    return MockLLMProvider(config=config)


@pytest.fixture
def sample_network_intent() -> NetworkIntent:
    """Fixture providing a multi-vendor network intent."""
    return NetworkIntent(
        intent_id="intent-test-01",
        raw_intent="Connect pc1 and pc2 via frr1 and srl1 using static routing.",
        summary="Test multi-vendor topology intent.",
        nodes=[
            NodeIntent(name="pc1", role="host", device_kind="linux", subnets=["10.1.1.0/24"]),
            NodeIntent(name="frr1", role="router", device_kind="frr", subnets=["10.1.1.0/24", "10.1.12.0/24"]),
            NodeIntent(name="srl1", role="router", device_kind="nokia_srlinux", subnets=["10.1.12.0/24", "10.2.2.0/24"]),
            NodeIntent(name="pc2", role="host", device_kind="linux", subnets=["10.2.2.0/24"]),
        ],
        links=[
            LinkIntent(source_node="pc1", target_node="frr1", subnet="10.1.1.0/24"),
            LinkIntent(source_node="frr1", target_node="srl1", subnet="10.1.12.0/24"),
            LinkIntent(source_node="srl1", target_node="pc2", subnet="10.2.2.0/24"),
        ],
        protocols=[ProtocolType.STATIC],
        qos=QoSLevel.STANDARD,
        isolation=IsolationMode.NONE,
        source_endpoints=["pc1"],
        target_endpoints=["pc2"],
        verification_targets=["pc1 -> pc2 ping"],
    )


@pytest.fixture
def sample_topology_file() -> ContainerlabTopologyFile:
    """Fixture providing a valid ContainerlabTopologyFile."""
    return ContainerlabTopologyFile(
        name="test-lab",
        mgmt=ContainerlabMgmtConfig(
            network="clab",
            ipv4_subnet="172.100.100.0/24",
        ),
        topology=ContainerlabTopologyDefinition(
            nodes={
                "pc1": ContainerlabNodeConfig(
                    kind="linux",
                    image="alpine:latest",
                    binds=["config/pc1/setup.sh:/setup.sh"],
                    exec=["sh /setup.sh"],
                ),
                "frr1": ContainerlabNodeConfig(
                    kind="linux",
                    image="frrouting/frr:latest",
                    sysctls={"net.ipv4.ip_forward": 1},
                    binds=["config/frr/frr.conf:/etc/frr/frr.conf", "config/frr/daemons:/etc/frr/daemons"],
                ),
            },
            links=[
                ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "frr1:eth1"]),
            ],
        ),
    )


@pytest.fixture
def sample_topology_package(sample_topology_file: ContainerlabTopologyFile) -> FullTopologyPackage:
    """Fixture providing a complete FullTopologyPackage."""
    configs = [
        DeviceConfigFile(
            node_name="pc1",
            file_path="config/pc1/setup.sh",
            content="#!/bin/sh\nip addr add 10.1.1.2/24 dev eth1\n",
            permissions="0755",
            description="pc1 setup",
        ),
        DeviceConfigFile(
            node_name="frr1",
            file_path="config/frr/frr.conf",
            content="hostname frr1\ninterface eth1\n ip address 10.1.1.1/24\n",
            permissions="0644",
            description="frr1 config",
        ),
    ]
    allocations = [
        IPAllocation(
            node_name="pc1",
            interface_name="eth1",
            ipv4_address="10.1.1.2/24",
            gateway_ipv4="10.1.1.1",
            peer_node="frr1",
            peer_interface="eth1",
        ),
        IPAllocation(
            node_name="frr1",
            interface_name="eth1",
            ipv4_address="10.1.1.1/24",
            peer_node="pc1",
            peer_interface="eth1",
        ),
    ]
    return FullTopologyPackage(
        topology=sample_topology_file,
        configs=configs,
        ip_allocations=allocations,
    )


@pytest.fixture
def sample_diagnostic_report() -> DiagnosticReport:
    """Fixture providing a DiagnosticReport."""
    return DiagnosticReport(
        report_id="diag-123456",
        telemetry_trigger="Ping 10.2.2.2 100% loss",
        root_cause="Missing static route on frr1 for 10.2.2.0/24",
        affected_nodes=["frr1", "pc1", "pc2"],
        error_category=ErrorCategory.ROUTING_MISCONFIG,
        severity=SeverityLevel.HIGH,
        confidence_score=0.95,
        evidence=["Ping timeout", "FIB missing prefix 10.2.2.0/24"],
        details={"prefix": "10.2.2.0/24"},
    )


@pytest.fixture
def sample_remediation_plan() -> RemediationPlan:
    """Fixture providing a RemediationPlan."""
    return RemediationPlan(
        plan_id="fix-123456",
        action_type=RemediationActionType.PATCH_CONFIG_FILE,
        target_entity="frr1",
        configuration_patch=ConfigurationPatch(
            file_path="config/frr/frr.conf",
            patch_type="FULL_REPLACE",
            new_content="hostname frr1\nip route 10.2.2.0/24 10.1.12.2\n",
            backup_content="hostname frr1\n",
        ),
        exec_commands=["vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"],
        rollback_steps=[
            RollbackStep(
                step_order=1,
                description="Remove route",
                action="EXEC_COMMAND",
                target_node="frr1",
                payload="vtysh -c 'no ip route 10.2.2.0/24 10.1.12.2'",
            )
        ],
        expected_outcome="Route restored, ping reachability achieved",
        estimated_risk=SeverityLevel.LOW,
        requires_human_approval=False,
    )


@pytest.fixture
def sample_health_report() -> NetworkHealthReport:
    """Fixture providing a comprehensive NetworkHealthReport."""
    ping = PingTelemetry(
        src_node="pc1",
        dst_ip="10.2.2.2",
        transmitted=5,
        received=5,
        loss_pct=0.0,
        rtt_min_ms=0.5,
        rtt_avg_ms=0.8,
        rtt_max_ms=1.1,
        rtt_mdev_ms=0.1,
        is_reachable=True,
        raw_output="5 packets transmitted, 5 received, 0% packet loss",
    )
    route_table = RouteTableTelemetry(
        node="frr1",
        routes=[
            RouteEntry(destination="10.1.1.0/24", next_hop=None, interface="eth1", protocol="connected"),
            RouteEntry(destination="10.2.2.0/24", next_hop="10.1.12.2", interface="eth2", protocol="static"),
        ],
        has_default_route=False,
        raw_output="10.1.1.0/24 dev eth1 proto kernel\n10.2.2.0/24 via 10.1.12.2 dev eth2 proto static",
    )
    interface = InterfaceTelemetry(
        node="pc1",
        interface_name="eth1",
        admin_state="UP",
        oper_state="UP",
        ip_addresses=["10.1.1.2/24"],
        mtu=1500,
        is_healthy=True,
    )
    return NetworkHealthReport(
        all_passed=True,
        ping_results=[ping],
        route_tables={"frr1": route_table},
        interfaces={"pc1": [interface]},
        failures=[],
        recommendations=["All checks passed"],
    )


@pytest.fixture
def fault_injector() -> "FaultInjector":
    """Fixture providing a fresh FaultInjector."""
    from langgraph_netagent.tools import FaultInjector
    return FaultInjector()


@pytest.fixture
def mock_engine(fault_injector: "FaultInjector") -> "MockEngine":
    """Fixture providing a fresh MockEngine."""
    from langgraph_netagent.tools import MockEngine
    return MockEngine(fault_injector=fault_injector)


@pytest.fixture
def mock_adapter(mock_engine: "MockEngine", fault_injector: "FaultInjector") -> "MockContainerlabAdapter":
    """Fixture providing a fresh MockContainerlabAdapter."""
    from langgraph_netagent.tools import MockContainerlabAdapter
    return MockContainerlabAdapter(mock_engine=mock_engine, fault_injector=fault_injector)


@pytest.fixture
def full_multi_node_package() -> FullTopologyPackage:
    """Fixture providing a 4-node multi-vendor topology package (pc1, frr1, srl1, pc2)."""
    topo = ContainerlabTopologyFile(
        name="multi-vendor-lab",
        mgmt=ContainerlabMgmtConfig(network="clab", ipv4_subnet="172.100.100.0/24"),
        topology=ContainerlabTopologyDefinition(
            nodes={
                "pc1": ContainerlabNodeConfig(
                    kind="linux",
                    image="alpine:latest",
                    binds=["config/pc1/setup.sh:/setup.sh"],
                    exec=["sh /setup.sh"],
                ),
                "frr1": ContainerlabNodeConfig(
                    kind="linux",
                    image="frrouting/frr:latest",
                    sysctls={"net.ipv4.ip_forward": 1},
                    binds=["config/frr/frr.conf:/etc/frr/frr.conf", "config/frr/daemons:/etc/frr/daemons"],
                ),
                "srl1": ContainerlabNodeConfig(
                    kind="nokia_srlinux",
                    image="ghcr.io/nokia/srlinux:latest",
                    startup_config="config/srl/srl.cfg",
                ),
                "pc2": ContainerlabNodeConfig(
                    kind="linux",
                    image="alpine:latest",
                    binds=["config/pc2/setup.sh:/setup.sh"],
                    exec=["sh /setup.sh"],
                ),
            },
            links=[
                ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "frr1:eth1"]),
                ContainerlabLinkEndpoint(endpoints=["frr1:eth2", "srl1:e1-1"]),
                ContainerlabLinkEndpoint(endpoints=["srl1:e1-2", "pc2:eth1"]),
            ],
        ),
    )
    configs = [
        DeviceConfigFile(
            node_name="pc1",
            file_path="config/pc1/setup.sh",
            content="#!/bin/sh\nip link set dev eth1 up\nip addr add 10.1.1.2/24 dev eth1\nip route replace default via 10.1.1.1 dev eth1\n",
            permissions="0755",
            description="pc1 setup script",
        ),
        DeviceConfigFile(
            node_name="frr1",
            file_path="config/frr/frr.conf",
            content="""hostname frr1
service integrated-vtysh-config
!
interface eth1
 ip address 10.1.1.1/24
!
interface eth2
 ip address 10.1.12.1/24
!
ip route 10.2.2.0/24 10.1.12.2
!
line vty
!
""",
            permissions="0644",
            description="frr1 config",
        ),
        DeviceConfigFile(
            node_name="srl1",
            file_path="config/srl/srl.cfg",
            content="""enter candidate
set / interface e1-1 subinterface 0 ipv4 address 10.1.12.2/24
set / interface e1-2 subinterface 0 ipv4 address 10.2.2.1/24
set / network-instance default static-route 10.1.1.0/24 next-hop 10.1.12.1
commit stay
""",
            permissions="0644",
            description="srl1 config",
        ),
        DeviceConfigFile(
            node_name="pc2",
            file_path="config/pc2/setup.sh",
            content="#!/bin/sh\nip link set dev eth1 up\nip addr add 10.2.2.2/24 dev eth1\nip route replace default via 10.2.2.1 dev eth1\n",
            permissions="0755",
            description="pc2 setup script",
        ),
    ]
    allocations = [
        IPAllocation(node_name="pc1", interface_name="eth1", ipv4_address="10.1.1.2/24", gateway_ipv4="10.1.1.1"),
        IPAllocation(node_name="frr1", interface_name="eth1", ipv4_address="10.1.1.1/24"),
        IPAllocation(node_name="frr1", interface_name="eth2", ipv4_address="10.1.12.1/24"),
        IPAllocation(node_name="srl1", interface_name="e1-1", ipv4_address="10.1.12.2/24"),
        IPAllocation(node_name="srl1", interface_name="e1-2", ipv4_address="10.2.2.1/24"),
        IPAllocation(node_name="pc2", interface_name="eth1", ipv4_address="10.2.2.2/24", gateway_ipv4="10.2.2.1"),
    ]
    return FullTopologyPackage(
        topology=topo,
        configs=configs,
        ip_allocations=allocations,
    )

