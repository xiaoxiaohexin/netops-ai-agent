"""Tests for LabIsolationGuard (R4).

Validates:
1. Container naming boundaries: clab-clos5-* pattern and clos5 logical node enforcement.
2. Rejection of unauthorized targets (host, localhost, non-clos5 containers, malicious injections).
3. Blocking of commands targeting host network interfaces (eth0, docker0, br-*, virbr*, veth*, Windows NICs).
4. Blocking of container namespace escapes (nsenter, /proc/1/ns/net, ip netns, --net=host).
5. Blocking of destructive system operations (reboot, shutdown, disk wipe).
6. Safe allowance of legitimate clos5 container network operations.
"""

import pytest

from langgraph_netagent.tools.lab_isolation import (
    LabIsolationGuard,
    LabIsolationViolationError,
)


@pytest.fixture
def guard():
    """Create standard LabIsolationGuard instance for clos5."""
    return LabIsolationGuard(lab_name="clos5")


class TestContainerNameValidation:
    """Tests container name boundaries and target authorization."""

    @pytest.mark.parametrize(
        "valid_node",
        [
            "leaf1", "leaf2", "leaf3", "leaf4",
            "spine1", "spine2", "spine3", "spine4",
            "superspine1", "superspine2",
            "dc-egress", "ext-router",
            "h1", "h2", "h3", "h4",
            "attacker", "sflow-rt",
        ],
    )
    def test_authorized_logical_nodes(self, guard, valid_node):
        """All 18 logical nodes in clos5 are recognized as valid."""
        assert guard.is_valid_container_target(valid_node) is True
        guard.assert_container_isolated(valid_node)
        assert guard.resolve_container_name(valid_node) == f"clab-clos5-{valid_node}"

    @pytest.mark.parametrize(
        "valid_container",
        [
            "clab-clos5-leaf1",
            "clab-clos5-spine3",
            "clab-clos5-superspine1",
            "clab-clos5-dc-egress",
            "clab-clos5-ext-router",
            "clab-clos5-h1",
            "clab-clos5-attacker",
        ],
    )
    def test_authorized_canonical_containers(self, guard, valid_container):
        """Canonical clab-clos5-* containers are authorized."""
        assert guard.is_valid_container_target(valid_container) is True
        guard.assert_container_isolated(valid_container)
        assert guard.resolve_container_name(valid_container) == valid_container

    @pytest.mark.parametrize(
        "unauthorized_target",
        [
            "host",
            "localhost",
            "127.0.0.1",
            "::1",
            "root",
            "",
            None,
            "   ",
            "clab-otherlab-leaf1",
            "clab-netagent-lab-pc1",
            "leaf99",
            "unknown-router",
            "my_test_container",
            "clab-clos5-leaf1; reboot",
            "clab-clos5-leaf1$(rm -rf /)",
            "clab-clos5-leaf1/../../etc",
        ],
    )
    def test_unauthorized_targets_rejected(self, guard, unauthorized_target):
        """Unauthorized target names are rejected with LabIsolationViolationError."""
        assert guard.is_valid_container_target(unauthorized_target) is False
        with pytest.raises(LabIsolationViolationError):
            guard.assert_container_isolated(unauthorized_target)
        with pytest.raises(LabIsolationViolationError):
            guard.resolve_container_name(unauthorized_target)


class TestHostInterfaceProtection:
    """Tests blocking of commands targeting host network interfaces."""

    @pytest.mark.parametrize(
        "host_nic_command",
        [
            "ip link set dev eth0 down",
            "ip link set dev eth0 up",
            "ip addr del 172.100.100.1/24 dev eth0",
            "tc qdisc add dev eth0 root netem loss 10%",
            "ifconfig eth0 down",
        ],
    )
    def test_blocks_eth0_host_interface(self, guard, host_nic_command):
        """Mutations targeting eth0 (WSL/host primary NIC) are strictly blocked."""
        assert guard.validate_command_safety(host_nic_command, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError) as exc_info:
            guard.assert_command_safety(host_nic_command, container_name="leaf1")
        assert "targets protected host interface" in str(exc_info.value)

    @pytest.mark.parametrize(
        "bridge_command",
        [
            "ip link set dev docker0 down",
            "tc qdisc add dev docker0 root netem delay 50ms",
            "ip link set dev br-3c89a1 down",
            "tc qdisc add dev br-fa1234 root netem loss 10%",
            "ip link set dev br_mgt down",
            "ip link set dev virbr0 down",
            "ip link set dev veth39485 down",
        ],
    )
    def test_blocks_docker_and_linux_bridges(self, guard, bridge_command):
        """Mutations targeting docker0, br-*, virbr*, or veth* are blocked."""
        assert guard.validate_command_safety(bridge_command, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError) as exc_info:
            guard.assert_command_safety(bridge_command, container_name="leaf1")
        assert "targets protected host interface" in str(exc_info.value)

    @pytest.mark.parametrize(
        "windows_nic_command",
        [
            "netsh interface set interface \"vEthernet\" disable",
            "netsh interface ipv4 show interfaces",
            "Get-NetAdapter | Disable-NetAdapter",
            "ip link set dev \"Wi-Fi\" down",
            "ip link set dev \"Ethernet 2\" down",
            "ip link set dev Local Area Connection down",
        ],
    )
    def test_blocks_windows_adapters_and_tools(self, guard, windows_nic_command):
        """Mutations targeting Windows host NICs or using Windows network tools are blocked."""
        assert guard.validate_command_safety(windows_nic_command, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError):
            guard.assert_command_safety(windows_nic_command, container_name="leaf1")


class TestHostNamespaceAndEscapeProtection:
    """Tests blocking of namespace escape techniques and container breakouts."""

    @pytest.mark.parametrize(
        "escape_command",
        [
            "nsenter -t 1 -n ip link",
            "nsenter --target 1 --net ip route",
            "cat /proc/1/ns/net",
            "ls -la /proc/999/ns/net",
            "ip netns exec host_ns ip link",
            "docker run --net=host alpine",
            "docker run --network=host alpine",
            "docker run --net host alpine",
            "docker run --pid=host alpine",
            "docker run --privileged alpine",
        ],
    )
    def test_blocks_host_namespace_escapes(self, guard, escape_command):
        """Attempts to access host namespaces or escape container boundaries are blocked."""
        assert guard.validate_command_safety(escape_command, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError) as exc_info:
            guard.assert_command_safety(escape_command, container_name="leaf1")
        assert "prohibited host escape" in str(exc_info.value)


class TestDestructiveCommandsProtection:
    """Tests blocking of destructive system commands."""

    @pytest.mark.parametrize(
        "destructive_command",
        [
            "reboot",
            "poweroff",
            "halt",
            "shutdown -h now",
            "systemctl reboot",
            "systemctl poweroff",
            "rm -rf /",
            "mkfs /dev/sda",
            "wipefs -a /dev/sda",
            "shred -n 3 /dev/sdb",
        ],
    )
    def test_blocks_destructive_host_commands(self, guard, destructive_command):
        """Destructive system commands are blocked."""
        assert guard.validate_command_safety(destructive_command, container_name="leaf1") is False
        with pytest.raises(LabIsolationViolationError):
            guard.assert_command_safety(destructive_command, container_name="leaf1")


class TestLegitimateLabOperationsAllowed:
    """Tests that legitimate containerlab commands on clos5 nodes are permitted."""

    @pytest.mark.parametrize(
        "node, command",
        [
            ("leaf1", "ip link set dev eth1 down"),
            ("leaf1", "ip link set dev eth1 up"),
            ("leaf2", "ip link set dev eth2 down"),
            ("spine1", "ip link set dev eth3 down"),
            ("h1", "ip route del 172.16.0.0/16 via 172.16.1.1"),
            ("h1", "ip route add 172.16.0.0/16 via 172.16.1.1"),
            ("dc-egress", "ip route replace 172.16.0.0/16 via 172.16.254.1 dev eth1"),
            ("ext-router", "tc qdisc add dev eth1 root netem loss 25%"),
            ("ext-router", "tc qdisc del dev eth1 root"),
            ("dc-egress", "tc qdisc add dev eth2 root netem delay 50ms 10ms"),
            ("dc-egress", "tc qdisc del dev eth2 root"),
            ("leaf1", 'vtysh -c "conf t" -c "router bgp 65001" -c "neighbor eth1 shutdown"'),
            ("leaf1", 'vtysh -c "conf t" -c "router bgp 65001" -c "no neighbor eth1 shutdown"'),
            ("leaf3", "vtysh -c 'show ip route json'"),
            ("h1", "ping -c 3 -W 2 172.16.2.2"),
        ],
    )
    def test_allows_legitimate_clos5_operations(self, guard, node, command):
        """Legitimate network diagnostic and remediation commands on clos5 nodes pass."""
        assert guard.validate_command_safety(command, container_name=node) is True
        guard.assert_command_safety(command, container_name=node)
