"""Unit and Safety Tests for Agent Access Layer (AAL).

Verifies:
1. Security whitelist & blacklist enforcement (blocking destructive commands).
2. Read-only mode enforcement for Stage-1 context enrichment.
3. Structured JSON output normalization for CLI outputs (ip addr, ip route, ping).
4. Step tagging tracking.
"""

import pytest

from langgraph_netagent.models.operational import AALResponse, AALToolCall
from langgraph_netagent.tools.aal import AALSecurityError, AgentAccessLayer
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter


@pytest.fixture
def mock_adapter():
    return MockContainerlabAdapter()


@pytest.fixture
def aal(mock_adapter):
    return AgentAccessLayer(lab_adapter=mock_adapter, raise_on_security_violation=False)


@pytest.fixture
def strict_aal(mock_adapter):
    return AgentAccessLayer(lab_adapter=mock_adapter, raise_on_security_violation=True)


class TestAALSecurityRules:
    """Verify security policies block destructive commands."""

    @pytest.mark.parametrize(
        "blocked_cmd",
        [
            "ip addr flush dev eth1",
            "ip address flush dev eth1",
            "reboot",
            "shutdown -h now",
            "init 0",
            "init 6",
            "poweroff",
            "systemctl reboot",
            "rm -rf /",
            "rm -rf /etc/frr/*",
            "mkfs.ext4 /dev/sda1",
            "dd if=/dev/zero of=/dev/sda",
            ":(){ :|:& };:",
            "ip link delete dev eth1",
        ],
    )
    def test_destructive_commands_blocked(self, aal: AgentAccessLayer, blocked_cmd: str):
        tool_call = AALToolCall(
            tool_name="cli_exec",
            node_name="frr1",
            command=blocked_cmd,
            step_tag="test_step",
        )
        resp = aal.execute(tool_call)
        assert resp.success is False
        assert resp.is_blocked is True
        assert resp.exit_code == 126
        assert "SECURITY POLICY VIOLATION" in (resp.error_message or "")

    def test_strict_mode_raises_exception(self, strict_aal: AgentAccessLayer):
        tool_call = AALToolCall(
            tool_name="cli_exec",
            node_name="frr1",
            command="rm -rf /var/log/*",
        )
        with pytest.raises(AALSecurityError):
            strict_aal.execute(tool_call)

    def test_whitelisted_commands_allowed(self, aal: AgentAccessLayer):
        tool_call = AALToolCall(
            tool_name="cli_exec",
            node_name="frr1",
            command="vtysh -c 'show ip route'",
            step_tag="step_1",
            read_only=True,
        )
        resp = aal.execute(tool_call)
        assert resp.is_blocked is False
        assert resp.step_tag == "step_1"


class TestAALReadOnlyEnforcement:
    """Verify Stage-1 read-only constraints prevent mutating network state."""

    @pytest.mark.parametrize(
        "mutating_cmd",
        [
            "ip route add 10.2.2.0/24 via 10.1.12.2",
            "ip addr add 10.1.1.5/24 dev eth1",
            "ip link set dev eth1 down",
            "vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'",
            "echo 'hostname frr1' > /etc/frr/frr.conf",
            "sed -i 's/foo/bar/g' /etc/frr/frr.conf",
        ],
    )
    def test_mutating_command_rejected_in_readonly_mode(self, aal: AgentAccessLayer, mutating_cmd: str):
        tool_call = AALToolCall(
            tool_name="read_config",
            node_name="frr1",
            command=mutating_cmd,
            read_only=True,
            step_tag="diag_stage1",
        )
        resp = aal.execute(tool_call)
        assert resp.success is False
        assert resp.is_blocked is True
        assert "READ-ONLY CONSTRAINT VIOLATION" in (resp.error_message or "")


class TestAALOutputNormalization:
    """Verify unstructured CLI responses are normalized into structured JSON."""

    def test_normalize_ip_addr_show(self, aal: AgentAccessLayer):
        raw_stdout = (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    link/ether 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "2: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
            "    link/ether 00:16:3e:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.1.1.1/24 scope global eth1\n"
        )
        parsed = aal.normalize_cli_output("ip addr show", raw_stdout)
        assert parsed["type"] == "interface_inventory"
        assert parsed["count"] == 2
        eth1 = [i for i in parsed["interfaces"] if i["name"] == "eth1"][0]
        assert eth1["state"] == "UP"
        assert eth1["mtu"] == 1500
        assert "10.1.1.1/24" in eth1["ips"]
        assert eth1["mac"] == "00:16:3e:12:34:56"

    def test_normalize_frr_route_show(self, aal: AgentAccessLayer):
        raw_stdout = (
            "Codes: K - kernel, C - connected, S - static\n"
            "C>* 10.1.1.0/24 is directly connected, eth1\n"
            "S>* 10.2.2.0/24 [1/0] via 10.1.12.2, eth2\n"
        )
        parsed = aal.normalize_cli_output("vtysh -c 'show ip route'", raw_stdout)
        assert parsed["type"] == "route_inventory"
        assert parsed["count"] == 2
        destinations = [r["destination"] for r in parsed["routes"]]
        assert "10.1.1.0/24" in destinations
        assert "10.2.2.0/24" in destinations
        stat_r = [r for r in parsed["routes"] if r["destination"] == "10.2.2.0/24"][0]
        assert stat_r["protocol"] == "static"
        assert stat_r["next_hop"] == "10.1.12.2"
        assert stat_r["interface"] == "eth2"

    def test_normalize_ping_success(self, aal: AgentAccessLayer):
        raw_stdout = (
            "PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.\n"
            "64 bytes from 10.2.2.2: icmp_seq=1 ttl=64 time=0.082 ms\n"
            "--- 10.2.2.2 ping statistics ---\n"
            "3 packets transmitted, 3 received, 0% packet loss, time 3000ms\n"
            "rtt min/avg/max/mdev = 0.075/0.082/0.090/0.005 ms\n"
        )
        parsed = aal.normalize_cli_output("ping -c 3 10.2.2.2", raw_stdout, exit_code=0)
        assert parsed["type"] == "ping_telemetry"
        assert parsed["packets_transmitted"] == 3
        assert parsed["packets_received"] == 3
        assert parsed["packet_loss_pct"] == 0.0
        assert parsed["is_reachable"] is True
        assert parsed["rtt_avg_ms"] == 0.082

    def test_normalize_ping_failure(self, aal: AgentAccessLayer):
        raw_stdout = (
            "PING 10.2.2.2 (10.2.2.2) 56(84) bytes of data.\n"
            "--- 10.2.2.2 ping statistics ---\n"
            "3 packets transmitted, 0 received, 100% packet loss, time 3000ms\n"
        )
        parsed = aal.normalize_cli_output("ping -c 3 10.2.2.2", raw_stdout, exit_code=1)
        assert parsed["type"] == "ping_telemetry"
        assert parsed["packets_transmitted"] == 3
        assert parsed["packets_received"] == 0
        assert parsed["packet_loss_pct"] == 100.0
        assert parsed["is_reachable"] is False


class TestAALStepTagging:
    """Verify execution tracking captures step_tags."""

    def test_execution_history_records_step_tag(self, aal: AgentAccessLayer):
        tool_call = AALToolCall(
            tool_name="cli_exec",
            node_name="frr1",
            command="ip route show",
            step_tag="diag_iter_2_step_1",
            read_only=True,
        )
        resp = aal.execute(tool_call)
        assert resp.step_tag == "diag_iter_2_step_1"
        assert len(aal.execution_history) == 1
        assert aal.execution_history[0]["step_tag"] == "diag_iter_2_step_1"
