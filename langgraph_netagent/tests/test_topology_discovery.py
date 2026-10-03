"""Comprehensive test suite for Dynamic Topology Discovery Engine.

Validates:
1. Containerlab schema extensions (defaults, group, ports, link MTU, dict endpoints).
2. Programmatic parsing of clos5_dhcp.yml (all nodes, all links, all data IPs including 172.16.x.x,
   NAT VIPs, and DHCP client reservations without hardcoded lookup tables).
3. Query helper methods (find_node_by_ip, find_gateway_for_subnet, find_router_nodes,
   find_peer_interfaces, get_node_subnets, resolve_next_hop).
4. Programmatic parsing of clab_output/netagent-lab.clab.yml with bound configs.
5. Runtime discovery with mock adapter and dynamic management IP segregation.
"""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from langgraph_netagent.models.topology import (
    ContainerlabDefaultsConfig,
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
)
from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CLOS5_PATH = REPO_ROOT / "clos5_dhcp.yml"
NETAGENT_LAB_PATH = REPO_ROOT / "clab_output" / "netagent-lab.clab.yml"


class TestContainerlabSchemaEnhancements:
    """Test suite verifying Containerlab schema enhancements."""

    def test_topology_defaults_applied_to_nodes(self):
        """Nodes without kind inherit topology.defaults.kind."""
        yaml_content = """
        name: defaults-test
        topology:
          defaults:
            kind: linux
            env:
              GLOBAL_VAR: "123"
          nodes:
            node1:
              image: alpine:latest
            node2:
              kind: nokia_srlinux
              image: ghcr.io/nokia/srlinux
        """
        topo = ContainerlabTopologyFile.from_yaml(yaml_content)
        assert topo.name == "defaults-test"
        assert topo.topology.defaults is not None
        assert topo.topology.nodes["node1"].kind == "linux"
        assert topo.topology.nodes["node2"].kind == "nokia_srlinux"

    def test_node_fields_group_ports_binds_env_exec(self):
        """Node models support group, ports, binds, env, and exec."""
        node = ContainerlabNodeConfig(
            kind="linux",
            image="sflow/clab-sflow-rt",
            group="telemetry",
            ports=["8008:8008"],
            binds=["/etc/hosts:/etc/hosts"],
            exec=["touch /tmp/ready"],
            env={"SAMPLE_RATE": 1000},
        )
        assert node.group == "telemetry"
        assert node.ports == ["8008:8008"]
        assert node.binds == ["/etc/hosts:/etc/hosts"]
        assert node.exec == ["touch /tmp/ready"]
        assert node.env == {"SAMPLE_RATE": 1000}

    def test_link_mtu_support(self):
        """Link models support MTU attribute."""
        link_jumbo = ContainerlabLinkEndpoint(
            endpoints=["node1:eth1", "node2:eth1"],
            mtu=9500,
        )
        assert link_jumbo.mtu == 9500

        link_std = ContainerlabLinkEndpoint(
            endpoints=["node1:eth2", "node3:eth1"],
            mtu=1500,
        )
        assert link_std.mtu == 1500

    def test_dict_style_link_endpoints(self):
        """Link endpoints in dict format are normalized to 'node:interface' strings."""
        link_dict = ContainerlabLinkEndpoint(
            endpoints=[
                {"node": "leaf1", "interface": "eth1"},
                {"node": "spine1", "interface": "eth2"},
            ]
        )
        assert link_dict.endpoints == ["leaf1:eth1", "spine1:eth2"]

    def test_mgmt_config_mtu(self):
        """ContainerlabMgmtConfig supports mtu attribute."""
        mgmt = ContainerlabMgmtConfig(
            network="fixedips",
            ipv4_subnet="172.100.100.0/24",
            mtu=1500,
        )
        assert mgmt.network == "fixedips"
        assert mgmt.mtu == 1500


class TestClos5TopologyParsing:
    """Comprehensive programmatic verification of clos5_dhcp.yml."""

    @pytest.fixture
    def clos5_topo(self) -> DiscoveredTopology:
        assert CLOS5_PATH.exists(), f"clos5_dhcp.yml not found at {CLOS5_PATH}"
        discoverer = TopologyDiscoverer()
        return discoverer.discover_from_yaml(CLOS5_PATH)

    def test_clos5_all_nodes_parsed(self, clos5_topo: DiscoveredTopology):
        """Verifies all nodes in clos5_dhcp.yml are parsed."""
        expected_nodes = {
            "leaf1", "leaf2", "leaf3", "leaf4",
            "spine1", "spine2", "spine3", "spine4",
            "superspine1", "superspine2",
            "dc-egress", "ext-router", "attacker",
            "h1", "h2", "h3", "h4",
            "sflow-rt",
        }
        assert set(clos5_topo.nodes.keys()) == expected_nodes
        assert len(clos5_topo.nodes) == 18

    def test_clos5_all_links_and_interfaces(self, clos5_topo: DiscoveredTopology):
        """Verifies all 19 links and interface connections are correctly extracted."""
        assert len(clos5_topo.links) == 19

        # Check MTU 9500 on superspine2:eth3 <-> dc-egress:eth1
        jumbo_links = [
            l for l in clos5_topo.links
            if (l.local_node == "superspine2" and l.remote_node == "dc-egress")
            or (l.local_node == "dc-egress" and l.remote_node == "superspine2")
        ]
        assert len(jumbo_links) == 1
        assert jumbo_links[0].mtu == 9500

        # Check peer interface mapping on leaf1
        leaf1_peers = clos5_topo.find_peer_interfaces("leaf1")
        assert leaf1_peers["eth1"] == ("spine1", "eth1")
        assert leaf1_peers["eth2"] == ("spine2", "eth1")
        assert leaf1_peers["eth3"] == ("h1", "eth1")

    def test_clos5_ip_extraction_without_hardcoding(self, clos5_topo: DiscoveredTopology):
        """Verifies data IP extraction from env, exec, and DHCP without hardcoded tables."""
        # leaf1 hostnet from env
        assert "172.16.1.1/24" in clos5_topo.nodes["leaf1"].ips

        # dc-egress static IPs from exec
        dc_ips = clos5_topo.nodes["dc-egress"].ips
        assert "172.16.254.2/24" in dc_ips
        assert "203.0.113.1/24" in dc_ips

        # ext-router static IPs from exec
        ext_ips = clos5_topo.nodes["ext-router"].ips
        assert "203.0.113.2/24" in ext_ips
        assert "192.168.100.1/24" in ext_ips

        # attacker dynamic DHCP reservation
        assert "192.168.100.2/24" in clos5_topo.nodes["attacker"].ips

        # h1 dynamic DHCP reservation
        assert "172.16.1.2/24" in clos5_topo.nodes["h1"].ips

        # VIPs on dc-egress
        assert "203.0.113.10" in clos5_topo.vips
        assert "203.0.113.20" in clos5_topo.vips
        assert "203.0.113.30" in clos5_topo.vips
        assert "203.0.113.40" in clos5_topo.vips

    def test_clos5_rfc1918_172_16_not_filtered(self, clos5_topo: DiscoveredTopology):
        """Validates that RFC 1918 172.16.x.x addresses are preserved as data plane IPs."""
        # 172.16.x.x must NOT be classified as management
        assert "172.16.1.1" in clos5_topo.ip_to_node
        assert clos5_topo.ip_to_node["172.16.1.1"] == "leaf1"

        assert "172.16.1.2" in clos5_topo.ip_to_node
        assert clos5_topo.ip_to_node["172.16.1.2"] == "h1"

        assert "172.16.254.2" in clos5_topo.ip_to_node
        assert clos5_topo.ip_to_node["172.16.254.2"] == "dc-egress"

        # Management network is 172.100.100.0/24
        assert clos5_topo.mgmt_ipv4_subnet == "172.100.100.0/24"

    def test_clos5_query_helpers(self, clos5_topo: DiscoveredTopology):
        """Verifies all query helper methods on clos5_dhcp.yml."""
        # 1. find_node_by_ip
        assert clos5_topo.find_node_by_ip("172.16.1.2") == "h1"
        assert clos5_topo.find_node_by_ip("192.168.100.2") == "attacker"
        assert clos5_topo.find_node_by_ip("203.0.113.10") == "dc-egress"
        assert clos5_topo.find_node_by_ip("10.99.99.99") is None

        # 2. find_gateway_for_subnet
        assert clos5_topo.find_gateway_for_subnet("172.16.1.0/24") == "leaf1"
        assert clos5_topo.find_gateway_for_subnet("172.16.2.0/24") == "leaf2"
        assert clos5_topo.find_gateway_for_subnet("192.168.100.0/24") == "ext-router"

        # 3. find_router_nodes
        routers = clos5_topo.find_router_nodes()
        assert "leaf1" in routers
        assert "spine1" in routers
        assert "superspine1" in routers
        assert "dc-egress" in routers
        assert "ext-router" in routers
        assert "attacker" not in routers
        assert "h1" not in routers

        # 4. get_node_subnets
        leaf1_subs = clos5_topo.get_node_subnets("leaf1")
        assert "172.16.1.0/24" in leaf1_subs

        # 5. resolve_next_hop
        # attacker -> 203.0.113.10: next hop must be ext-router's eth2 IP (192.168.100.1)
        next_hop_attacker = clos5_topo.resolve_next_hop("attacker", "203.0.113.10")
        assert next_hop_attacker == "192.168.100.1"

        # ext-router -> 172.16.1.2: next hop must be dc-egress's eth2 IP (203.0.113.1)
        next_hop_ext = clos5_topo.resolve_next_hop("ext-router", "172.16.1.2")
        assert next_hop_ext == "203.0.113.1"


class TestNetagentLabTopologyParsing:
    """Test suite for clab_output/netagent-lab.clab.yml parsing."""

    def test_netagent_lab_discovery(self):
        """Verifies netagent-lab.clab.yml parses nodes, links, and bound configs."""
        assert NETAGENT_LAB_PATH.exists(), f"netagent-lab.clab.yml not found at {NETAGENT_LAB_PATH}"
        discoverer = TopologyDiscoverer()
        topo = discoverer.discover_from_yaml(NETAGENT_LAB_PATH)

        assert topo.name == "netagent-lab"
        assert set(topo.nodes.keys()) == {"pc1", "frr1", "pc2"}
        assert len(topo.links) == 2

        # Check IPs extracted from bound setup.sh and frr.conf
        assert "10.1.1.2" in topo.ip_to_node
        assert topo.ip_to_node["10.1.1.2"] == "pc1"

        assert "10.2.2.2" in topo.ip_to_node
        assert topo.ip_to_node["10.2.2.2"] == "pc2"

        assert "10.1.1.1" in topo.ip_to_node
        assert topo.ip_to_node["10.1.1.1"] == "frr1"

        assert "10.2.2.1" in topo.ip_to_node
        assert topo.ip_to_node["10.2.2.1"] == "frr1"

        # Check next-hop resolution
        # pc1 routing to pc2 (10.2.2.2) via frr1 (10.1.1.1)
        nh1 = topo.resolve_next_hop("pc1", "10.2.2.2")
        assert nh1 == "10.1.1.1"

        # pc2 routing to pc1 (10.1.1.2) via frr1 (10.2.2.1)
        nh2 = topo.resolve_next_hop("pc2", "10.1.1.2")
        assert nh2 == "10.2.2.1"


class TestRuntimeDiscoveryAndSegregation:
    """Test suite for runtime discovery prober and management IP segregation."""

    class MockAdapter:
        """Simulated Containerlab adapter for runtime testing."""
        def exec_command(self, node: str, cmd: str, timeout: int = 15):
            return self.execute_command(node, cmd)

        def execute_command(self, node: str, cmd: str):
            class Result:
                def __init__(self, exit_code, stdout):
                    self.exit_code = exit_code
                    self.stdout = stdout
                    self.stderr = ""

            if "ip -j addr show" in cmd:
                if node == "pc1":
                    payload = [
                        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "172.100.100.11", "prefixlen": 24}]},
                        {"ifname": "eth1", "addr_info": [{"family": "inet", "local": "10.1.1.2", "prefixlen": 24}]},
                    ]
                    return Result(0, json.dumps(payload))
                elif node == "frr1":
                    payload = [
                        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                        {"ifname": "eth0", "addr_info": [{"family": "inet", "local": "172.100.100.12", "prefixlen": 24}]},
                        {"ifname": "eth1", "addr_info": [{"family": "inet", "local": "10.1.1.1", "prefixlen": 24}]},
                        {"ifname": "eth2", "addr_info": [{"family": "inet", "local": "10.2.2.1", "prefixlen": 24}]},
                    ]
                    return Result(0, json.dumps(payload))
            elif "ip -j route show" in cmd:
                return Result(0, json.dumps([{"dst": "default", "gateway": "10.1.1.1", "dev": "eth1"}]))
            return Result(1, "")

    def test_runtime_discovery_filters_mgmt_network(self):
        """Verifies runtime discovery correctly ignores management subnet 172.100.100.0/24."""
        discoverer = TopologyDiscoverer(mgmt_subnet_override="172.100.100.0/24")
        mock_adapter = self.MockAdapter()

        topo = discoverer.discover_from_runtime(adapter=mock_adapter, yaml_path=NETAGENT_LAB_PATH)

        # Management IPs must NOT be in data plane ip_to_node
        assert "172.100.100.11" not in topo.ip_to_node
        assert "172.100.100.12" not in topo.ip_to_node
        assert "127.0.0.1" not in topo.ip_to_node

        # Data IPs must be registered
        assert "10.1.1.2" in topo.ip_to_node
        assert "10.1.1.1" in topo.ip_to_node

        # Node mgmt_ip should record the management address
        assert topo.nodes["pc1"].mgmt_ip == "172.100.100.11"
        assert topo.nodes["frr1"].mgmt_ip == "172.100.100.12"


class TestEdgeCasesAndAdvancedQueries:
    """Test suite for edge cases, error handling, and advanced queries."""

    def test_discover_from_raw_yaml_string(self):
        """TopologyDiscoverer handles raw YAML string content."""
        yaml_content = """
        name: raw-string-lab
        mgmt:
          network: custom-net
          ipv4-subnet: 192.168.200.0/24
        topology:
          nodes:
            r1:
              kind: linux
              image: frrouting/frr:latest
              exec:
                - ip addr add 192.168.1.1/24 dev eth1
            h1:
              kind: linux
              image: alpine:latest
              exec:
                - ip addr add 192.168.1.100/24 dev eth1
          links:
            - endpoints: [r1:eth1, h1:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert topo.name == "raw-string-lab"
        assert topo.mgmt_network == "custom-net"
        assert topo.mgmt_ipv4_subnet == "192.168.200.0/24"
        assert topo.find_node_by_ip("192.168.1.1") == "r1"
        assert topo.find_node_by_ip("192.168.1.100") == "h1"
        assert topo.find_node_by_ip("192.168.1.100/24") == "h1"

    def test_discover_classmethod_factory(self):
        """TopologyDiscoverer.discover factory method operates correctly."""
        topo = TopologyDiscoverer.discover(CLOS5_PATH)
        assert topo.name == "clos5"
        assert len(topo.nodes) == 18

    def test_unnumbered_interfaces_detection(self):
        """Unnumbered links and interfaces are correctly detected and flagged."""
        topo = TopologyDiscoverer().discover_from_yaml(CLOS5_PATH)
        # spine1:eth1 and leaf1:eth1 run BGP unnumbered
        leaf1_eth1 = topo.nodes["leaf1"].interfaces["eth1"]
        spine1_eth1 = topo.nodes["spine1"].interfaces["eth1"]
        assert leaf1_eth1.is_unnumbered is True
        assert spine1_eth1.is_unnumbered is True

        # Find link between leaf1:eth1 and spine1:eth1
        unnum_links = [
            l for l in topo.links
            if (l.local_node == "leaf1" and l.local_iface == "eth1")
            or (l.remote_node == "leaf1" and l.remote_iface == "eth1")
        ]
        assert len(unnum_links) == 1
        assert unnum_links[0].is_unnumbered is True

    def test_find_gateway_by_ip_in_subnet(self):
        """find_gateway_for_subnet resolves gateway when passed an arbitrary IP in subnet."""
        topo = TopologyDiscoverer().discover_from_yaml(CLOS5_PATH)
        # 172.16.1.45 is in leaf1's 172.16.1.0/24 subnet
        gw = topo.find_gateway_for_subnet("172.16.1.45")
        assert gw == "leaf1"

        # 192.168.100.99 is in ext-router's 192.168.100.0/24 subnet
        gw_ext = topo.find_gateway_for_subnet("192.168.100.99")
        assert gw_ext == "ext-router"

    def test_invalid_yaml_raises_value_error(self):
        """Non-dictionary or invalid YAML raises ValueError."""
        with pytest.raises(ValueError):
            TopologyDiscoverer().discover_from_yaml("- not a dictionary")
        with pytest.raises(ValueError):
            TopologyDiscoverer().discover_from_yaml("")
