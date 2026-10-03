"""Dynamic Topology Discovery Engine for Containerlab Environments.

Parses Containerlab YAML topology baselines (supporting topology.defaults, groups,
ports, link MTUs, embedded env/exec configurations, DHCP reservations, and NAT VIPs),
ingests optional runtime state from live or mock adapters, and produces a queryable
DiscoveredTopology graph model without hardcoded lookup tables.
"""

from __future__ import annotations
import collections
import ipaddress
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import yaml

from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.models.topology import (
    ContainerlabTopologyFile,
)


class TopologyDiscoverer:
    """Discovers network topology dynamically from YAML files or container runtime."""

    def __init__(self, mgmt_subnet_override: Optional[str] = None):
        """Initialize TopologyDiscoverer.
        
        Args:
            mgmt_subnet_override: Optional management subnet CIDR override.
        """
        self.mgmt_subnet_override = mgmt_subnet_override

    @classmethod
    def discover(
        cls,
        topo_file: Union[str, Path],
        adapter: Optional[Any] = None,
    ) -> DiscoveredTopology:
        """Convenience factory method to discover topology from file or runtime."""
        discoverer = cls()
        if adapter is not None:
            return discoverer.discover_from_runtime(adapter=adapter, yaml_path=topo_file)
        return discoverer.discover_from_yaml(topo_file)

    def discover_from_yaml(self, yaml_path_or_content: Union[str, Path]) -> DiscoveredTopology:
        """Parse Containerlab YAML and extract static topology, IPs, links, and roles.
        
        Args:
            yaml_path_or_content: Path to .clab.yml / .yml file or raw YAML string.
            
        Returns:
            DiscoveredTopology object with populated nodes, links, and indexes.
        """
        raw_dict, base_dir = self._load_yaml_dict(yaml_path_or_content)
        topo_model = ContainerlabTopologyFile.model_validate(raw_dict)

        # 1. Management network segregation
        mgmt_net_str = self.mgmt_subnet_override
        if not mgmt_net_str and topo_model.mgmt and topo_model.mgmt.ipv4_subnet:
            mgmt_net_str = topo_model.mgmt.ipv4_subnet
        if not mgmt_net_str:
            mgmt_net_str = "172.100.100.0/24"

        try:
            mgmt_network = ipaddress.ip_network(mgmt_net_str, strict=False)
        except ValueError:
            mgmt_network = None

        mgmt_net_name = topo_model.mgmt.network if topo_model.mgmt else "clab"
        mgmt_ipv6_str = topo_model.mgmt.ipv6_subnet if topo_model.mgmt else None

        # 2. Extract global defaults
        default_kind = "linux"
        default_env: Dict[str, Any] = {}
        default_exec: List[str] = []

        raw_topology = raw_dict.get("topology", {})
        raw_defaults = raw_topology.get("defaults") if isinstance(raw_topology, dict) else None
        if isinstance(raw_defaults, dict):
            if raw_defaults.get("kind"):
                default_kind = str(raw_defaults["kind"])
            if isinstance(raw_defaults.get("env"), dict):
                default_env = dict(raw_defaults["env"])
            if isinstance(raw_defaults.get("exec"), list):
                default_exec = [str(x) for x in raw_defaults["exec"]]

        # 3. Initialize nodes
        nodes: Dict[str, DiscoveredNode] = {}
        dhcp_reservations: Dict[str, Dict[str, Any]] = {}  # client_name -> {ip, gateway, subnet, server_node, server_iface}
        all_vips: Set[str] = set()

        for node_name, node_cfg in topo_model.topology.nodes.items():
            effective_kind = node_cfg.kind or default_kind
            effective_image = node_cfg.image or ""
            effective_group = node_cfg.group

            merged_env: Dict[str, Any] = dict(default_env)
            merged_env.update(node_cfg.env)

            merged_exec: List[str] = list(default_exec)
            for cmd in node_cfg.exec:
                cmd_str = str(cmd)
                if cmd_str not in merged_exec:
                    merged_exec.append(cmd_str)

            discovered_node = DiscoveredNode(
                name=node_name,
                kind=effective_kind,
                image=effective_image,
                group=effective_group,
                env=merged_env,
                exec_cmds=merged_exec,
                ports=[str(p) for p in node_cfg.ports],
            )

            # Parse static configs for this node
            self._extract_node_configs(
                node=discovered_node,
                node_cfg=node_cfg,
                base_dir=base_dir,
                mgmt_network=mgmt_network,
                dhcp_reservations=dhcp_reservations,
                all_vips=all_vips,
            )
            nodes[node_name] = discovered_node

        # 4. Parse Links and Adjacencies
        links: List[DiscoveredLink] = []
        for link_endpoint in topo_model.topology.links:
            if len(link_endpoint.endpoints) != 2:
                continue
            ep1, ep2 = link_endpoint.endpoints[0], link_endpoint.endpoints[1]
            node1, iface1 = ep1.split(":", 1)
            node2, iface2 = ep2.split(":", 1)
            mtu = link_endpoint.mtu or 1500

            # Register interfaces on nodes if not already present
            if node1 in nodes:
                if iface1 not in nodes[node1].interfaces:
                    nodes[node1].interfaces[iface1] = DiscoveredInterface(name=iface1, mtu=mtu)
                nodes[node1].interfaces[iface1].peer_node = node2
                nodes[node1].interfaces[iface1].peer_interface = iface2
                nodes[node1].interfaces[iface1].mtu = mtu

            if node2 in nodes:
                if iface2 not in nodes[node2].interfaces:
                    nodes[node2].interfaces[iface2] = DiscoveredInterface(name=iface2, mtu=mtu)
                nodes[node2].interfaces[iface2].peer_node = node1
                nodes[node2].interfaces[iface2].peer_interface = iface1
                nodes[node2].interfaces[iface2].mtu = mtu

            # Determine link numbering
            is_unnum = False
            link_subnet: Optional[str] = None
            if node1 in nodes and node2 in nodes:
                n1_iface = nodes[node1].interfaces.get(iface1)
                n2_iface = nodes[node2].interfaces.get(iface2)
                if n1_iface and n2_iface:
                    if not n1_iface.ipv4_addresses and not n2_iface.ipv4_addresses:
                        is_unnum = True
                        n1_iface.is_unnumbered = True
                        n2_iface.is_unnumbered = True
                    elif n1_iface.ipv4_addresses:
                        try:
                            link_subnet = str(ipaddress.ip_interface(n1_iface.ipv4_addresses[0]).network)
                        except ValueError:
                            pass

            link_obj = DiscoveredLink(
                endpoints=[(node1, iface1), (node2, iface2)],
                local_node=node1,
                local_iface=iface1,
                remote_node=node2,
                remote_iface=iface2,
                mtu=mtu,
                subnet=link_subnet,
                is_unnumbered=is_unnum,
            )
            links.append(link_obj)

        # 5. Correlate DHCP Client Reservations
        for client_name, dhcp_info in dhcp_reservations.items():
            if client_name in nodes:
                c_node = nodes[client_name]
                client_ip = dhcp_info["ip"]
                subnet_cidr = dhcp_info.get("subnet") or "24"
                if "/" not in client_ip:
                    client_ip_with_mask = f"{client_ip}/{subnet_cidr}"
                else:
                    client_ip_with_mask = client_ip

                # Connect to interface facing server if possible
                server_node = dhcp_info.get("server_node")
                assigned_iface = "eth1"
                for iface_name, iface in c_node.interfaces.items():
                    if iface.peer_node == server_node:
                        assigned_iface = iface_name
                        break

                if assigned_iface not in c_node.interfaces:
                    c_node.interfaces[assigned_iface] = DiscoveredInterface(name=assigned_iface)

                if client_ip_with_mask not in c_node.interfaces[assigned_iface].ipv4_addresses:
                    c_node.interfaces[assigned_iface].ipv4_addresses.append(client_ip_with_mask)
                if client_ip_with_mask not in c_node.ips:
                    c_node.ips.append(client_ip_with_mask)

                # Attach subnet
                try:
                    c_subnet = str(ipaddress.ip_interface(client_ip_with_mask).network)
                    if c_subnet not in c_node.subnets:
                        c_node.subnets.append(c_subnet)
                except ValueError:
                    pass

        # 6. Infer Node Roles Dynamically
        router_nodes: List[str] = []
        host_nodes: List[str] = []
        node_roles: Dict[str, str] = {}

        for node_name, node in nodes.items():
            role = self._infer_node_role(node, links)
            node.role = role
            node_roles[node_name] = role
            if role in {"router", "leaf", "spine", "superspine", "egress", "gateway"}:
                router_nodes.append(node_name)
            else:
                host_nodes.append(node_name)

        # 7. Build Indexes
        ip_to_node: Dict[str, str] = {}
        all_subnets_set: Set[str] = set()
        subnet_to_nodes: Dict[str, List[str]] = collections.defaultdict(list)

        for node_name, node in nodes.items():
            # Populate IPs
            for ip in node.ips:
                clean_ip = ip.split("/")[0]
                ip_to_node[clean_ip] = node_name
                try:
                    net_str = str(ipaddress.ip_interface(ip).network)
                    all_subnets_set.add(net_str)
                    if node_name not in subnet_to_nodes[net_str]:
                        subnet_to_nodes[net_str].append(node_name)
                except ValueError:
                    continue

            # Populate VIPs
            for vip in node.vips:
                ip_to_node[vip] = node_name
                all_vips.add(vip)

        # Sort subnets by prefix length (descending)
        subnets_sorted = sorted(
            list(all_subnets_set),
            key=lambda s: ipaddress.ip_network(s, strict=False).prefixlen if "/" in s else 0,
            reverse=True,
        )

        return DiscoveredTopology(
            name=topo_model.name,
            mgmt_network=mgmt_net_name,
            mgmt_ipv4_subnet=mgmt_net_str,
            mgmt_ipv6_subnet=mgmt_ipv6_str,
            nodes=nodes,
            links=links,
            ip_to_node=ip_to_node,
            subnet_to_nodes=dict(subnet_to_nodes),
            subnets=subnets_sorted,
            node_roles=node_roles,
            vips=sorted(all_vips),
            routers=sorted(router_nodes),
            hosts=sorted(host_nodes),
        )

    def discover_from_runtime(
        self,
        adapter: Optional[Any] = None,
        yaml_path: Optional[Union[str, Path]] = None,
    ) -> DiscoveredTopology:
        """Discover topology combining YAML static structure with runtime container introspection.
        
        Args:
            adapter: Containerlab or Mock adapter supporting execute_command(node, cmd).
            yaml_path: Optional path to YAML file to establish baseline link graph.
            
        Returns:
            DiscoveredTopology updated with runtime IP addresses, interface states, and FIBs.
        """
        if yaml_path is not None:
            topo = self.discover_from_yaml(yaml_path)
        else:
            # Fallback search for default topologies in repo
            candidates = [
                Path("clos5_dhcp.yml"),
                Path("../clos5_dhcp.yml"),
                Path("clab_output/netagent-lab.clab.yml"),
                Path("../clab_output/netagent-lab.clab.yml"),
            ]
            found_path = None
            for cand in candidates:
                if cand.exists():
                    found_path = cand
                    break
            if found_path:
                topo = self.discover_from_yaml(found_path)
            else:
                topo = DiscoveredTopology(name="runtime-discovered")

        if adapter is None:
            return topo

        # Live introspection via adapter
        try:
            mgmt_network = (
                ipaddress.ip_network(topo.mgmt_ipv4_subnet, strict=False)
                if topo.mgmt_ipv4_subnet
                else None
            )
        except ValueError:
            mgmt_network = None

        for node_name, node in topo.nodes.items():
            # Query interface IPs: ip -j addr show
            cmd_res = self._exec_adapter_cmd(adapter, node_name, "ip -j addr show")
            if not cmd_res or cmd_res.get("exit_code") != 0:
                cmd_res = self._exec_adapter_cmd(adapter, node_name, "ip addr show")
                if cmd_res and cmd_res.get("exit_code") == 0:
                    self._parse_raw_ip_addr(node, cmd_res.get("stdout", ""), mgmt_network)
            else:
                self._parse_json_ip_addr(node, cmd_res.get("stdout", ""), mgmt_network)

            # Query routes: ip -j route show
            rt_res = self._exec_adapter_cmd(adapter, node_name, "ip -j route show")
            if not rt_res or rt_res.get("exit_code") != 0:
                rt_res = self._exec_adapter_cmd(adapter, node_name, "ip route show")
                if rt_res and rt_res.get("exit_code") == 0:
                    self._parse_raw_ip_route(node, rt_res.get("stdout", ""))
            else:
                self._parse_json_ip_route(node, rt_res.get("stdout", ""))

        # Recompile indexes after runtime updates
        self._reindex_topology(topo)
        return topo

    # --------------------------------------------------------------------------
    # Internal Parsing & Extraction Helpers
    # --------------------------------------------------------------------------

    def _load_yaml_dict(self, yaml_path_or_content: Union[str, Path]) -> Tuple[Dict[str, Any], Path]:
        """Load YAML content into dict and determine base directory."""
        if isinstance(yaml_path_or_content, Path):
            p = yaml_path_or_content.resolve()
            content = p.read_text(encoding="utf-8")
            base_dir = p.parent
        elif isinstance(yaml_path_or_content, str):
            clean_str = yaml_path_or_content.strip()
            if not clean_str:
                raise ValueError("YAML content cannot be empty")
            p = Path(yaml_path_or_content)
            if "\n" not in yaml_path_or_content and p.is_file():
                resolved = p.resolve()
                content = resolved.read_text(encoding="utf-8")
                base_dir = resolved.parent
            else:
                content = yaml_path_or_content
                base_dir = Path.cwd()
        else:
            raise ValueError(f"Expected str or Path, got {type(yaml_path_or_content)}")

        raw_dict = yaml.safe_load(content)
        if not isinstance(raw_dict, dict):
            raise ValueError(f"YAML must deserialize into a dictionary, got: {type(raw_dict)}")
        return raw_dict, base_dir

    def _extract_node_configs(
        self,
        node: DiscoveredNode,
        node_cfg: Any,
        base_dir: Path,
        mgmt_network: Optional[ipaddress.IPv4Network],
        dhcp_reservations: Dict[str, Dict[str, Any]],
        all_vips: Set[str],
    ) -> None:
        """Extract IP addresses, subnets, VIPs, and routes from static declarations."""
        # A. Parse environment variables (e.g. HOSTNET, LOCAL_AS, NEIGHBORS)
        hostport = str(node.env.get("HOSTPORT", "eth3"))
        if "HOSTNET" in node.env:
            hostnet_val = str(node.env["HOSTNET"]).strip()
            self._register_node_ip(node, hostport, hostnet_val, mgmt_network)

        if "LOCAL_AS" in node.env:
            try:
                node.bgp_as = int(node.env["LOCAL_AS"])
            except (ValueError, TypeError):
                pass

        if "NEIGHBORS" in node.env:
            neighbors_str = str(node.env["NEIGHBORS"])
            for n_iface in neighbors_str.split():
                if n_iface not in node.interfaces:
                    node.interfaces[n_iface] = DiscoveredInterface(name=n_iface, is_unnumbered=True)
                else:
                    node.interfaces[n_iface].is_unnumbered = True

        # B. Parse exec commands
        ip_addr_regex = re.compile(r"ip\s+(?:addr|address)\s+add\s+([0-9\.]+/\d+)\s+dev\s+([a-zA-Z0-9_\.\-]+)")
        dnat_regex = re.compile(r"iptables\s+.*?-d\s+([0-9\.]+)\s+.*?-j\s+DNAT\s+--to-destination\s+([0-9\.]+)")
        dhcp_host_regex = re.compile(r"--dhcp-host=([a-zA-Z0-9_\-]+),([0-9\.]+)")
        dhcp_range_regex = re.compile(r"--dhcp-range=([0-9\.]+),([0-9\.]+)(?:,([0-9\.]+))?")
        dhcp_gw_regex = re.compile(r"--dhcp-option=3,([0-9\.]+)")
        dhcp_iface_regex = re.compile(r"--interface=([a-zA-Z0-9_\.\-]+)")
        route_add_regex = re.compile(r"ip\s+route\s+(?:add|replace)\s+([0-9\./]+|default)\s+via\s+([0-9\.]+)(?:\s+dev\s+([a-zA-Z0-9_\.\-]+))?")

        current_dhcp_iface = hostport
        current_dhcp_gw: Optional[str] = None
        current_dhcp_mask = "24"

        for cmd in node.exec_cmds:
            # IP assignments
            for match in ip_addr_regex.finditer(cmd):
                ip_cidr, iface_name = match.groups()
                # Check for /32 VIPs on transit interfaces
                if ip_cidr.endswith("/32"):
                    vip_ip = ip_cidr.split("/")[0]
                    node.vips.append(vip_ip)
                    all_vips.add(vip_ip)
                else:
                    self._register_node_ip(node, iface_name, ip_cidr, mgmt_network)

            # DNAT VIPs
            for match in dnat_regex.finditer(cmd):
                vip, target_ip = match.groups()
                if vip not in node.vips:
                    node.vips.append(vip)
                all_vips.add(vip)

            # DHCP Server Configurations
            if "dnsmasq" in cmd:
                iface_m = dhcp_iface_regex.search(cmd)
                if iface_m:
                    current_dhcp_iface = iface_m.group(1)
                gw_m = dhcp_gw_regex.search(cmd)
                if gw_m:
                    current_dhcp_gw = gw_m.group(1)
                range_m = dhcp_range_regex.search(cmd)
                if range_m and range_m.group(3):
                    # convert netmask to CIDR prefix
                    try:
                        current_dhcp_mask = str(ipaddress.IPv4Network(f"0.0.0.0/{range_m.group(3)}").prefixlen)
                    except Exception:
                        current_dhcp_mask = "24"

                for host_m in dhcp_host_regex.finditer(cmd):
                    client_host, client_ip = host_m.groups()
                    dhcp_reservations[client_host] = {
                        "ip": client_ip,
                        "subnet": current_dhcp_mask,
                        "gateway": current_dhcp_gw,
                        "server_node": node.name,
                        "server_iface": current_dhcp_iface,
                    }

            # Static / Default Routes
            for route_m in route_add_regex.finditer(cmd):
                dst_prefix, nexthop, dev = route_m.groups()
                node.static_routes.append({
                    "destination": dst_prefix,
                    "next_hop": nexthop,
                    "interface": dev,
                })

        # C. Parse volume mounts (binds)
        for bind in node_cfg.binds:
            parts = bind.split(":")
            host_file = parts[0]
            candidate_paths = [
                base_dir / host_file,
                base_dir.parent / host_file,
                Path(host_file),
                Path.cwd() / host_file,
                base_dir / "config" / node.name / Path(host_file).name,
            ]
            for c_path in candidate_paths:
                if c_path.exists() and c_path.is_file():
                    self._parse_bound_config_file(node, c_path, mgmt_network)
                    break

    def _parse_bound_config_file(
        self,
        node: DiscoveredNode,
        file_path: Path,
        mgmt_network: Optional[ipaddress.IPv4Network],
    ) -> None:
        """Parse startup scripts or router configurations mounted via volume binds."""
        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return

        # 1. Shell script format (setup.sh)
        ip_addr_regex = re.compile(r"ip\s+(?:addr|address)\s+add\s+([0-9\.]+/\d+)\s+dev\s+([a-zA-Z0-9_\.\-]+)")
        route_add_regex = re.compile(r"ip\s+route\s+(?:add|replace)\s+([0-9\./]+|default)\s+via\s+([0-9\.]+)(?:\s+dev\s+([a-zA-Z0-9_\.\-]+))?")

        for match in ip_addr_regex.finditer(content):
            ip_cidr, iface_name = match.groups()
            self._register_node_ip(node, iface_name, ip_cidr, mgmt_network)

        for route_m in route_add_regex.finditer(content):
            dst_prefix, nexthop, dev = route_m.groups()
            node.static_routes.append({
                "destination": dst_prefix,
                "next_hop": nexthop,
                "interface": dev,
            })

        # 2. FRR config format (frr.conf)
        frr_iface_block = re.findall(
            r"interface\s+([a-zA-Z0-9_\.\-]+)\s*\n((?:\s+.*\n)*?)!",
            content,
        )
        for iface_name, block_text in frr_iface_block:
            ip_matches = re.findall(r"ip\s+address\s+([0-9\.]+/\d+)", block_text)
            for ip_cidr in ip_matches:
                self._register_node_ip(node, iface_name, ip_cidr, mgmt_network)

    def _register_node_ip(
        self,
        node: DiscoveredNode,
        iface_name: str,
        ip_cidr: str,
        mgmt_network: Optional[ipaddress.IPv4Network],
    ) -> None:
        """Safely record an IP address to a node and its interface if not a management IP."""
        if not ip_cidr:
            return
        clean_ip = ip_cidr.strip()

        # Segregate management IPs: exclude loopback and management subnet
        if self._is_mgmt_ip(clean_ip, mgmt_network):
            if not node.mgmt_ip:
                node.mgmt_ip = clean_ip.split("/")[0]
            if iface_name not in node.interfaces:
                node.interfaces[iface_name] = DiscoveredInterface(name=iface_name, is_mgmt=True)
            node.interfaces[iface_name].is_mgmt = True
            return

        # Data-plane IP
        if iface_name not in node.interfaces:
            node.interfaces[iface_name] = DiscoveredInterface(name=iface_name)

        if clean_ip not in node.interfaces[iface_name].ipv4_addresses:
            node.interfaces[iface_name].ipv4_addresses.append(clean_ip)

        if clean_ip not in node.ips:
            node.ips.append(clean_ip)

        try:
            net_str = str(ipaddress.ip_interface(clean_ip).network)
            if net_str not in node.subnets:
                node.subnets.append(net_str)
        except ValueError:
            pass

    def _is_mgmt_ip(self, ip_str: str, mgmt_network: Optional[ipaddress.IPv4Network]) -> bool:
        """Segregate management IP from data plane IPs without hardcoded assumptions.
        
        Crucially, does NOT treat RFC 1918 172.16.x.x addresses as management unless
        the management subnet explicitly contains them.
        """
        clean = ip_str.split("/")[0].strip()
        if clean.startswith("127.") or clean == "::1":
            return True

        if mgmt_network is not None:
            try:
                ip_obj = ipaddress.ip_address(clean)
                if ip_obj in mgmt_network:
                    return True
            except ValueError:
                pass

        return False

    def _infer_node_role(self, node: DiscoveredNode, links: List[DiscoveredLink]) -> str:
        """Dynamically infer the role of a node based on group, degree, kind, or images."""
        if node.group:
            grp = node.group.lower().strip()
            if grp in {"leaf", "spine", "superspine", "egress", "router"}:
                return grp
            if grp in {"attacker", "server", "host", "client"}:
                return grp

        name_lower = node.name.lower()
        image_lower = node.image.lower()

        if "sflow" in name_lower or "sflow" in image_lower or "collector" in name_lower:
            return "collector"
        if "attacker" in name_lower:
            return "attacker"
        if "egress" in name_lower:
            return "egress"
        if "superspine" in name_lower:
            return "superspine"
        if "spine" in name_lower:
            return "spine"
        if "leaf" in name_lower:
            return "leaf"

        if node.kind.lower() in {"frr", "nokia_srlinux", "cisco_xrv", "arista_ceos"} or "frr" in image_lower:
            return "router"

        # Check connectivity degree
        node_links = [l for l in links if l.local_node == node.name or l.remote_node == node.name]
        if len(node_links) > 2 or len(node.subnets) > 1:
            return "router"

        return "host"

    def _exec_adapter_cmd(self, adapter: Any, node_name: str, cmd: str) -> Optional[Dict[str, Any]]:
        """Safely execute a command via adapter and normalize return dict."""
        try:
            func = getattr(adapter, "exec_command", None) or getattr(adapter, "execute_command", None)
            if callable(func):
                res = func(node_name, cmd)
                if hasattr(res, "stdout"):
                    return {
                        "exit_code": getattr(res, "exit_code", 0),
                        "stdout": getattr(res, "stdout", ""),
                        "stderr": getattr(res, "stderr", ""),
                    }
                if isinstance(res, dict):
                    return res
        except Exception:
            pass
        return None

    def _parse_json_ip_addr(self, node: DiscoveredNode, stdout: str, mgmt_network: Optional[ipaddress.IPv4Network]) -> None:
        """Parse output of `ip -j addr show`."""
        try:
            data = json.loads(stdout)
            if not isinstance(data, list):
                return
            for item in data:
                iface_name = item.get("ifname")
                if not iface_name or iface_name == "lo":
                    continue
                addr_info = item.get("addr_info", [])
                for addr in addr_info:
                    if addr.get("family") == "inet":
                        local_ip = addr.get("local")
                        prefixlen = addr.get("prefixlen", 24)
                        if local_ip:
                            self._register_node_ip(node, iface_name, f"{local_ip}/{prefixlen}", mgmt_network)
        except Exception:
            pass

    def _parse_raw_ip_addr(self, node: DiscoveredNode, stdout: str, mgmt_network: Optional[ipaddress.IPv4Network]) -> None:
        """Parse output of standard `ip addr show`."""
        current_iface = None
        for line in stdout.splitlines():
            line = line.strip()
            if re.match(r"^\d+:\s+([a-zA-Z0-9_\.\-]+):", line):
                m = re.match(r"^\d+:\s+([a-zA-Z0-9_\.\-]+):", line)
                if m:
                    current_iface = m.group(1).split("@")[0]
            elif line.startswith("inet ") and current_iface and current_iface != "lo":
                parts = line.split()
                if len(parts) >= 2:
                    ip_cidr = parts[1]
                    self._register_node_ip(node, current_iface, ip_cidr, mgmt_network)

    def _parse_json_ip_route(self, node: DiscoveredNode, stdout: str) -> None:
        """Parse output of `ip -j route show`."""
        try:
            data = json.loads(stdout)
            if not isinstance(data, list):
                return
            for item in data:
                dst = item.get("dst", "default")
                gateway = item.get("gateway")
                dev = item.get("dev")
                if gateway:
                    node.static_routes.append({
                        "destination": dst,
                        "next_hop": gateway,
                        "interface": dev,
                    })
        except Exception:
            pass

    def _parse_raw_ip_route(self, node: DiscoveredNode, stdout: str) -> None:
        """Parse output of standard `ip route show`."""
        for line in stdout.splitlines():
            line = line.strip()
            parts = line.split()
            if not parts:
                continue
            dst = parts[0]
            gateway = None
            dev = None
            if "via" in parts:
                idx = parts.index("via")
                if idx + 1 < len(parts):
                    gateway = parts[idx + 1]
            if "dev" in parts:
                idx = parts.index("dev")
                if idx + 1 < len(parts):
                    dev = parts[idx + 1]
            if gateway:
                node.static_routes.append({
                    "destination": dst,
                    "next_hop": gateway,
                    "interface": dev,
                })

    def _reindex_topology(self, topo: DiscoveredTopology) -> None:
        """Recompute dynamic indexes on DiscoveredTopology."""
        ip_to_node: Dict[str, str] = {}
        all_subnets_set: Set[str] = set()
        subnet_to_nodes: Dict[str, List[str]] = collections.defaultdict(list)

        for node_name, node in topo.nodes.items():
            for ip in node.ips:
                clean_ip = ip.split("/")[0]
                ip_to_node[clean_ip] = node_name
                try:
                    net_str = str(ipaddress.ip_interface(ip).network)
                    all_subnets_set.add(net_str)
                    if node_name not in subnet_to_nodes[net_str]:
                        subnet_to_nodes[net_str].append(node_name)
                except ValueError:
                    continue

            for vip in node.vips:
                ip_to_node[vip] = node_name

        topo.ip_to_node = ip_to_node
        topo.subnet_to_nodes = dict(subnet_to_nodes)
        topo.subnets = sorted(
            list(all_subnets_set),
            key=lambda s: ipaddress.ip_network(s, strict=False).prefixlen if "/" in s else 0,
            reverse=True,
        )
