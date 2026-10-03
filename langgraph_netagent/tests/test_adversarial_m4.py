"""Adversarial stress-test suite for Milestone M4.

Adversarially challenges and stress-tests:
1. Dynamic Topology Discovery Engine (TopologyDiscoverer and DiscoveredTopology):
   - Abnormal YAML schemas (empty nodes, single node, cyclic multi-tier links, jumbo MTU 9000+, missing defaults, unnumbered links, arbitrary RFC 1918 subnets).
   - Graph queries: BFS next-hop on disconnected nodes, unknown IPs, multi-homed gateway resolution.
2. Dynamic Vendor Doc Scraper and Cache Subsystem (VendorDocScraper, DocCacheManager, ReverseRollbackGenerator):
   - Malformed HTML, missing CLI tags, nested tables, broken URLs.
   - Cache race conditions, corrupted cache files (syntax errors, empty files, schema validation errors).
   - Reverse rollback generator: diverse command strings across FRR, Cisco, Arista, and Linux netfilter/tc/ip.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List
import pytest
import bs4

from langgraph_netagent.models.discovered_topology import (
    DiscoveredInterface,
    DiscoveredLink,
    DiscoveredNode,
    DiscoveredTopology,
)
from langgraph_netagent.models.topology import (
    ContainerlabTopologyFile,
)
from langgraph_netagent.tools.topology_discovery import TopologyDiscoverer
from langgraph_netagent.tools.vendor_doc_scraper import (
    AristaDocParser,
    CiscoDocParser,
    CommandSyntax,
    DocCacheManager,
    DocFetchError,
    DocFetcher,
    FRRDocParser,
    GenericDocParser,
    ReverseRollbackGenerator,
    ScrapedDocResult,
    TroubleshootingStep,
    VendorDocScraper,
)


# =============================================================================
# Suite 1: TopologyDiscoverer Adversarial Tests
# =============================================================================

class TestTopologyDiscovererAdversarial:
    """Stress-tests TopologyDiscoverer against edge cases, cyclic graphs, and abnormal schemas."""

    def test_empty_nodes_yaml(self):
        """Topology with empty nodes dictionary parses cleanly without unhandled crashes."""
        yaml_content = """
        name: empty-nodes-lab
        topology:
          nodes: {}
          links: []
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert topo.name == "empty-nodes-lab"
        assert len(topo.nodes) == 0
        assert len(topo.links) == 0
        assert len(topo.subnets) == 0
        assert len(topo.routers) == 0
        assert len(topo.hosts) == 0

        # Query helper methods on empty topology must return None or empty collections without crashing
        assert topo.find_node_by_ip("192.168.1.1") is None
        assert topo.find_gateway_for_subnet("192.168.1.0/24") is None
        assert topo.find_router_nodes() == []
        assert topo.find_peer_interfaces("nonexistent") == {}
        assert topo.get_node_subnets("nonexistent") == []
        assert topo.resolve_next_hop("nonexistent", "192.168.1.1") is None

    def test_single_node_topology(self):
        """Single-node isolated topology without links."""
        yaml_content = """
        name: single-node-lab
        topology:
          nodes:
            standalone-server:
              kind: linux
              image: debian:latest
              exec:
                - ip addr add 10.99.0.5/24 dev eth1
          links: []
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 1
        assert "standalone-server" in topo.nodes
        assert len(topo.links) == 0

        # Query helpers
        assert topo.find_node_by_ip("10.99.0.5") == "standalone-server"
        assert topo.find_node_by_ip("10.99.0.5/24") == "standalone-server"
        # Destination is source node itself -> returns None
        assert topo.resolve_next_hop("standalone-server", "10.99.0.5") is None
        # Destination unreachable -> returns None
        assert topo.resolve_next_hop("standalone-server", "8.8.8.8") is None
        # No peer interfaces
        assert topo.find_peer_interfaces("standalone-server") == {}

    def test_multi_tier_cyclic_links(self):
        """Topology with multi-tier cyclic links (triangle and ring) does not cause BFS infinite loop."""
        yaml_content = """
        name: cyclic-lab
        topology:
          nodes:
            r1:
              kind: linux
              exec:
                - ip addr add 10.1.1.1/24 dev eth1
                - ip addr add 10.1.3.1/24 dev eth2
            r2:
              kind: linux
              exec:
                - ip addr add 10.1.1.2/24 dev eth1
                - ip addr add 10.1.2.1/24 dev eth2
            r3:
              kind: linux
              exec:
                - ip addr add 10.1.2.2/24 dev eth1
                - ip addr add 10.1.3.2/24 dev eth2
            h1:
              kind: linux
              exec:
                - ip addr add 10.99.99.1/24 dev eth1
          links:
            # Triangle cycle: r1 <-> r2 <-> r3 <-> r1
            - endpoints: [r1:eth1, r2:eth1]
            - endpoints: [r2:eth2, r3:eth1]
            - endpoints: [r3:eth2, r1:eth2]
            # Tail host to r3
            - endpoints: [r3:eth3, h1:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 4
        assert len(topo.links) == 4

        # BFS shortest-path resolution across cycles
        # r1 to r2 is direct (1 hop)
        nh_r1_to_r2 = topo.resolve_next_hop("r1", "10.1.1.2")
        assert nh_r1_to_r2 == "10.1.1.2"

        # r1 to h1 (10.99.99.1): r1 -> r3 -> h1 (or r1 -> r2 -> r3 -> h1)
        # Direct shortest path r1 -> r3 is 1 hop away
        nh_r1_to_h1 = topo.resolve_next_hop("r1", "10.99.99.1")
        assert nh_r1_to_h1 is not None
        # Must resolve to either r3's interface IP (10.1.3.2) or r2's interface IP (10.1.1.2)
        assert nh_r1_to_h1 in ("10.1.3.2", "10.1.1.2")

    def test_disconnected_components_bfs_graceful(self):
        """BFS next-hop resolution on disconnected network components returns None without crashing."""
        yaml_content = """
        name: partitioned-lab
        topology:
          nodes:
            islandA_r1:
              kind: linux
              exec:
                - ip addr add 10.10.1.1/24 dev eth1
            islandA_h1:
              kind: linux
              exec:
                - ip addr add 10.10.1.2/24 dev eth1
            islandB_r2:
              kind: linux
              exec:
                - ip addr add 10.20.1.1/24 dev eth1
            islandB_h2:
              kind: linux
              exec:
                - ip addr add 10.20.1.2/24 dev eth1
          links:
            # Component 1
            - endpoints: [islandA_r1:eth1, islandA_h1:eth1]
            # Component 2 (completely disconnected from Component 1)
            - endpoints: [islandB_r2:eth1, islandB_h2:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 4
        assert len(topo.links) == 2

        # Intracomponent resolution works
        nh_intra = topo.resolve_next_hop("islandA_r1", "10.10.1.2")
        assert nh_intra == "10.10.1.2"

        # Intercomponent query: Island A cannot reach Island B
        nh_inter = topo.resolve_next_hop("islandA_r1", "10.20.1.2")
        assert nh_inter is None

        # Unknown destination IP
        nh_unknown = topo.resolve_next_hop("islandA_r1", "198.51.100.99")
        assert nh_unknown is None

        # Non-existent source node
        assert topo.resolve_next_hop("ghost-node", "10.10.1.1") is None

    def test_jumbo_mtu_9000_plus_preservation(self):
        """Topologies with jumbo MTU (9000, 9216, 9500, 16000) preserve MTU across links and interfaces."""
        yaml_content = """
        name: jumbo-mtu-lab
        topology:
          nodes:
            spine1:
              kind: linux
            leaf1:
              kind: linux
            leaf2:
              kind: linux
          links:
            - endpoints: [spine1:eth1, leaf1:eth1]
              mtu: 9216
            - endpoints: [spine1:eth2, leaf2:eth1]
              mtu: 16000
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.links) == 2

        l1 = next(l for l in topo.links if "leaf1" in (l.local_node, l.remote_node))
        assert l1.mtu == 9216
        assert topo.nodes["leaf1"].interfaces["eth1"].mtu == 9216

        l2 = next(l for l in topo.links if "leaf2" in (l.local_node, l.remote_node))
        assert l2.mtu == 16000
        assert topo.nodes["leaf2"].interfaces["eth1"].mtu == 16000

    def test_missing_defaults_and_partial_defaults(self):
        """YAML without 'defaults' or with partial defaults parses cleanly."""
        yaml_no_defaults = """
        name: no-defaults-lab
        topology:
          nodes:
            n1:
              image: alpine:latest
          links: []
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_no_defaults)
        assert topo.nodes["n1"].kind == "linux"  # fallback default
        assert topo.nodes["n1"].image == "alpine:latest"

        yaml_partial_defaults = """
        name: partial-defaults-lab
        topology:
          defaults:
            env:
              GLOBAL_DEBUG: "1"
          nodes:
            n1:
              image: custom:v1
              env:
                LOCAL_VAR: "abc"
          links: []
        """
        topo2 = TopologyDiscoverer().discover_from_yaml(yaml_partial_defaults)
        assert topo2.nodes["n1"].env["GLOBAL_DEBUG"] == "1"
        assert topo2.nodes["n1"].env["LOCAL_VAR"] == "abc"
        assert topo2.nodes["n1"].kind == "linux"

    def test_unnumbered_links_flagging(self):
        """Point-to-point links without IP addresses are properly flagged as unnumbered."""
        yaml_content = """
        name: unnumbered-lab
        topology:
          nodes:
            r1:
              kind: linux
              env:
                NEIGHBORS: "eth1"
            r2:
              kind: linux
              env:
                NEIGHBORS: "eth1"
          links:
            - endpoints: [r1:eth1, r2:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert topo.nodes["r1"].interfaces["eth1"].is_unnumbered is True
        assert topo.nodes["r2"].interfaces["eth1"].is_unnumbered is True
        assert topo.links[0].is_unnumbered is True

    def test_arbitrary_rfc1918_subnets_preserved(self):
        """Arbitrary RFC 1918 data subnets (172.24.0.0/16, 10.99.0.0/24) are NOT filtered as management."""
        yaml_content = """
        name: rfc1918-lab
        mgmt:
          network: clab
          ipv4-subnet: 172.100.100.0/24
        topology:
          nodes:
            gw1:
              kind: linux
              exec:
                - ip addr add 172.24.0.1/16 dev eth1
                - ip addr add 10.99.0.1/24 dev eth2
                - ip addr add 192.168.250.1/24 dev eth3
            h1:
              kind: linux
              exec:
                - ip addr add 172.24.10.20/16 dev eth1
            h2:
              kind: linux
              exec:
                - ip addr add 10.99.0.100/24 dev eth1
          links:
            - endpoints: [gw1:eth1, h1:eth1]
            - endpoints: [gw1:eth2, h2:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)

        # Ensure all RFC 1918 data IPs are in ip_to_node
        assert topo.find_node_by_ip("172.24.0.1") == "gw1"
        assert topo.find_node_by_ip("172.24.10.20") == "h1"
        assert topo.find_node_by_ip("10.99.0.1") == "gw1"
        assert topo.find_node_by_ip("10.99.0.100") == "h2"
        assert topo.find_node_by_ip("192.168.250.1") == "gw1"

        # Check LPM lookup for unassigned host IP in 172.24.0.0/16
        # 172.24.99.99 is not explicitly assigned, but falls in 172.24.0.0/16
        match_node = topo.find_node_by_ip("172.24.99.99")
        assert match_node in ("gw1", "h1")

    def test_gateway_resolution_multi_homed_router(self):
        """find_gateway_for_subnet accurately resolves gateways on multi-homed routers."""
        yaml_content = """
        name: multihome-gw-lab
        topology:
          nodes:
            core-gw:
              kind: linux
              group: router
              exec:
                - ip addr add 10.1.1.1/24 dev eth1
                - ip addr add 10.2.2.1/24 dev eth2
                - ip addr add 172.16.100.1/24 dev eth3
            secondary-gw:
              kind: linux
              group: router
              exec:
                - ip addr add 10.1.1.254/24 dev eth1
            host1:
              kind: linux
              group: host
              exec:
                - ip addr add 10.1.1.50/24 dev eth1
          links:
            - endpoints: [core-gw:eth1, secondary-gw:eth1]
            - endpoints: [core-gw:eth1, host1:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)

        # On 10.1.1.0/24, both core-gw (.1) and secondary-gw (.254) are routers,
        # but core-gw ends in .1, so it gets default gateway priority bonus
        assert topo.find_gateway_for_subnet("10.1.1.0/24") == "core-gw"

        # When queried with an IP address in subnet
        assert topo.find_gateway_for_subnet("10.1.1.50") == "core-gw"
        assert topo.find_gateway_for_subnet("10.2.2.99") == "core-gw"
        assert topo.find_gateway_for_subnet("172.16.100.5") == "core-gw"

        # Nonexistent subnet
        assert topo.find_gateway_for_subnet("192.168.99.0/24") is None


# =============================================================================
# Suite 2: VendorDocScraper & Cache Subsystem Adversarial Tests
# =============================================================================

class TestVendorDocScraperAdversarial:
    """Stress-tests VendorDocScraper, DOM parsers, cache manager, and rollback generator."""

    MALFORMED_HTML_CASES = [
        "",  # completely empty
        "   \n\t   ",  # whitespace only
        "<<<<<>>>>>!@#$%^&*()",  # gibberish unclosed tags
        "<html><dl class='cli'><dt></dt><dd></dd></dl></html>",  # empty dt/dd
        "<table><tr><td>incomplete table without th or closing tr",  # malformed table
        "<table><tr><th>Keyword</th><th>Description</th></tr><tr><td>only-one-td</td></tr></table>",  # mismatched cols
        "<table><table><table><tr><td>deeply nested table</td></tr></table></table></table>",  # deeply nested
        "<script>alert('xss attack payload');</script><style>body {display:none;}</style>",  # script/style only
        "<!DOCTYPE html><html><body><h1>Header</h1><p>No CLI syntax anywhere.</p></body></html>",  # plain text
        "<html><pre># only comments\n# no real command</pre></html>",  # comments only
        "<html><dt class='sig'>\uf0c1 <a class='headerlink'>link</a></dt></html>",  # only permalinks
    ]

    @pytest.mark.parametrize("html_input", MALFORMED_HTML_CASES)
    @pytest.mark.parametrize("vendor", ["frr", "cisco", "arista", "generic"])
    def test_dom_parsers_survive_malformed_html(self, html_input: str, vendor: str):
        """All vendor DOM parsers parse malformed HTML without uncaught crashes."""
        scraper = VendorDocScraper()
        soup = bs4.BeautifulSoup(html_input, "html.parser")
        result = scraper.parse_html(html_input, url="https://test.vendor.com/doc", vendor=vendor)
        assert isinstance(result, ScrapedDocResult)
        assert result.vendor == vendor
        assert isinstance(result.commands, list)
        assert isinstance(result.troubleshooting_steps, list)

    def test_broken_urls_handling(self):
        """DocFetcher and VendorDocScraper raise DocFetchError on broken or unresolvable URLs."""
        # Non-routable or invalid URL without cache
        fetcher = DocFetcher(timeout=1.0, max_retries=1, rate_limit_delay=0.0)
        with pytest.raises(DocFetchError):
            fetcher.fetch("https://invalid-nonexistent-domain-99999.internal.corp")

    def test_cache_corrupted_json_syntax_fallback(self, tmp_path):
        """DocCacheManager cleanly ignores syntactically corrupted JSON cache files and returns None."""
        cache = DocCacheManager(cache_dir=tmp_path)
        url = "https://docs.frrouting.org/test"
        html_p, json_p = cache._get_paths(url)
        html_p.write_text("<html>valid html</html>", encoding="utf-8")
        json_p.write_text("{corrupted: json string [unclosed", encoding="utf-8")

        # get() must not crash, must return None due to json decode error
        res = cache.get(url)
        assert res is None

    def test_cache_empty_json_file_fallback(self, tmp_path):
        """DocCacheManager cleanly handles 0-byte JSON cache files."""
        cache = DocCacheManager(cache_dir=tmp_path)
        url = "https://docs.frrouting.org/empty_test"
        html_p, json_p = cache._get_paths(url)
        html_p.write_text("<html>content</html>", encoding="utf-8")
        json_p.write_text("", encoding="utf-8")  # 0 bytes

        res = cache.get(url)
        assert res is None

    def test_cache_concurrency_stress(self, tmp_path):
        """DocCacheManager handles high-concurrency read/write operations without deadlocks or corruptions."""
        cache = DocCacheManager(cache_dir=tmp_path, ttl_seconds=3600.0)
        urls = [f"https://vendor.com/doc/{i}" for i in range(20)]
        num_workers = 10
        iterations = 50

        def worker_task(worker_id: int):
            for i in range(iterations):
                url = urls[i % len(urls)]
                html = f"<html><body>Worker {worker_id} Iteration {i}</body></html>"
                meta = {"worker": worker_id, "iter": i}
                # Write
                cache.set(url, html, metadata=meta)
                # Read back
                entry = cache.get(url)
                if entry is not None:
                    assert isinstance(entry["html"], str)

        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(worker_task, wid) for wid in range(num_workers)]
            for fut in as_completed(futures):
                fut.result()  # raise any exceptions if occurred

    def test_reverse_rollback_generator_exhaustive(self):
        """Exhaustive test suite for ReverseRollbackGenerator across diverse network commands."""
        test_cases = [
            # Cisco standard negations
            ("Router(config)# ip route 10.0.0.0 255.0.0.0 10.1.1.1", "cisco", "no ip route 10.0.0.0 255.0.0.0 10.1.1.1"),
            ("Router(config)# router ospf 10", "cisco", "no router ospf 10"),
            ("Router(config-router)# network 192.168.1.0 0.0.0.255 area 0", "cisco", "no network 192.168.1.0 0.0.0.255 area 0"),
            ("Router(config-if)# shutdown", "cisco", "no shutdown"),
            ("Router(config-if)# no shutdown", "cisco", "shutdown"),
            ("Router(config)# ip access-list extended BLOCK_MALICIOUS", "cisco", "no ip access-list extended BLOCK_MALICIOUS"),

            # FRRouting commands
            ("vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'", "frr", "vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'"),
            ("vtysh -c 'conf t' -c 'router bgp 65000'", "frr", "vtysh -c 'conf t' -c 'no router bgp 65000'"),
            ("router bgp 65001", "frr", "no router bgp 65001"),

            # Arista EOS
            ("switch(config)# ip route 172.16.10.0/24 172.16.2.1", "arista", "no ip route 172.16.10.0/24 172.16.2.1"),
            ("switch(config-if-Et1)# no switchport", "arista", "switchport"),

            # Linux netfilter and iproute2
            ("ip route add 10.2.2.0/24 via 10.1.12.2 dev eth1", "linux", "ip route del 10.2.2.0/24 via 10.1.12.2 dev eth1"),
            ("ip route replace default via 192.168.1.254", "linux", "ip route del default via 192.168.1.254"),
            ("ip route append 10.0.0.0/8 via 10.1.1.1", "linux", "ip route del 10.0.0.0/8 via 10.1.1.1"),
            ("ip route del 10.2.2.0/24 via 10.1.12.2 dev eth1", "linux", "ip route add 10.2.2.0/24 via 10.1.12.2 dev eth1"),
            ("ip link set dev eth2 up", "linux", "ip link set dev eth2 down"),
            ("ip link set dev eth2 down", "linux", "ip link set dev eth2 up"),
            ("iptables -I FORWARD -s 203.0.113.10 -j DROP", "linux", "iptables -D FORWARD -s 203.0.113.10 -j DROP"),
            ("iptables -A INPUT -p tcp --dport 22 -j ACCEPT", "linux", "iptables -D INPUT -p tcp --dport 22 -j ACCEPT"),
            ("iptables -D FORWARD -s 203.0.113.10 -j DROP", "linux", "iptables -I FORWARD -s 203.0.113.10 -j DROP"),
            ("arptables -I INPUT --source-ip 10.0.0.1 -j DROP", "linux", "arptables -D INPUT --source-ip 10.0.0.1 -j DROP"),
            ("tc qdisc add dev eth1 root handle 1: tbf rate 10mbit", "linux", "tc qdisc del dev eth1 root handle 1: tbf rate 10mbit"),
            ("tc qdisc replace dev eth1 root handle 1: fq_codel", "linux", "tc qdisc del dev eth1 root handle 1: fq_codel"),
            ("tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dport 80 0xffff flowid 1:10", "linux", "tc filter del dev eth0 parent 1: protocol ip prio 1 u32 match ip dport 80 0xffff flowid 1:10"),
            ("sysctl -w net.ipv4.ip_forward=1", "linux", "# Restore original sysctl value for net.ipv4.ip_forward"),

            # Generic verbs
            ("enable feature bfd", "generic", "disable feature bfd"),
            ("add rule 10", "generic", "del rule 10"),
            ("permit tcp any any eq 80", "generic", "deny tcp any any eq 80"),
            ("start daemon zebra", "generic", "stop daemon zebra"),

            # Boundary cases
            ("", "generic", ""),
            ("   ", "generic", ""),
        ]

        for cmd, vendor, expected_rollback in test_cases:
            actual = ReverseRollbackGenerator.generate_rollback(cmd, vendor=vendor)
            assert actual == expected_rollback, f"Failed for '{cmd}' ({vendor}): expected '{expected_rollback}', got '{actual}'"

    def test_reverse_rollback_table_flag_limitation_observed(self):
        """Empirically document the limitation where iptables with preceding flags (e.g. -t nat -A) does not invert."""
        cmd = "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080"
        actual = ReverseRollbackGenerator.generate_rollback(cmd, vendor="linux")
        # Observation: because regex expects \biptables\s+-A\b, preceding '-t nat' causes regex miss
        # and falls back to 'no <command>'
        assert actual.startswith("no iptables"), f"Observed behavior changed: {actual}"

    def test_cache_corrupted_schema_raises_validation_error(self, tmp_path):
        """When cache JSON contains valid syntax but an invalid/corrupted schema, scrape() raises ValidationError."""
        cache = DocCacheManager(cache_dir=tmp_path)
        url = "https://docs.frrouting.org/schema_corrupt"
        html_p, json_p = cache._get_paths(url)
        html_p.write_text("<html>valid html</html>", encoding="utf-8")
        # Valid JSON syntax, but missing required ScrapedDocResult fields ('url', 'vendor')
        json_p.write_text(json.dumps({"result": {"bad_field": 123}, "metadata": {}}), encoding="utf-8")

        scraper = VendorDocScraper(cache_manager=cache)
        with pytest.raises(Exception) as exc_info:
            scraper.scrape(url)
        # Empirically verify that pydantic.ValidationError is raised because scrape() does not catch it
        assert "validation error" in str(exc_info.value).lower()

    def test_find_node_by_ip_adversarial_inputs(self):
        """find_node_by_ip withstands invalid, malformed, or unusual IP strings."""
        yaml_content = """
        name: ip-test-lab
        topology:
          nodes:
            r1:
              kind: linux
              exec:
                - ip addr add 10.50.1.1/24 dev eth1
          links: []
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        # Exact match
        assert topo.find_node_by_ip("10.50.1.1") == "r1"
        # Match with prefix
        assert topo.find_node_by_ip("10.50.1.1/24") == "r1"
        assert topo.find_node_by_ip("10.50.1.1/32") == "r1"
        # Match with leading/trailing whitespace
        assert topo.find_node_by_ip("  10.50.1.1  ") == "r1"
        # Invalid / out-of-range IPs
        assert topo.find_node_by_ip("999.999.999.999") is None
        assert topo.find_node_by_ip("not_an_ip") is None
        assert topo.find_node_by_ip("") is None
        assert topo.find_node_by_ip("::1") is None
        assert topo.find_node_by_ip("2001:db8::1") is None

    def test_dangling_link_discovery_does_not_crash(self):
        """A topology with links pointing to undefined nodes parses and queries without crashing."""
        yaml_content = """
        name: dangling-link-lab
        topology:
          nodes:
            r1:
              kind: linux
              exec:
                - ip addr add 10.1.1.1/24 dev eth1
          links:
            - endpoints: [r1:eth1, undefined_peer:eth1]
        """
        topo = TopologyDiscoverer().discover_from_yaml(yaml_content)
        assert len(topo.nodes) == 1
        assert len(topo.links) == 1
        assert topo.links[0].remote_node == "undefined_peer"
        # Peer interfaces should report the undefined peer
        peer_map = topo.find_peer_interfaces("r1")
        assert peer_map.get("eth1") == ("undefined_peer", "eth1")
        # Querying next hop to an IP on that undefined peer
        nh = topo.resolve_next_hop("r1", "10.1.1.99")
        # Should gracefully return None or undefined_peer without crashing
        assert nh in (None, "undefined_peer")

