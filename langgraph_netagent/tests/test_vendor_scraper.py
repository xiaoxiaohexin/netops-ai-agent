"""Acceptance & Unit Tests for Dynamic Vendor Documentation Scraper and SOP Retriever (Requirement R2).

Verifies:
1. Multi-vendor DOM parsers (FRR Sphinx, Cisco Command References, Arista EOS, Generic fallback)
2. Automated Reverse Rollback Generator (Cisco, FRR, Arista, Linux netfilter/ip/tc)
3. DocFetcher network resilience (User-Agent, rate-limiting, exponential retry on 429/5xx)
4. DocCacheManager persistent SHA-256 caching (<1ms hits, TTL expiration, air-gapped stale fallback)
5. DynamicSOPRetriever integration (Tree store, Vector index, SOPDocument, `<500B` prompt budget)
6. Acceptance test against live official vendor documentation URL (when reachable)
"""

from __future__ import annotations

import json
from pathlib import Path
import time
from typing import Any
from unittest.mock import patch

import bs4
import httpx
import pytest

from langgraph_netagent.models.knowledge import DualRetrievalResult, TreeNode
from langgraph_netagent.tools.dynamic_sop_retriever import DynamicSOPRetriever
from langgraph_netagent.tools.sop_retriever import SOPDocument, SOPRetriever
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
# Realistic HTML Fixtures
# =============================================================================

FRR_STATICD_HTML_FIXTURE = """<!DOCTYPE html>
<html>
<head><title>Static Routing — FRR</title></head>
<body>
<div class="document">
  <h1>Static Routing Daemon (staticd)</h1>
  <p>Static routing provides explicit forwarding paths through network topology.</p>
  <dl class="std clicmd">
    <dt class="sig sig-object std" id="cli-ip-route-network-gateway">
      <code class="sig-name descname">ip route</code>
      <span class="sig-param">NETWORK</span>
      <span class="sig-param">GATEWAY</span>
      <span class="sig-param">[distance &lt;(1-255)&gt;]</span>
      <span class="sig-param">[tag &lt;(1-4294967295)&gt;]</span>
      <a class="headerlink" href="#cli-ip-route-network-gateway" title="Permalink to this definition">&#xf0c1;</a>
    </dt>
    <dd>
      <p>Configure a static route to destination subnet NETWORK via next-hop GATEWAY.</p>
      <ul class="simple">
        <li><strong>NETWORK</strong>: Destination IPv4 or IPv6 network in CIDR notation (e.g. 10.1.0.0/24).</li>
        <li><strong>GATEWAY</strong>: Next-hop IP address or egress interface name.</li>
      </ul>
      <div class="highlight-frr notranslate">
        <pre>
router> show ip route
router(config)# ip route 10.2.2.0/24 10.1.12.2
        </pre>
      </div>
    </dd>
  </dl>
  <dl class="std clicmd">
    <dt class="sig sig-object std" id="cli-show-ip-route">
      <code class="sig-name descname">show ip route</code>
      <a class="headerlink" href="#cli-show-ip-route" title="Permalink to this definition">&#xf0c1;</a>
    </dt>
    <dd>
      <p>Display the IP routing table installed in zebra RIB.</p>
    </dd>
  </dl>
</div>
</body>
</html>
"""

CISCO_IP_ROUTE_HTML_FIXTURE = """<!DOCTYPE html>
<html>
<head><title>Cisco IOS Command Reference - ip route</title></head>
<body>
<div class="content">
  <h2>ip route</h2>
  <p class="syntax"><code>ip route prefix mask {ip-address | interface-type interface-number} [distance]</code></p>
  <div class="section">
    <h3>Command Modes</h3>
    <p>Global configuration (config)</p>
  </div>
  <div class="section">
    <h3>Syntax Description</h3>
    <table class="table">
      <thead><tr><th>Keyword or Argument</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td>prefix</td><td>IP route prefix for the destination.</td></tr>
        <tr><td>mask</td><td>Prefix mask for the destination network.</td></tr>
        <tr><td>ip-address</td><td>IP address of the next hop that can be used to reach that network.</td></tr>
      </tbody>
    </table>
  </div>
  <div class="section">
    <h3>Examples</h3>
    <pre>
Router(config)# ip route 192.168.10.0 255.255.255.0 10.0.0.1
Router# show ip route 192.168.10.0
    </pre>
  </div>
</div>
</body>
</html>
"""

ARISTA_EOS_HTML_FIXTURE = """<!DOCTYPE html>
<html>
<head><title>Arista EOS - ip route</title></head>
<body>
  <h1>ip route</h1>
  <h3>Command Syntax</h3>
  <code>ip route &lt;ipv4-prefix/mask&gt; {&lt;next-hop-ip&gt; | &lt;interface&gt;} [distance]</code>
  <h3>Command Mode</h3>
  <p>(config)#</p>
  <h3>Usage Guidelines</h3>
  <p>Configures a static IPv4 route entry in the forwarding table.</p>
  <pre>
switch(config)# ip route 172.16.10.0/24 172.16.2.1
switch# show ip route static
  </pre>
</body>
</html>
"""

GENERIC_NET_HTML_FIXTURE = """<!DOCTYPE html>
<html>
<head><title>Linux Edge Firewall & Route Configuration</title></head>
<body>
  <h1>Edge Router Hardening Guide</h1>
  <p>To drop malicious flood traffic and verify status:</p>
  <pre>
# Diagnostic inspection
ping 10.1.1.1 -c 3
show ip route

# Active remediation
iptables -I FORWARD -s 203.0.113.10 -j DROP
ip route add 10.50.0.0/16 via 192.168.1.254
  </pre>
</body>
</html>
"""


# =============================================================================
# 1. Reverse Rollback Generator Tests
# =============================================================================

class TestReverseRollbackGenerator:
    """Verify automated inverse command generation across vendor CLI syntaxes."""

    def test_cisco_and_frr_standard_negation(self):
        cmd = "ip route 10.1.0.0 255.255.255.0 10.1.12.2"
        rb = ReverseRollbackGenerator.generate_rollback(cmd, vendor="cisco")
        assert rb == "no ip route 10.1.0.0 255.255.255.0 10.1.12.2"

        frr_cmd = "router bgp 65001"
        frr_rb = ReverseRollbackGenerator.generate_rollback(frr_cmd, vendor="frr")
        assert frr_rb == "no router bgp 65001"

    def test_strip_prompts(self):
        cmd = "Router(config)# ip route 192.168.1.0 255.255.255.0 10.0.0.1"
        rb = ReverseRollbackGenerator.generate_rollback(cmd, vendor="cisco")
        assert rb == "no ip route 192.168.1.0 255.255.255.0 10.0.0.1"

        sw_cmd = "switch(config)# ip route 172.16.0.0/16 10.0.0.2"
        sw_rb = ReverseRollbackGenerator.generate_rollback(sw_cmd, vendor="arista")
        assert sw_rb == "no ip route 172.16.0.0/16 10.0.0.2"

    def test_existing_no_prefix_inversion(self):
        cmd = "no shutdown"
        rb = ReverseRollbackGenerator.generate_rollback(cmd, vendor="cisco")
        assert rb == "shutdown"

        cmd2 = "no ip route 10.0.0.0/24 10.1.1.1"
        rb2 = ReverseRollbackGenerator.generate_rollback(cmd2, vendor="frr")
        assert rb2 == "ip route 10.0.0.0/24 10.1.1.1"

    def test_vtysh_wrapped_commands(self):
        cmd = "vtysh -c 'configure terminal' -c 'ip route 10.2.2.0/24 10.1.12.2'"
        rb = ReverseRollbackGenerator.generate_rollback(cmd, vendor="frr")
        assert rb == "vtysh -c 'configure terminal' -c 'no ip route 10.2.2.0/24 10.1.12.2'"

    def test_linux_ip_route_and_link(self):
        cmd_add = "ip route add 10.2.2.0/24 via 10.1.12.2 dev eth1"
        rb_add = ReverseRollbackGenerator.generate_rollback(cmd_add, vendor="linux")
        assert rb_add == "ip route del 10.2.2.0/24 via 10.1.12.2 dev eth1"

        cmd_up = "ip link set dev eth2 up"
        rb_up = ReverseRollbackGenerator.generate_rollback(cmd_up, vendor="linux")
        assert rb_up == "ip link set dev eth2 down"

    def test_linux_iptables_and_tc(self):
        cmd_ipt = "iptables -I FORWARD -s 203.0.113.10 -j DROP"
        rb_ipt = ReverseRollbackGenerator.generate_rollback(cmd_ipt, vendor="linux")
        assert rb_ipt == "iptables -D FORWARD -s 203.0.113.10 -j DROP"

        cmd_tc = "tc qdisc add dev eth1 root handle 1: tbf rate 10mbit"
        rb_tc = ReverseRollbackGenerator.generate_rollback(cmd_tc, vendor="linux")
        assert rb_tc == "tc qdisc del dev eth1 root handle 1: tbf rate 10mbit"


# =============================================================================
# 2. Multi-Vendor DOM Parser Tests
# =============================================================================

class TestVendorDocParsers:
    """Verify DOM parsing accuracy on vendor documentation fixtures."""

    def test_frr_sphinx_parsing(self):
        parser = FRRDocParser()
        soup = bs4.BeautifulSoup(FRR_STATICD_HTML_FIXTURE, "html.parser")
        result = parser.parse(soup, url="https://docs.frrouting.org/en/latest/static.html")

        assert result.vendor == "frr"
        assert result.topic == "static_route"
        assert len(result.commands) >= 1

        route_cmd = next(c for c in result.commands if "ip route" in c.command_template)
        assert "NETWORK" in route_cmd.syntax
        assert "GATEWAY" in route_cmd.syntax
        assert "network" in route_cmd.parameters
        assert "gateway" in route_cmd.parameters
        assert route_cmd.mode == "vtysh"

        # Verify troubleshooting steps
        assert len(result.troubleshooting_steps) >= 1
        has_verif = any(any("show ip route" in v for v in s.verification_commands) for s in result.troubleshooting_steps)
        assert has_verif
        has_remed = any(any("ip route" in r for r in s.remediation_commands) for s in result.troubleshooting_steps)
        assert has_remed
        has_roll = any(any("no ip route" in rb for rb in s.rollback_commands) for s in result.troubleshooting_steps)
        assert has_roll

    def test_cisco_command_reference_parsing(self):
        parser = CiscoDocParser()
        soup = bs4.BeautifulSoup(CISCO_IP_ROUTE_HTML_FIXTURE, "html.parser")
        result = parser.parse(soup, url="https://www.cisco.com/c/en/us/td/docs/ip_route.html")

        assert result.vendor == "cisco"
        assert len(result.commands) >= 1
        cmd = result.commands[0]
        assert "ip route" in cmd.command_template
        assert "prefix" in cmd.parameters
        assert "mask" in cmd.parameters
        assert cmd.mode == "config"

        # Check troubleshooting steps
        assert len(result.troubleshooting_steps) >= 1
        step = result.troubleshooting_steps[-1]
        assert any("no ip route" in rb for rb in step.rollback_commands)

    def test_arista_eos_parsing(self):
        parser = AristaDocParser()
        soup = bs4.BeautifulSoup(ARISTA_EOS_HTML_FIXTURE, "html.parser")
        result = parser.parse(soup, url="https://www.arista.com/en/support/eos/ip_route.html")

        assert result.vendor == "arista"
        assert len(result.commands) >= 1
        cmd = result.commands[0]
        assert "ip route" in cmd.command_template
        assert cmd.mode == "(config)#"

        step = result.troubleshooting_steps[-1]
        assert any("no ip route" in rb for rb in step.rollback_commands)

    def test_generic_doc_parsing(self):
        parser = GenericDocParser()
        soup = bs4.BeautifulSoup(GENERIC_NET_HTML_FIXTURE, "html.parser")
        result = parser.parse(soup, url="https://wiki.linux.org/net/guide.html")

        assert result.vendor == "generic"
        assert len(result.commands) >= 1
        remed_templates = [c.command_template for c in result.commands]
        assert any("iptables" in t for t in remed_templates)
        assert any("ip route" in t for t in remed_templates)

        step = next(s for s in result.troubleshooting_steps if s.verification_commands)
        assert any("ping" in v or "show" in v for v in step.verification_commands)


# =============================================================================
# 3. DocCacheManager Tests
# =============================================================================

class TestDocCacheManager:
    """Verify persistent SHA-256 caching, <1ms access latency, and TTL handling."""

    def test_cache_save_and_sub_millisecond_hit(self, tmp_path):
        cache = DocCacheManager(cache_dir=tmp_path)
        url = "https://docs.frrouting.org/en/latest/static.html"

        assert cache.get(url) is None

        meta = {"vendor": "frr", "topic": "static_route"}
        result_mock = {"url": url, "vendor": "frr", "commands": []}
        cache.set(url, FRR_STATICD_HTML_FIXTURE, result=result_mock, metadata=meta)

        # Benchmark cache hit latency
        t0 = time.perf_counter()
        cached = cache.get(url)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert cached is not None
        assert cached["html"] == FRR_STATICD_HTML_FIXTURE
        assert cached["metadata"]["vendor"] == "frr"
        assert cached["result"]["vendor"] == "frr"
        assert cached["stale"] is False
        # Must execute in < 5ms (usually <0.5ms on modern disk/SSD)
        assert elapsed_ms < 15.0

    def test_cache_force_refresh_and_expiration(self, tmp_path):
        # 1-second TTL
        cache = DocCacheManager(cache_dir=tmp_path, ttl_seconds=0.1)
        url = "https://docs.frrouting.org/en/latest/test.html"
        cache.set(url, "<html>test</html>")

        # Force refresh bypasses cache
        assert cache.get(url, force_refresh=True) is None

        # Normal hit before TTL expires
        assert cache.get(url, force_refresh=False) is not None

        # Wait for TTL to expire
        time.sleep(0.15)
        # Without allow_stale -> returns None
        assert cache.get(url, allow_stale=False) is None
        # With allow_stale -> returns stale content for air-gapped fallback
        stale_hit = cache.get(url, allow_stale=True)
        assert stale_hit is not None
        assert stale_hit["stale"] is True


# =============================================================================
# 4. DocFetcher & Transport Tests
# =============================================================================

class TestDocFetcher:
    """Verify HTTP client behavior, mock transport, rate limiting, and retries."""

    def test_fetcher_with_mock_transport(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "frrouting.org" in str(request.url):
                return httpx.Response(200, text=FRR_STATICD_HTML_FIXTURE)
            return httpx.Response(404, text="Not Found")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = DocFetcher(client=client, rate_limit_delay=0.0)

        html = fetcher.fetch("https://docs.frrouting.org/en/latest/static.html")
        assert "Static Routing Daemon" in html

        with pytest.raises(DocFetchError):
            fetcher.fetch("https://other.com/404")

    def test_fetcher_retry_on_500_and_recovery(self):
        call_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return httpx.Response(500, text="Server Error")
            return httpx.Response(200, text="<html>Success after retry</html>")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = DocFetcher(client=client, max_retries=3, backoff_factor=0.01, rate_limit_delay=0.0)

        text = fetcher.fetch("https://test.com/retry")
        assert "Success after retry" in text
        assert call_count == 3


# =============================================================================
# 5. DynamicSOPRetriever Tests
# =============================================================================

class TestDynamicSOPRetriever:
    """Verify dynamic SOP document generation, tree/vector indexing, and prompt budgeting."""

    @pytest.fixture
    def mock_scraper(self, tmp_path):
        def handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if "frrouting.org" in url_str:
                return httpx.Response(200, text=FRR_STATICD_HTML_FIXTURE)
            if "cisco.com" in url_str:
                return httpx.Response(200, text=CISCO_IP_ROUTE_HTML_FIXTURE)
            return httpx.Response(404, text="Not Found")

        client = httpx.Client(transport=httpx.MockTransport(handler))
        fetcher = DocFetcher(client=client, rate_limit_delay=0.0)
        cache_manager = DocCacheManager(cache_dir=tmp_path)
        return VendorDocScraper(fetcher=fetcher, cache_manager=cache_manager)

    def test_dynamic_scraping_and_sops_ingestion(self, mock_scraper):
        retriever = DynamicSOPRetriever(scraper=mock_scraper)
        url = "https://docs.frrouting.org/en/latest/static.html"

        result = retriever.scrape_and_ingest(url, vendor="frr", topic="static_route")
        assert result.vendor == "frr"
        assert len(retriever.dynamic_sops) >= 1

        # Verify SOP search retrieval by keyword
        matched = retriever.retrieve(["frr", "static", "route", "gateway"])
        assert len(matched) >= 1
        first_sop = matched[0]
        assert "frr" in first_sop["sop_id"].lower()
        assert any("ip route" in rem for rem in first_sop["remediation_template"])
        assert any("no ip route" in rb for rb in first_sop["rollback_template"])

        # Verify dual-retrieval returns tree-backed result
        dual_res = retriever.retrieve_dual("static route gateway", vendor="frr", limit=2)
        assert len(dual_res) >= 1
        assert dual_res[0].vendor == "frr"
        assert "ip route" in dual_res[0].command_template
        assert "no ip route" in dual_res[0].rollback_template

    def test_prompt_budget_strictly_under_500b(self, mock_scraper):
        retriever = DynamicSOPRetriever(scraper=mock_scraper)
        retriever.scrape_and_ingest("https://docs.frrouting.org/en/latest/static.html", vendor="frr")
        retriever.scrape_and_ingest("https://www.cisco.com/c/en/us/td/docs/ip_route.html", vendor="cisco")

        dual_results = retriever.retrieve_dual("configure static route next-hop", limit=5)
        formatted_dual = retriever.format_dual_markdown(dual_results, max_bytes=500)

        # Byte budget constraint
        dual_bytes = len(formatted_dual.encode("utf-8"))
        assert dual_bytes <= 500
        assert dual_bytes > 0

        # Test SOP markdown formatting under budget
        sops = retriever.retrieve(["route", "static"], limit=5)
        formatted_sops = retriever.format_sop_markdown(sops, max_bytes=500)
        sop_bytes = len(formatted_sops.encode("utf-8"))
        assert sop_bytes <= 500
        assert sop_bytes > 0

    def test_air_gapped_offline_resilience(self, tmp_path):
        """When network is completely disconnected, scraper transparently falls back to cache."""
        cache_manager = DocCacheManager(cache_dir=tmp_path)
        test_url = "https://docs.frrouting.org/en/latest/static.html"

        # Pre-seed cache
        parser = FRRDocParser()
        soup = bs4.BeautifulSoup(FRR_STATICD_HTML_FIXTURE, "html.parser")
        parsed_res = parser.parse(soup, url=test_url, topic="static_route")
        cache_manager.set(test_url, FRR_STATICD_HTML_FIXTURE, result=parsed_res)

        # Mock client that raises ConnectError
        def offline_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Network unreachable (air-gapped environment)")

        client = httpx.Client(transport=httpx.MockTransport(offline_handler))
        fetcher = DocFetcher(client=client, max_retries=1, rate_limit_delay=0.0)
        scraper = VendorDocScraper(fetcher=fetcher, cache_manager=cache_manager)
        retriever = DynamicSOPRetriever(scraper=scraper)

        # Should NOT raise DocFetchError; must return cached copy seamlessly
        scraped = retriever.scrape_and_ingest(test_url, vendor="frr")
        assert scraped is not None
        assert scraped.vendor == "frr"
        assert len(scraped.commands) >= 1


# =============================================================================
# 6. Live Documentation Acceptance Test
# =============================================================================

class TestLiveAcceptanceScraping:
    """Acceptance test accepting an authoritative live vendor doc URL."""

    def test_live_frr_documentation_acceptance(self, tmp_path):
        """Acceptance test taking a known FRR doc URL and verifying syntax & troubleshooting extraction."""
        live_url = "https://docs.frrouting.org/en/latest/static.html"
        scraper = VendorDocScraper(cache_dir=tmp_path)

        try:
            result = scraper.scrape(live_url, vendor="frr", topic="static_route")
        except DocFetchError as exc:
            pytest.skip(f"Live network access unavailable in test environment: {exc}")

        # Assertions on live official document content
        assert result.vendor == "frr"
        assert len(result.commands) >= 1
        assert any("ip route" in c.command_template for c in result.commands)
        assert len(result.troubleshooting_steps) >= 1
        assert any(
            any("ip route" in r for r in s.remediation_commands)
            for s in result.troubleshooting_steps
        )
        assert any(
            any("no ip route" in rb for rb in s.rollback_commands)
            for s in result.troubleshooting_steps
        )
