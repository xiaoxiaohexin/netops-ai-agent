"""Vendor Documentation Scraping Engine & Persistent Cache Subsystem.

Provides:
1. Extraction Models: CommandSyntax, TroubleshootingStep, ScrapedDocResult
2. Automated Reverse Rollback Generator: Synthesizes inverse compensation commands
3. DocFetcher: HTTP client with rate-limiting, exponential backoff, realistic User-Agent, and offline awareness
4. DocCacheManager: SHA-256 persistent disk cache with TTL expiration and air-gapped fallback (<1ms hits)
5. Multi-Vendor DOM Parsers:
   - FRRDocParser: Sphinx documentation (<dl class="cli">, <dl class="clicmd">, <dt class="sig">, <dd>, highlight blocks)
   - CiscoDocParser: Command references (<p class="syntax">, parameter tables, command modes, examples)
   - AristaDocParser: EOS references (syntax, (config)# modes, usage guidelines, verification)
   - GenericDocParser: Heuristic CLI syntax and step extractor for arbitrary HTML
6. VendorDocScraper: Orchestrates fetching, caching, vendor detection, and parsing
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

import bs4
from bs4 import BeautifulSoup
import httpx
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


# =============================================================================
# 1. Extraction Models
# =============================================================================

class CommandSyntax(BaseModel):
    """Authoritative CLI command syntax extracted from vendor documentation."""
    model_config = ConfigDict(populate_by_name=True)

    command_template: str = Field(
        ...,
        description="Command template with parameter placeholders or keywords",
    )
    syntax: str = Field(
        default="",
        description="Full formal syntax signature as documented by vendor",
    )
    description: str = Field(
        default="",
        description="Functional description and semantics of the command",
    )
    parameters: Dict[str, str] = Field(
        default_factory=dict,
        description="Parameter names mapped to their descriptions/types",
    )
    mode: str = Field(
        default="config",
        description="Execution mode / prompt context: 'config', 'vtysh', 'exec', 'system-view'",
    )
    vendor: str = Field(
        default="generic",
        description="Vendor identifier: 'frr', 'cisco', 'arista', 'linux', 'generic'",
    )


class TroubleshootingStep(BaseModel):
    """Structured troubleshooting or operational procedure step."""
    model_config = ConfigDict(populate_by_name=True)

    step_number: int = Field(
        default=1,
        description="Sequential index of the troubleshooting step",
    )
    title: str = Field(
        ...,
        description="Short summary of the step (e.g. 'Verify Route Table', 'Apply Static Route')",
    )
    explanation: str = Field(
        default="",
        description="Detailed operational guidance or reasoning for this step",
    )
    verification_commands: List[str] = Field(
        default_factory=list,
        description="Read-only diagnostic inspection commands (e.g. 'show ip route')",
    )
    remediation_commands: List[str] = Field(
        default_factory=list,
        description="Active configuration or remediation CLI commands to apply",
    )
    rollback_commands: List[str] = Field(
        default_factory=list,
        description="Inverse rollback commands to safely undo remediation",
    )


class ScrapedDocResult(BaseModel):
    """Complete structured extraction result from a scraped vendor documentation page."""
    model_config = ConfigDict(populate_by_name=True)

    url: str = Field(
        ...,
        description="Source documentation URL",
    )
    vendor: str = Field(
        ...,
        description="Target vendor identifier ('frr', 'cisco', 'arista', 'linux', 'generic')",
    )
    topic: str = Field(
        default="",
        description="Operational topic or protocol (e.g. 'static_route', 'bgp', 'acl', 'interface')",
    )
    title: str = Field(
        default="",
        description="Page or document title",
    )
    commands: List[CommandSyntax] = Field(
        default_factory=list,
        description="Extracted command syntax items",
    )
    troubleshooting_steps: List[TroubleshootingStep] = Field(
        default_factory=list,
        description="Extracted or synthesized operational troubleshooting steps",
    )
    raw_text_summary: str = Field(
        default="",
        description="Concise textual summary of documentation content",
    )


# =============================================================================
# 2. Automated Reverse Rollback Generator
# =============================================================================

class ReverseRollbackGenerator:
    """Synthesizes inverse rollback commands to safely undo configuration remediations."""

    # Explicit keyword inversion map for Linux / unix network utilities
    _LINUX_VERB_INVERSIONS: List[Tuple[re.Pattern, str]] = [
        (re.compile(r"\bip\s+route\s+add\b", re.IGNORECASE), "ip route del"),
        (re.compile(r"\bip\s+route\s+replace\b", re.IGNORECASE), "ip route del"),
        (re.compile(r"\bip\s+route\s+append\b", re.IGNORECASE), "ip route del"),
        (re.compile(r"\bip\s+route\s+del\b", re.IGNORECASE), "ip route add"),
        (re.compile(r"\bip\s+link\s+set\s+(?:dev\s+)?([^\s]+)\s+up\b", re.IGNORECASE), r"ip link set dev \1 down"),
        (re.compile(r"\bip\s+link\s+set\s+(?:dev\s+)?([^\s]+)\s+down\b", re.IGNORECASE), r"ip link set dev \1 up"),
        (re.compile(r"\biptables\s+-I\b", re.IGNORECASE), "iptables -D"),
        (re.compile(r"\biptables\s+-A\b", re.IGNORECASE), "iptables -D"),
        (re.compile(r"\biptables\s+-D\b", re.IGNORECASE), "iptables -I"),
        (re.compile(r"\barptables\s+-I\b", re.IGNORECASE), "arptables -D"),
        (re.compile(r"\barptables\s+-A\b", re.IGNORECASE), "arptables -D"),
        (re.compile(r"\btc\s+qdisc\s+add\b", re.IGNORECASE), "tc qdisc del"),
        (re.compile(r"\btc\s+qdisc\s+replace\b", re.IGNORECASE), "tc qdisc del"),
        (re.compile(r"\btc\s+filter\s+add\b", re.IGNORECASE), "tc filter del"),
        (re.compile(r"\btc\s+filter\s+replace\b", re.IGNORECASE), "tc filter del"),
    ]

    # CLI prompt prefixes to strip
    _PROMPT_PATTERNS = [
        re.compile(r"^[A-Za-z0-9_\-\.\(\)]+[#>$]\s*"),
        re.compile(r"^\$\s*"),
        re.compile(r"^#\s*"),
    ]

    @classmethod
    def clean_command(cls, command: str) -> str:
        """Strip CLI router prompts (e.g. 'Router(config)# ', 'router> ', '$ ')."""
        cmd = command.strip()
        for pat in cls._PROMPT_PATTERNS:
            cmd = pat.sub("", cmd).strip()
        return cmd

    @classmethod
    def generate_rollback(cls, command: str, vendor: str = "generic") -> str:
        """Generate inverse rollback command for a given remediation command.

        Args:
            command: CLI configuration command.
            vendor: Target vendor ('frr', 'cisco', 'arista', 'linux', 'generic').

        Returns:
            Inverse CLI rollback command string.
        """
        clean = cls.clean_command(command)
        if not clean:
            return ""

        vendor_lower = (vendor or "generic").lower()

        # Handle vtysh wrapped commands: vtysh -c '...' or vtysh -c "..."
        vtysh_match = re.match(
            r"^(vtysh\s+(?:-c\s+['\"][^'\"]*['\"]\s+)*-c\s+)(['\"])(.*)\2$",
            clean,
            re.IGNORECASE | re.DOTALL,
        )
        if vtysh_match:
            prefix, quote, inner_cmd = vtysh_match.group(1), vtysh_match.group(2), vtysh_match.group(3)
            inner_rollback = cls.generate_rollback(inner_cmd, vendor="frr")
            return f"{prefix}{quote}{inner_rollback}{quote}"

        # If already starts with 'no ', remove 'no '
        if re.match(r"^no\s+", clean, re.IGNORECASE):
            return re.sub(r"^no\s+", "", clean, flags=re.IGNORECASE).strip()

        # Check Linux / netfilter verb inversions
        for pattern, replacement in cls._LINUX_VERB_INVERSIONS:
            if pattern.search(clean):
                return pattern.sub(replacement, clean)

        # Handle sysctl adjustments
        sysctl_match = re.match(r"^sysctl\s+-w\s+([A-Za-z0-9_\.]+)=.*$", clean, re.IGNORECASE)
        if sysctl_match:
            key = sysctl_match.group(1)
            return f"# Restore original sysctl value for {key}"

        # Cisco, FRRouting, and Arista EOS standard negation: prepend 'no '
        if vendor_lower in ("frr", "cisco", "arista"):
            return f"no {clean}"

        # Generic commands: check for standard opposite verbs
        if clean.startswith("enable "):
            return "disable " + clean[7:]
        if clean.startswith("add "):
            return "del " + clean[4:]
        if clean.startswith("permit "):
            return "deny " + clean[7:]
        if clean.startswith("start "):
            return "stop " + clean[6:]

        # Fallback to 'no <command>'
        return f"no {clean}"


# =============================================================================
# 3. DocFetcher: HTTP Transport & Network Resilience
# =============================================================================

class DocFetchError(Exception):
    """Raised when document fetching fails fatally across retries."""
    pass


class DocFetcher:
    """HTTP document fetcher with rate limiting, timeouts, and exponential backoff."""

    def __init__(
        self,
        client: Optional[httpx.Client] = None,
        timeout: float = 10.0,
        user_agent: str = "Mozilla/5.0 NetOpsAgent/1.0",
        rate_limit_delay: float = 0.5,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
    ) -> None:
        self.timeout = timeout
        self.user_agent = user_agent
        self.rate_limit_delay = rate_limit_delay
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._last_request_time: Dict[str, float] = {}

        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                timeout=httpx.Timeout(self.timeout),
                headers={
                    "User-Agent": self.user_agent,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
                follow_redirects=True,
            )
            self._owns_client = True

    def _enforce_rate_limit(self, url: str) -> None:
        """Enforce polite minimum delay between requests to the same hostname."""
        if self.rate_limit_delay <= 0:
            return
        domain = urlparse(url).netloc or "default"
        now = time.time()
        last = self._last_request_time.get(domain, 0.0)
        elapsed = now - last
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time[domain] = time.time()

    def fetch(self, url: str) -> str:
        """Fetch raw HTML text for a target URL with retries on 429/5xx or transport errors.

        Args:
            url: Target HTTP/HTTPS URL.

        Returns:
            HTML text response.

        Raises:
            DocFetchError: If request fails after maximum retry attempts.
        """
        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries):
            self._enforce_rate_limit(url)
            try:
                response = self._client.get(url)
                if response.status_code == 200:
                    return response.text
                elif response.status_code in (429, 500, 502, 503, 504):
                    logger.warning(
                        "HTTP %d from %s (attempt %d/%d)",
                        response.status_code,
                        url,
                        attempt + 1,
                        self.max_retries,
                    )
                    last_error = DocFetchError(f"HTTP {response.status_code}: {response.text[:200]}")
                else:
                    raise DocFetchError(f"HTTP {response.status_code} fetching {url}")
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.NetworkError) as exc:
                logger.warning(
                    "Network error %s fetching %s (attempt %d/%d)",
                    exc,
                    url,
                    attempt + 1,
                    self.max_retries,
                )
                last_error = exc
            except DocFetchError:
                raise
            except Exception as exc:
                last_error = exc

            # Exponential backoff before next attempt
            if attempt < self.max_retries - 1:
                delay = self.backoff_factor * (2 ** attempt)
                time.sleep(delay)

        raise DocFetchError(f"Failed to fetch {url} after {self.max_retries} attempts: {last_error}")

    def close(self) -> None:
        """Close underlying HTTP client if owned."""
        if self._owns_client and self._client:
            self._client.close()

    def __enter__(self) -> DocFetcher:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# =============================================================================
# 4. DocCacheManager: SHA-256 Persistent Local Disk Cache
# =============================================================================

class DocCacheManager:
    """SHA-256 keyed persistent disk cache storing raw HTML and parsed JSON metadata.

    Features:
    - Default TTL 24h (86,400s)
    - Sub-millisecond lookup (<1ms)
    - Air-gapped fallback: serves stale cache when network fails
    """

    def __init__(
        self,
        cache_dir: Optional[Union[str, Path]] = None,
        ttl_seconds: float = 86400.0,
    ) -> None:
        if cache_dir is not None:
            self.cache_dir = Path(cache_dir).resolve()
        else:
            # Default to data/scraped_cache relative to project root or .cache/vendor_docs
            self.cache_dir = Path("data/scraped_cache").resolve()

        self.ttl_seconds = ttl_seconds
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning("Failed to create cache directory %s: %s", self.cache_dir, exc)

    @classmethod
    def compute_cache_key(cls, url: str) -> str:
        """Compute deterministic SHA-256 hash from normalized URL."""
        norm_url = url.strip().lower()
        return hashlib.sha256(norm_url.encode("utf-8")).hexdigest()

    def _get_paths(self, url: str) -> Tuple[Path, Path]:
        key = self.compute_cache_key(url)
        html_path = self.cache_dir / f"{key}.html"
        json_path = self.cache_dir / f"{key}.json"
        return html_path, json_path

    def get(
        self,
        url: str,
        force_refresh: bool = False,
        allow_stale: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve cached HTML and parsed metadata for a URL.

        Args:
            url: Target URL.
            force_refresh: If True, bypass cache.
            allow_stale: If True, return expired cache (useful for air-gapped fallback).

        Returns:
            Dictionary with keys 'html', 'metadata', 'result', 'timestamp', 'stale' or None.
        """
        key = self.compute_cache_key(url)
        if force_refresh:
            self._memory_cache.pop(key, None)
            return None

        # Check L1 in-memory cache first for sub-millisecond response (<0.05ms)
        if key in self._memory_cache:
            entry = self._memory_cache[key]
            now = time.time()
            age = now - entry["timestamp"]
            is_stale = age > self.ttl_seconds
            if not is_stale or allow_stale:
                return {
                    "html": entry["html"],
                    "metadata": dict(entry.get("metadata", {})),
                    "result": entry.get("result"),
                    "timestamp": entry["timestamp"],
                    "age_seconds": age,
                    "stale": is_stale,
                }

        # Check L2 disk cache
        html_path, json_path = self._get_paths(url)
        if not html_path.exists():
            return None

        try:
            now = time.time()
            mtime = html_path.stat().st_mtime
            age = now - mtime
            is_stale = age > self.ttl_seconds

            if is_stale and not allow_stale:
                return None

            html_content = html_path.read_text(encoding="utf-8", errors="replace")

            metadata: Dict[str, Any] = {}
            result_data: Optional[Dict[str, Any]] = None
            if json_path.exists():
                json_content = json_path.read_text(encoding="utf-8", errors="replace")
                parsed_json = json.loads(json_content)
                metadata = parsed_json.get("metadata", {})
                result_data = parsed_json.get("result")

            entry = {
                "html": html_content,
                "metadata": metadata,
                "result": result_data,
                "timestamp": mtime,
                "age_seconds": age,
                "stale": is_stale,
            }
            self._memory_cache[key] = entry
            return entry
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Error reading cache for %s: %s", url, exc)
            return None

    def set(
        self,
        url: str,
        html: str,
        result: Optional[Union[ScrapedDocResult, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Store HTML content and parsed result to disk.

        Args:
            url: Target URL.
            html: Raw HTML text.
            result: ScrapedDocResult instance or dictionary.
            metadata: Additional metadata dictionary.
        """
        key = self.compute_cache_key(url)
        now_ts = time.time()
        res_dict = result.model_dump() if isinstance(result, ScrapedDocResult) else result

        # Update L1 in-memory cache
        self._memory_cache[key] = {
            "html": html,
            "metadata": metadata or {},
            "result": res_dict,
            "timestamp": now_ts,
            "age_seconds": 0.0,
            "stale": False,
        }

        # Update L2 disk cache
        html_path, json_path = self._get_paths(url)
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            html_path.write_text(html, encoding="utf-8", errors="replace")

            meta_payload: Dict[str, Any] = {
                "url": url,
                "timestamp": now_ts,
                "metadata": metadata or {},
            }
            if res_dict is not None:
                meta_payload["result"] = res_dict

            json_path.write_text(json.dumps(meta_payload, indent=2), encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Failed to write cache for %s: %s", url, exc)


# =============================================================================
# 5. Specialized Multi-Vendor DOM Parsers
# =============================================================================

class BaseVendorParser:
    """Abstract base class for vendor-specific HTML DOM parsers."""

    def parse(self, soup: BeautifulSoup, url: str, topic: Optional[str] = None) -> ScrapedDocResult:
        raise NotImplementedError


class FRRDocParser(BaseVendorParser):
    """Specialized DOM parser for FRRouting Sphinx documentation (docs.frrouting.org).

    Parses:
    - `<dl class="cli">`, `<dl class="clicmd">`, `<dl class="describe">`, `<dl class="std clicmd">`
    - `<dt class="sig">`, `<dt class="sig-object">`
    - Parameter definitions in `<dd>` (e.g. `<ul class="simple">`, `<dl class="field-list">`)
    - Code snippets in `<div class="highlight-frr">`, `<div class="highlight">`, `<pre>`
    """

    def parse(self, soup: BeautifulSoup, url: str, topic: Optional[str] = None) -> ScrapedDocResult:
        page_title = ""
        title_tag = soup.find("title") or soup.find("h1")
        if title_tag:
            page_title = title_tag.get_text().strip()
            # Clean up ' — FRR' suffix if present
            page_title = re.sub(r"\s*—\s*FRR.*$", "", page_title)

        inferred_topic = topic or self._infer_topic(url, page_title)
        commands: List[CommandSyntax] = []
        troubleshooting_steps: List[TroubleshootingStep] = []

        # Find all CLI definition lists
        cli_dls = soup.find_all(
            "dl",
            class_=lambda c: c and any(cls_name in str(c) for cls_name in ("cli", "clicmd", "describe")),
        )

        # Fallback if no class found: inspect all dls with dt.sig
        if not cli_dls:
            for dl in soup.find_all("dl"):
                if dl.find("dt", class_=lambda c: c and "sig" in str(c)):
                    cli_dls.append(dl)

        for dl in cli_dls:
            dt = dl.find("dt")
            if not dt:
                continue

            # Strip Sphinx permalinks (headerlink, \uf0c1)
            for hl in dt.find_all("a", class_="headerlink"):
                hl.decompose()

            raw_sig = dt.get_text(separator=" ", strip=True)
            raw_sig = raw_sig.replace("\uf0c1", "").strip()
            if not raw_sig:
                continue

            # Extract command name and template
            cmd_name_tag = dt.find("code", class_=lambda c: c and "descname" in str(c))
            cmd_name = cmd_name_tag.get_text().strip() if cmd_name_tag else raw_sig.split()[0] if raw_sig.split() else ""

            # Extract parameter dictionary and description from <dd>
            dd = dl.find("dd")
            params: Dict[str, str] = {}
            desc_text = ""

            if dd:
                # Look for parameter lists in <li><strong>PARAM</strong>: desc</li>
                for li in dd.find_all("li"):
                    strong = li.find("strong")
                    if strong:
                        p_name = strong.get_text().strip().lower()
                        p_desc = li.get_text().replace(strong.get_text(), "").strip(" :-\t")
                        params[p_name] = p_desc

                # Also extract field-list parameters if present
                for field in dd.find_all("tr", class_="field"):
                    th = field.find("th")
                    td = field.find("td")
                    if th and td:
                        params[th.get_text().strip().lower()] = td.get_text().strip()

                desc_paras = [p.get_text().strip() for p in dd.find_all("p") if p.get_text().strip()]
                desc_text = " ".join(desc_paras)

            # If params dict is still empty, extract uppercase or bracketed tokens from signature
            if not params:
                param_tokens = re.findall(r"\b([A-Z]{2,}|<[^>]+>)\b", raw_sig)
                for pt in param_tokens:
                    clean_pt = pt.strip("<>").lower()
                    params[clean_pt] = f"Parameter {pt} for {cmd_name}"

            commands.append(
                CommandSyntax(
                    command_template=raw_sig,
                    syntax=raw_sig,
                    description=desc_text or f"FRR command {raw_sig}",
                    parameters=params,
                    mode="vtysh",
                    vendor="frr",
                )
            )

        # Extract code examples from highlight blocks
        code_blocks: List[str] = []
        for hl in soup.find_all(["div", "pre"], class_=lambda c: c and any(k in str(c) for k in ("highlight", "code"))):
            block_text = hl.get_text().strip()
            if block_text and block_text not in code_blocks:
                code_blocks.append(block_text)

        # Distinguish verification vs configuration commands from highlight blocks and signatures
        verification_cmds: List[str] = []
        remediation_cmds: List[str] = []

        for cb in code_blocks:
            lines = [l.strip() for l in cb.split("\n") if l.strip()]
            for line in lines:
                clean_l = ReverseRollbackGenerator.clean_command(line)
                if not clean_l or clean_l.startswith("#"):
                    continue
                if clean_l.startswith("show ") or "show ip " in clean_l:
                    if clean_l not in verification_cmds:
                        verification_cmds.append(clean_l)
                elif any(clean_l.startswith(k) for k in ("ip route", "ipv6 route", "router bgp", "neighbor ", "interface ")):
                    if clean_l not in remediation_cmds:
                        remediation_cmds.append(clean_l)

        # Also inspect commands list for verification & remediation
        for cmd in commands:
            sig = cmd.syntax
            if sig.startswith("show ") or "show ip " in sig:
                if sig not in verification_cmds:
                    verification_cmds.append(sig)
            elif not sig.startswith("show "):
                if sig not in remediation_cmds:
                    remediation_cmds.append(sig)

        # Formulate structured TroubleshootingSteps
        step_idx = 1
        if verification_cmds:
            troubleshooting_steps.append(
                TroubleshootingStep(
                    step_number=step_idx,
                    title="Verify Active FRR Routing State",
                    explanation="Inspect active routing and protocol state via vtysh show commands.",
                    verification_commands=verification_cmds[:5],
                    remediation_commands=[],
                    rollback_commands=[],
                )
            )
            step_idx += 1

        if remediation_cmds:
            for rem in remediation_cmds[:5]:
                rb = ReverseRollbackGenerator.generate_rollback(rem, vendor="frr")
                troubleshooting_steps.append(
                    TroubleshootingStep(
                        step_number=step_idx,
                        title=f"Apply FRR Configuration: {rem.split()[0:3]}",
                        explanation=f"Configure routing policy or daemon setting via vtysh.",
                        verification_commands=[f"show {rem.split()[0]}"] if rem.split() else ["show ip route"],
                        remediation_commands=[rem],
                        rollback_commands=[rb] if rb else [],
                    )
                )
                step_idx += 1

        summary = f"FRR documentation for {page_title or inferred_topic}. Extracted {len(commands)} commands and {len(troubleshooting_steps)} troubleshooting steps."

        return ScrapedDocResult(
            url=url,
            vendor="frr",
            topic=inferred_topic,
            title=page_title or "FRR Documentation",
            commands=commands,
            troubleshooting_steps=troubleshooting_steps,
            raw_text_summary=summary,
        )

    @staticmethod
    def _infer_topic(url: str, title: str) -> str:
        text = f"{url} {title}".lower()
        if "static" in text:
            return "static_route"
        if "bgp" in text:
            return "bgp"
        if "ospf" in text:
            return "ospf"
        if "zebra" in text:
            return "interface_routing"
        if "isis" in text:
            return "isis"
        return "routing"


class CiscoDocParser(BaseVendorParser):
    """Specialized DOM parser for Cisco Systems Command References (cisco.com).

    Parses:
    - Command headings (`<h2>`, `<h3>`, `<p class="title">`)
    - Syntax blocks (`<p class="syntax">`, `<code>`)
    - Parameter tables (`<table>` with Keyword/Argument and Description)
    - Command modes (`Command Modes` section)
    - Examples and verification commands (`show ...`)
    """

    def parse(self, soup: BeautifulSoup, url: str, topic: Optional[str] = None) -> ScrapedDocResult:
        page_title = ""
        title_tag = soup.find("title") or soup.find("h1") or soup.find("h2")
        if title_tag:
            page_title = title_tag.get_text().strip()

        commands: List[CommandSyntax] = []
        troubleshooting_steps: List[TroubleshootingStep] = []

        # Find syntax blocks
        syntax_tags = soup.find_all(
            ["p", "div", "code", "pre"],
            class_=lambda c: c and any(cls_name in str(c) for cls_name in ("syntax", "Syntax", "cmd_syntax")),
        )
        if not syntax_tags:
            # Fallback: search for headings containing 'Syntax' and get next element
            for heading in soup.find_all(["h2", "h3", "h4", "p"]):
                if "syntax" in heading.get_text().lower():
                    next_el = heading.find_next(["p", "code", "pre", "div"])
                    if next_el and next_el not in syntax_tags:
                        syntax_tags.append(next_el)

        # Detect command mode
        command_mode = "config"
        for mode_heading in soup.find_all(["h2", "h3", "h4", "p"]):
            if "command mode" in mode_heading.get_text().lower():
                next_p = mode_heading.find_next("p")
                if next_p:
                    mode_text = next_p.get_text().lower()
                    if "global" in mode_text:
                        command_mode = "config"
                    elif "interface" in mode_text:
                        command_mode = "config-if"
                    elif "router" in mode_text:
                        command_mode = "config-router"
                    elif "exec" in mode_text or "privileged" in mode_text:
                        command_mode = "exec"

        # Parse parameter tables
        parameters: Dict[str, str] = {}
        for table in soup.find_all("table"):
            headers = [th.get_text().lower() for th in table.find_all(["th", "td"])]
            if any("keyword" in h or "argument" in h or "parameter" in h for h in headers):
                for row in table.find_all("tr"):
                    cols = row.find_all("td")
                    if len(cols) >= 2:
                        param_name = cols[0].get_text().strip().lower()
                        param_desc = cols[1].get_text().strip()
                        if param_name and param_desc:
                            parameters[param_name] = param_desc

        for stag in syntax_tags:
            syntax_str = stag.get_text(separator=" ", strip=True)
            if not syntax_str:
                continue

            commands.append(
                CommandSyntax(
                    command_template=syntax_str,
                    syntax=syntax_str,
                    description=page_title or f"Cisco command {syntax_str}",
                    parameters=parameters,
                    mode=command_mode,
                    vendor="cisco",
                )
            )

        # Extract examples
        example_cmds: List[str] = []
        for pre in soup.find_all(["pre", "code"]):
            text = pre.get_text().strip()
            for line in text.split("\n"):
                clean = ReverseRollbackGenerator.clean_command(line)
                if clean and not clean.startswith("#") and clean not in example_cmds:
                    example_cmds.append(clean)

        verif_cmds = [c for c in example_cmds if c.startswith("show ")]
        remed_cmds = [c for c in example_cmds if not c.startswith("show ") and any(c.startswith(k) for k in ("ip route", "ip access-list", "router bgp", "interface", "ip address"))]

        # Build troubleshooting steps
        step_idx = 1
        if verif_cmds:
            troubleshooting_steps.append(
                TroubleshootingStep(
                    step_number=step_idx,
                    title="Verify Cisco Device Operational Status",
                    explanation="Run privileged exec verification commands to check interface and routing table.",
                    verification_commands=verif_cmds[:5],
                    remediation_commands=[],
                    rollback_commands=[],
                )
            )
            step_idx += 1

        if remed_cmds or commands:
            target_remed = remed_cmds[:5] or [commands[0].command_template] if commands else []
            for rem in target_remed:
                rb = ReverseRollbackGenerator.generate_rollback(rem, vendor="cisco")
                troubleshooting_steps.append(
                    TroubleshootingStep(
                        step_number=step_idx,
                        title=f"Deploy Cisco Configuration: {rem.split()[0:3]}",
                        explanation=f"Execute configuration command in {command_mode} mode.",
                        verification_commands=verif_cmds[:2] if verif_cmds else ["show running-config"],
                        remediation_commands=[rem],
                        rollback_commands=[rb] if rb else [],
                    )
                )
                step_idx += 1

        inferred_topic = topic or ("routing" if "route" in url.lower() or "route" in page_title.lower() else "acl_security" if "access" in url.lower() else "general")
        summary = f"Cisco documentation for {page_title}. Extracted {len(commands)} commands and {len(troubleshooting_steps)} troubleshooting steps."

        return ScrapedDocResult(
            url=url,
            vendor="cisco",
            topic=inferred_topic,
            title=page_title or "Cisco Command Reference",
            commands=commands,
            troubleshooting_steps=troubleshooting_steps,
            raw_text_summary=summary,
        )


class AristaDocParser(BaseVendorParser):
    """Specialized DOM parser for Arista Networks EOS Command References (arista.com).

    Parses:
    - Command Syntax sections with CIDR notation
    - Command Mode (e.g. `(config)#`)
    - Usage guidelines, examples, and rollback commands (`no <command>`)
    """

    def parse(self, soup: BeautifulSoup, url: str, topic: Optional[str] = None) -> ScrapedDocResult:
        page_title = ""
        title_tag = soup.find("title") or soup.find("h1") or soup.find("h2")
        if title_tag:
            page_title = title_tag.get_text().strip()

        commands: List[CommandSyntax] = []
        troubleshooting_steps: List[TroubleshootingStep] = []
        parameters: Dict[str, str] = {}

        # Look for Syntax section
        syntax_blocks: List[str] = []
        for heading in soup.find_all(["h2", "h3", "h4", "p", "strong"]):
            if "command syntax" in heading.get_text().lower():
                next_el = heading.find_next(["code", "pre", "p"])
                if next_el:
                    syntax_blocks.append(next_el.get_text().strip())

        # Also find all code tags
        if not syntax_blocks:
            for code in soup.find_all("code"):
                txt = code.get_text().strip()
                if any(txt.startswith(k) for k in ("ip route", "router bgp", "interface", "ip access-list")):
                    syntax_blocks.append(txt)

        # Detect command mode
        command_mode = "(config)#"
        for mode_h in soup.find_all(["h2", "h3", "h4", "p"]):
            if "command mode" in mode_h.get_text().lower():
                next_p = mode_h.find_next(["p", "code"])
                if next_p:
                    command_mode = next_p.get_text().strip()

        for s in syntax_blocks:
            # Extract parameters in angle brackets or brackets
            param_matches = re.findall(r"[<\[]([a-zA-Z0-9_\-]+)[>\]]", s)
            for pm in param_matches:
                parameters[pm.lower()] = f"Arista parameter {pm}"

            commands.append(
                CommandSyntax(
                    command_template=s,
                    syntax=s,
                    description=page_title or f"Arista EOS command {s}",
                    parameters=parameters,
                    mode=command_mode,
                    vendor="arista",
                )
            )

        # Extract examples
        examples: List[str] = []
        for pre in soup.find_all(["pre", "code"]):
            for line in pre.get_text().split("\n"):
                clean = ReverseRollbackGenerator.clean_command(line)
                if clean and clean not in examples:
                    examples.append(clean)

        verif = [e for e in examples if e.startswith("show ")]
        remed = [e for e in examples if not e.startswith("show ") and any(e.startswith(k) for k in ("ip route", "router bgp", "ip access-list", "interface"))]

        step_idx = 1
        if verif:
            troubleshooting_steps.append(
                TroubleshootingStep(
                    step_number=step_idx,
                    title="Inspect Arista EOS Routing and Interface State",
                    explanation="Verify running configuration and RIB state via show commands.",
                    verification_commands=verif[:5],
                    remediation_commands=[],
                    rollback_commands=[],
                )
            )
            step_idx += 1

        if remed or commands:
            target_remed = remed[:5] or [commands[0].command_template] if commands else []
            for r in target_remed:
                rb = ReverseRollbackGenerator.generate_rollback(r, vendor="arista")
                troubleshooting_steps.append(
                    TroubleshootingStep(
                        step_number=step_idx,
                        title=f"Execute Arista EOS Remediation: {r.split()[0:3]}",
                        explanation=f"Apply configuration in mode {command_mode}.",
                        verification_commands=verif[:2] if verif else ["show ip route"],
                        remediation_commands=[r],
                        rollback_commands=[rb] if rb else [],
                    )
                )
                step_idx += 1

        inferred_topic = topic or "routing"
        summary = f"Arista EOS documentation for {page_title}. Extracted {len(commands)} commands and {len(troubleshooting_steps)} troubleshooting steps."

        return ScrapedDocResult(
            url=url,
            vendor="arista",
            topic=inferred_topic,
            title=page_title or "Arista EOS Documentation",
            commands=commands,
            troubleshooting_steps=troubleshooting_steps,
            raw_text_summary=summary,
        )


class GenericDocParser(BaseVendorParser):
    """Heuristic fallback DOM parser for arbitrary network documentation."""

    _KNOWN_CLI_VERBS = (
        "ip route",
        "ip link",
        "ip addr",
        "iptables",
        "arptables",
        "tc qdisc",
        "tc filter",
        "sysctl",
        "vtysh",
        "router bgp",
        "router ospf",
        "show ip",
        "show running-config",
        "show interfaces",
        "ping",
    )

    def parse(self, soup: BeautifulSoup, url: str, topic: Optional[str] = None) -> ScrapedDocResult:
        page_title = ""
        title_tag = soup.find("title") or soup.find("h1")
        if title_tag:
            page_title = title_tag.get_text().strip()

        commands: List[CommandSyntax] = []
        troubleshooting_steps: List[TroubleshootingStep] = []
        extracted_lines: List[str] = []

        # Scrape pre, code, blockquote tags
        for tag in soup.find_all(["pre", "code", "blockquote", "p"]):
            text = tag.get_text().strip()
            for line in text.split("\n"):
                clean = ReverseRollbackGenerator.clean_command(line)
                if not clean or clean.startswith("#"):
                    continue
                if any(clean.lower().startswith(v) for v in self._KNOWN_CLI_VERBS):
                    if clean not in extracted_lines:
                        extracted_lines.append(clean)

        verif_cmds: List[str] = []
        remed_cmds: List[str] = []

        for line in extracted_lines:
            if line.startswith("show ") or line.startswith("ping ") or "show ip" in line:
                verif_cmds.append(line)
            else:
                remed_cmds.append(line)
                rb = ReverseRollbackGenerator.generate_rollback(line, vendor="generic")
                commands.append(
                    CommandSyntax(
                        command_template=line,
                        syntax=line,
                        description=f"Operational command: {line}",
                        parameters={},
                        mode="cli",
                        vendor="generic",
                    )
                )

        step_idx = 1
        if verif_cmds:
            troubleshooting_steps.append(
                TroubleshootingStep(
                    step_number=step_idx,
                    title="Execute Diagnostic Verifications",
                    explanation="Verify system baseline and reachability.",
                    verification_commands=verif_cmds[:5],
                    remediation_commands=[],
                    rollback_commands=[],
                )
            )
            step_idx += 1

        if remed_cmds:
            for rem in remed_cmds[:5]:
                rb = ReverseRollbackGenerator.generate_rollback(rem, vendor="generic")
                troubleshooting_steps.append(
                    TroubleshootingStep(
                        step_number=step_idx,
                        title=f"Execute Remediation: {rem.split()[0:3]}",
                        explanation="Apply network configuration change.",
                        verification_commands=verif_cmds[:2] if verif_cmds else [],
                        remediation_commands=[rem],
                        rollback_commands=[rb] if rb else [],
                    )
                )
                step_idx += 1

        inferred_topic = topic or "network_operations"
        summary = f"Generic network documentation for {page_title}. Extracted {len(commands)} commands."

        return ScrapedDocResult(
            url=url,
            vendor="generic",
            topic=inferred_topic,
            title=page_title or "Network Documentation",
            commands=commands,
            troubleshooting_steps=troubleshooting_steps,
            raw_text_summary=summary,
        )


# =============================================================================
# 6. VendorDocScraper: Orchestrator
# =============================================================================

class VendorDocScraper:
    """Orchestrates web fetching, disk caching, vendor detection, and DOM parsing."""

    def __init__(
        self,
        fetcher: Optional[DocFetcher] = None,
        cache_manager: Optional[DocCacheManager] = None,
        cache_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self.fetcher = fetcher or DocFetcher()
        self.cache_manager = cache_manager or DocCacheManager(cache_dir=cache_dir)
        self._parsers: Dict[str, BaseVendorParser] = {
            "frr": FRRDocParser(),
            "cisco": CiscoDocParser(),
            "arista": AristaDocParser(),
            "generic": GenericDocParser(),
        }

    @staticmethod
    def detect_vendor(url: str, hint: Optional[str] = None) -> str:
        """Detect vendor from URL or hint string."""
        if hint:
            hint_lower = hint.strip().lower()
            if any(k in hint_lower for k in ("frr", "frrouting", "zebra", "vtysh")):
                return "frr"
            if "cisco" in hint_lower or "ios" in hint_lower:
                return "cisco"
            if "arista" in hint_lower or "eos" in hint_lower:
                return "arista"
            if "linux" in hint_lower or "iptables" in hint_lower:
                return "linux"

        url_lower = url.lower()
        if "frrouting.org" in url_lower or "frr" in url_lower:
            return "frr"
        if "cisco.com" in url_lower:
            return "cisco"
        if "arista.com" in url_lower:
            return "arista"

        return "generic"

    def get_parser(self, vendor: str) -> BaseVendorParser:
        """Get specialized parser instance for vendor."""
        v = (vendor or "generic").lower()
        return self._parsers.get(v, self._parsers["generic"])

    def parse_html(
        self,
        html: str,
        url: str = "",
        vendor: Optional[str] = None,
        topic: Optional[str] = None,
    ) -> ScrapedDocResult:
        """Parse raw HTML into ScrapedDocResult using vendor-specific parser."""
        detected_vendor = self.detect_vendor(url, hint=vendor)
        parser = self.get_parser(detected_vendor)
        soup = BeautifulSoup(html, "html.parser")
        return parser.parse(soup, url=url, topic=topic)

    def extract_command_syntaxes(self, soup: BeautifulSoup, vendor: str) -> List[CommandSyntax]:
        """Convenience method: extract command syntaxes for soup and vendor."""
        parser = self.get_parser(vendor)
        result = parser.parse(soup, url="", topic=None)
        return result.commands

    def extract_troubleshooting_steps(self, soup: BeautifulSoup, vendor: str) -> List[TroubleshootingStep]:
        """Convenience method: extract troubleshooting steps for soup and vendor."""
        parser = self.get_parser(vendor)
        result = parser.parse(soup, url="", topic=None)
        return result.troubleshooting_steps

    def scrape(
        self,
        url: str,
        vendor: Optional[str] = None,
        topic: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ScrapedDocResult:
        """Scrape documentation URL with SHA-256 caching and offline fallback.

        Execution flow:
        1. Check cache (unless force_refresh is True). On cache hit, return in <1ms.
        2. Attempt live HTTP fetch via DocFetcher.
        3. If live fetch fails (e.g. air-gapped / offline), gracefully fall back to stale cache.
        4. Parse HTML and write updated result to cache.
        """
        # 1. Fast-path cache lookup
        cached = self.cache_manager.get(url, force_refresh=force_refresh, allow_stale=False)
        if cached:
            if cached.get("result"):
                return ScrapedDocResult.model_validate(cached["result"])
            # Re-parse cached HTML if result wasn't stored
            return self.parse_html(cached["html"], url=url, vendor=vendor, topic=topic)

        # 2. Attempt live fetch
        html_text = ""
        fetch_succeeded = False
        try:
            html_text = self.fetcher.fetch(url)
            fetch_succeeded = True
        except Exception as exc:
            logger.warning("Live fetch failed for %s (%s). Attempting stale cache fallback.", url, exc)
            # 3. Air-gapped fallback to stale cache
            stale_cached = self.cache_manager.get(url, force_refresh=False, allow_stale=True)
            if stale_cached:
                logger.info("Air-gapped fallback hit for %s (stale cache)", url)
                if stale_cached.get("result"):
                    return ScrapedDocResult.model_validate(stale_cached["result"])
                return self.parse_html(stale_cached["html"], url=url, vendor=vendor, topic=topic)
            raise DocFetchError(f"Network unavailable and no local cache exists for {url}: {exc}") from exc

        # 4. Parse freshly fetched HTML
        result = self.parse_html(html_text, url=url, vendor=vendor, topic=topic)

        # 5. Persist to cache
        if fetch_succeeded:
            self.cache_manager.set(
                url=url,
                html=html_text,
                result=result,
                metadata={"vendor": result.vendor, "topic": result.topic, "title": result.title},
            )

        return result

    def close(self) -> None:
        """Close fetcher connection pool."""
        self.fetcher.close()

    def __enter__(self) -> VendorDocScraper:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
