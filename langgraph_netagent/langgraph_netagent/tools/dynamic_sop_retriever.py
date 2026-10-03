"""Dynamic SOP Retriever for LangGraph NetAgent.

Bridges the real-time VendorDocScraper engine with the DualRetrievalEngine and
legacy SOPRetriever interfaces.

Key Capabilities:
1. Dynamically generates SOPDocument instances from ScrapedDocResult
2. Ingests scraped command syntax and rollbacks directly into CommandTreeStore (as TreeNode)
   and LightweightVectorIndex (as VectorIndexEntry)
3. Supports on-demand scraping and ingestion via `scrape_and_ingest(url, vendor, topic)`
4. Satisfies both `retrieve(keywords, limit, vendor)` and `retrieve_dual(query, vendor, limit)`
   interfaces required by `operational_nodes.py`
5. Formats markdown prompt context strictly adhering to the `<500B` budget ceiling
"""

from __future__ import annotations

import logging
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Union

from langgraph_netagent.models.knowledge import (
    DualRetrievalResult,
    TreeNode,
    VectorIndexEntry,
)
from langgraph_netagent.tools.sop_retriever import (
    DEFAULT_SOPS,
    SOPDocument,
    SOPRetriever,
)
from langgraph_netagent.tools.vendor_doc_scraper import (
    CommandSyntax,
    ReverseRollbackGenerator,
    ScrapedDocResult,
    TroubleshootingStep,
    VendorDocScraper,
)
from langgraph_netagent.tools.vendor_knowledge import DualRetrievalEngine

logger = logging.getLogger(__name__)


class DynamicSOPRetriever(SOPRetriever):
    """Dynamic Standard Operating Procedure (SOP) Knowledge Retriever.

    Subclasses SOPRetriever to provide seamless backward compatibility while
    dynamically populating the knowledge base with real-time scraped vendor documentation.
    """

    def __init__(
        self,
        sops: Optional[List[SOPDocument]] = None,
        dual_engine: Optional[DualRetrievalEngine] = None,
        scraper: Optional[VendorDocScraper] = None,
        cache_dir: Optional[Union[str, Path]] = None,
        pre_scrape_urls: Optional[List[str]] = None,
    ) -> None:
        # Use a copy of sops list so mutations don't alter global DEFAULT_SOPS
        initial_sops = list(sops) if sops is not None else list(DEFAULT_SOPS)
        super().__init__(sops=initial_sops, dual_engine=dual_engine)
        self._scraper_instance = scraper
        self._cache_dir = cache_dir
        self._dynamic_sops: List[SOPDocument] = []
        self._scraped_results: List[ScrapedDocResult] = []

        if pre_scrape_urls:
            for url in pre_scrape_urls:
                try:
                    self.scrape_and_ingest(url)
                except Exception as exc:
                    logger.warning("Pre-scrape ingestion failed for %s: %s", url, exc)

    @property
    def scraper(self) -> VendorDocScraper:
        """Lazily initialize the VendorDocScraper to avoid early network client creation."""
        if self._scraper_instance is None:
            self._scraper_instance = VendorDocScraper(cache_dir=self._cache_dir)
        return self._scraper_instance

    @scraper.setter
    def scraper(self, value: VendorDocScraper) -> None:
        self._scraper_instance = value

    @property
    def dynamic_sops(self) -> List[SOPDocument]:
        """List of dynamically ingested SOPDocuments."""
        return list(self._dynamic_sops)

    @property
    def scraped_results(self) -> List[ScrapedDocResult]:
        """List of raw ScrapedDocResult objects collected."""
        return list(self._scraped_results)

    def scrape_and_ingest(
        self,
        url: str,
        vendor: Optional[str] = None,
        topic: Optional[str] = None,
        force_refresh: bool = False,
    ) -> ScrapedDocResult:
        """Fetch, scrape, and ingest vendor documentation into tree store and SOP catalogue.

        Args:
            url: Target vendor documentation URL.
            vendor: Optional vendor hint ('frr', 'cisco', 'arista', 'linux', 'generic').
            topic: Operational category hint (e.g. 'static_route', 'bgp').
            force_refresh: If True, bypass cache and re-fetch from network.

        Returns:
            The parsed ScrapedDocResult.
        """
        result = self.scraper.scrape(
            url=url,
            vendor=vendor,
            topic=topic,
            force_refresh=force_refresh,
        )
        self.ingest_scraped_result(result)
        return result

    def ingest_scraped_result(self, scraped: ScrapedDocResult) -> List[SOPDocument]:
        """Convert ScrapedDocResult into SOPDocument, TreeNode, and VectorIndexEntry instances.

        Args:
            scraped: The structured scraped result.

        Returns:
            List of generated SOPDocument instances.
        """
        self._scraped_results.append(scraped)
        vendor = scraped.vendor.lower()
        topic = (scraped.topic or "routing").lower().replace(" ", "_")

        generated_sops: List[SOPDocument] = []

        # 1. Ingest CommandSyntax items into DualRetrievalEngine (TreeNode & VectorIndexEntry)
        for idx, cmd in enumerate(scraped.commands):
            action_name = self._derive_action_name(cmd.command_template, cmd.syntax, idx)
            platform = self._derive_platform(vendor)
            domain = topic
            path = f"{vendor}/{platform}/{domain}/{action_name}"

            rollback = ReverseRollbackGenerator.generate_rollback(cmd.command_template, vendor=vendor)
            param_list = list(cmd.parameters.keys()) if cmd.parameters else self._extract_parameters(cmd.command_template)

            # Build TreeNode
            node = TreeNode(
                path=path,
                vendor=vendor,
                platform=platform,
                domain=domain,
                action=action_name,
                command_template=cmd.command_template,
                rollback_template=rollback,
                parameters=param_list,
                description=cmd.description or f"Remediation template for {action_name}",
                is_leaf=True,
                mode=cmd.mode,
            )
            self.dual_engine.tree_store.insert(node)

            # Build VectorIndexEntry
            entry_id = f"vec-{path.replace('/', '-')}"
            symptom_tokens = (
                [vendor, platform, domain, action_name]
                + param_list
                + [w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", cmd.command_template)]
                + [w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", cmd.description)]
            )
            entry = VectorIndexEntry(
                entry_id=entry_id,
                tree_path=path,
                vendor=vendor,
                intent=action_name.upper(),
                scene_description=cmd.description or f"{vendor.title()} {domain} command: {cmd.command_template}",
                symptom_keywords=list(dict.fromkeys(symptom_tokens)),
            )
            self.dual_engine.vector_index.add_entry(entry)

        # 2. Build SOPDocument instances from TroubleshootingSteps and Commands
        if scraped.troubleshooting_steps:
            for step in scraped.troubleshooting_steps:
                if not step.remediation_commands and not step.verification_commands:
                    continue
                step_sop = self._build_sop_from_step(scraped, step)
                generated_sops.append(step_sop)

        # If no troubleshooting steps yielded remediations, build an aggregate SOP from commands
        if not generated_sops and scraped.commands:
            aggregate_sop = self._build_aggregate_sop(scraped)
            generated_sops.append(aggregate_sop)

        # Register generated SOPs into active search catalogue
        for sop in generated_sops:
            self._dynamic_sops.append(sop)
            # Insert at head so freshly scraped SOPs take precedence over default static fallbacks
            self.sops.insert(0, sop)

        logger.info(
            "Ingested %d commands and %d dynamic SOPs from %s",
            len(scraped.commands),
            len(generated_sops),
            scraped.url,
        )
        return generated_sops

    def _build_sop_from_step(self, scraped: ScrapedDocResult, step: TroubleshootingStep) -> SOPDocument:
        """Create a single SOPDocument from a TroubleshootingStep."""
        vendor = scraped.vendor.lower()
        topic = (scraped.topic or "routing").lower().replace(" ", "_")
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", step.title.lower()).strip("_")
        sop_id = f"SOP-SCRAPED-{vendor.upper()}-{slug[:24]}"

        remed = list(step.remediation_commands)
        rollbacks = list(step.rollback_commands)
        if remed and not rollbacks:
            rollbacks = [ReverseRollbackGenerator.generate_rollback(c, vendor=vendor) for c in remed]

        kws = [vendor, topic] + [w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", step.title)]
        for cmd in remed:
            kws.extend([w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", cmd)])

        return SOPDocument(
            sop_id=sop_id,
            title=f"{scraped.vendor.title()} {scraped.topic.title()}: {step.title}",
            category=scraped.topic.upper() or "DYNAMIC_VENDOR_SOP",
            keywords=list(dict.fromkeys(kws)),
            symptoms=[
                step.explanation or f"Operational failure requiring {step.title} on {scraped.vendor}",
            ],
            diagnosis_steps=step.verification_commands or [f"Check {scraped.vendor} status for {scraped.topic}"],
            remediation_template=remed or [f"# Verify {scraped.vendor} configuration"],
            rollback_template=rollbacks or [f"# Undo {scraped.vendor} configuration"],
        )

    def _build_aggregate_sop(self, scraped: ScrapedDocResult) -> SOPDocument:
        """Build an aggregate SOPDocument when no explicit TroubleshootingSteps exist."""
        vendor = scraped.vendor.lower()
        topic = (scraped.topic or "routing").lower().replace(" ", "_")
        sop_id = f"SOP-SCRAPED-{vendor.upper()}-{topic.upper()}"

        remed: List[str] = []
        rollbacks: List[str] = []
        kws: List[str] = [vendor, topic]

        for cmd in scraped.commands:
            remed.append(cmd.command_template)
            rollbacks.append(ReverseRollbackGenerator.generate_rollback(cmd.command_template, vendor=vendor))
            kws.extend(cmd.parameters.keys())
            kws.extend([w.lower() for w in re.findall(r"\b[a-zA-Z]{3,}\b", cmd.command_template)])

        return SOPDocument(
            sop_id=sop_id,
            title=scraped.title or f"{scraped.vendor.title()} {scraped.topic.title()} Dynamic Procedure",
            category=scraped.topic.upper() or "DYNAMIC_VENDOR_SOP",
            keywords=list(dict.fromkeys(kws)),
            symptoms=[
                f"Operational incident involving {scraped.vendor} {scraped.topic}",
            ],
            diagnosis_steps=[f"Run show commands on {scraped.vendor} to verify {scraped.topic}"],
            remediation_template=remed[:5],
            rollback_template=rollbacks[:5],
        )

    @staticmethod
    def _derive_action_name(template: str, syntax: str, index: int) -> str:
        """Derive clean tree action identifier from command syntax."""
        src = template or syntax or f"action_{index}"
        clean = ReverseRollbackGenerator.clean_command(src)
        tokens = [t for t in re.findall(r"[a-zA-Z0-9]+", clean) if not t.isupper()]
        if len(tokens) >= 2:
            return f"{tokens[0]}_{tokens[1]}".lower()
        elif len(tokens) == 1:
            return tokens[0].lower()
        return f"cmd_{index + 1}"

    @staticmethod
    def _derive_platform(vendor: str) -> str:
        """Derive CLI execution platform for vendor."""
        v = (vendor or "generic").lower()
        if v == "frr":
            return "vtysh"
        if v == "cisco":
            return "ios"
        if v == "arista":
            return "eos"
        if v == "linux":
            return "system"
        return "cli"

    @staticmethod
    def _extract_parameters(template: str) -> List[str]:
        """Extract parameter placeholder tokens from template."""
        curly = re.findall(r"\{([a-zA-Z0-9_]+)\}", template)
        if curly:
            return curly
        brackets = re.findall(r"[<\[]([a-zA-Z0-9_]+)[>\]]", template)
        if brackets:
            return [b.lower() for b in brackets]
        uppers = [w.lower() for w in re.findall(r"\b[A-Z]{2,}\b", template)]
        return uppers

    def retrieve(
        self,
        keywords: List[str],
        limit: int = 3,
        vendor: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve matching SOPs based on keywords and vendor.

        Searches dynamic scraped SOPs alongside default catalogue.
        """
        return super().retrieve(keywords=keywords, limit=limit, vendor=vendor)

    def retrieve_dual(
        self,
        query: str,
        vendor: Optional[str] = None,
        limit: int = 3,
    ) -> List[DualRetrievalResult]:
        """Retrieve tree-backed DualRetrievalResult items from dynamic tree & vector index."""
        return self.dual_engine.retrieve(query=query, vendor=vendor, top_k=limit)

    def format_dual_markdown(
        self,
        results: List[DualRetrievalResult],
        max_bytes: int = 500,
    ) -> str:
        """Format dual-retrieval results into concise markdown strictly adhering to `<500B` budget.

        Args:
            results: List of DualRetrievalResult items.
            max_bytes: Hard ceiling in bytes (default 500).

        Returns:
            Concise markdown string guaranteed to be <= max_bytes.
        """
        return self.dual_engine.format_prompt_context(results, max_bytes=max_bytes)

    @staticmethod
    def format_sop_markdown(
        sops: List[Dict[str, Any]],
        max_bytes: int = 500,
    ) -> str:
        """Format SOP list into markdown strictly within `max_bytes` budget (<500B).

        Args:
            sops: List of SOP dictionary entries.
            max_bytes: Maximum byte budget (default 500).

        Returns:
            Markdown formatted string strictly within byte budget.
        """
        if not sops:
            return ""

        parts: List[str] = []
        current_bytes = 0

        for sop in sops:
            title = sop.get("title", "")
            sop_id = sop.get("sop_id", "")
            cat = sop.get("category", "")
            remed = "; ".join(sop.get("remediation_template", []))
            roll = "; ".join(sop.get("rollback_template", []))

            snippet = f"### {sop_id}: {title}\n- Cat: {cat}\n- Fix: {remed}\n- Rollback: {roll}"
            sb = len(snippet.encode("utf-8"))

            if current_bytes + sb > max_bytes and parts:
                break
            parts.append(snippet)
            current_bytes += sb + 2

        formatted = "\n\n".join(parts)
        if len(formatted.encode("utf-8")) > max_bytes:
            trimmed = formatted.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
            last_nl = trimmed.rfind("\n")
            if last_nl > 0:
                formatted = trimmed[:last_nl]
            else:
                formatted = trimmed

        return formatted
