# Project: netops-ai-agent Dynamic Topology Discovery & Scraped Knowledge Base Refactoring

## Architecture
Decouple netops-ai-agent from static topology assumptions and hardcoded SOP playbooks by implementing runtime-driven network diagnosis:
1. **Dynamic Topology Engine (`tools/topology_discovery.py`)**:
   - Parses Containerlab `.clab.yml` files (supporting `defaults.kind`, `nodes`, `links`, `group`, `ports`, `mtu`, `env`, `exec`, `binds`).
   - Extracts embedded configs (IPs in `env:`, `exec:` commands like `ip addr add`, DHCP pools, NAT VIPs).
   - Resolves RFC 1918 subnets (fixing the 172.16.x.x filtering bug).
   - Builds `DiscoveredTopology` graph with subnet indexing, longest-prefix matching (LPM), interface-to-peer links, and role classification.
2. **Dynamic Knowledge Base & Scraper (`tools/vendor_doc_scraper.py` & `tools/dynamic_sop_retriever.py`)**:
   - Fetches live vendor documentation (FRR Sphinx docs, Cisco command reference tables, Arista EOS docs) via `httpx` and `BeautifulSoup`.
   - Extracts command syntax, parameters, verification commands, and troubleshooting workflows.
   - Manages SHA-256 persistent disk caching with TTL for offline/air-gapped resilience and sub-millisecond query performance.
   - Automatically generates inverse rollback commands (`no <command>`, etc.).
   - Feeds into `CommandTreeStore` and `LightweightVectorIndex`, preserving the `<500B` prompt budget.
3. **Refactored Day-2 Operational Workflow (`workflow/operational_nodes.py` & `operational_state.py`)**:
   - Extends `OperationalState` with `discovered_topology`, `scraped_sops`, and `runtime_incident_context`.
   - Eliminates all 13 hardcoded IPs (`192.168.100.2`, `203.0.113.10`, `10.1.12.2`, `10.2.2.0/24`) and router names (`dc-egress`, `frr1`) from `operational_nodes.py`.
   - Resolves bottleneck nodes, offending client IPs, victim VIPs, and routing deficits dynamically from the graph.
   - Injects runtime topology and scraped knowledge into Day-2 LLM diagnostic prompts.
4. **Verification & Hardening Pipeline (`tests/`)**:
   - Programmatic topology discovery test with `clos5_dhcp.yml`.
   - Grep verification ensuring zero hardcoded IPs/node names in `workflow/*.py`.
   - Programmatic web scraping test against vendor URLs.
   - End-to-end Containerlab diagnostic test with dynamic context.
   - 100% zero-regression across all 973 existing tests.

---

## Feature Inventory
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F1 | Containerlab Full Schema Parser | Parse YAML files supporting `topology.defaults`, custom kinds, link MTUs, groups, and ports | M1 | explorer_survey_3_1 |
| F2 | Static Configuration Extractor | Extract declared IPs and subnets from `env` (e.g. `HOSTNET`), `exec` commands, and binds | M1 | explorer_survey_3_1 |
| F3 | DiscoveredTopology Graph Model | Graph data model holding nodes, links, IP-to-node index, subnet-to-nodes LPM index, and peer maps | M1 | explorer_survey_3_1 |
| F4 | RFC 1918 172.16.x.x Subnet Fix | Fix filtering in `_extract_data_ips` so valid data plane subnets in `172.16.0.0/12` are preserved | M1 | explorer_survey_3_1 |
| F5 | Topology Query & Routing Helpers | Provide programmatic helper methods for role detection, gateway lookup, and adjacent peer resolution | M1 | explorer_survey_3_1 |
| F6 | Resilient HTTP Document Fetcher | Fetch vendor docs with polite headers, rate limiting, and exponential retry backoff | M2 | spec_miner_survey_3_2 |
| F7 | Multi-Vendor HTML Parsers | DOM parsers for FRR Sphinx (`<dl class="cli">`), Cisco tables, and Arista EOS references | M2 | spec_miner_survey_3_2 |
| F8 | Syntax & Troubleshooting Extractor | Extract command syntax, descriptions, parameters, and troubleshooting step sequences | M2 | spec_miner_survey_3_2 |
| F9 | SHA-256 Persistent Local Caching | Cache scraped documentation locally by URL hash with TTL for air-gapped / offline execution | M2 | spec_miner_survey_3_2 |
| F10 | Automated Rollback Generator | Synthesize inverse compensation commands (`no <cmd>`, `del`, etc.) for scraped actions | M2 | spec_miner_survey_3_2 |
| F11 | Dynamic SOP Retriever Integration | Feed scraped SOPs into `CommandTreeStore` and vector index preserving `<500B` prompt budget | M2 | spec_miner_survey_3_2 |
| F12 | OperationalState Schema Extension | Add `discovered_topology`, `scraped_sops`, and `runtime_incident_context` to `OperationalState` | M3 | explorer_survey_3_3 |
| F13 | Baseline Ingestion Dynamic Topology | Populate `discovered_topology` in `baseline_ingestion_node` via `TopologyDiscoverer` | M3 | explorer_survey_3_3 |
| F14 | Operational Nodes Hardcode Removal | Replace all 13 hardcoded IPs, subnets, and node names in `operational_nodes.py` with graph lookups | M3 | explorer_survey_3_3 |
| F15 | LLM Prompt Dynamic Context Injection | Inject discovered topology and scraped SOPs into `diagnostic_stage1` and `stage2` prompts | M3 | explorer_survey_3_3 |
| F16 | Programmatic Topology Discovery Test | Test taking `clos5_dhcp.yml` and outputting nodes, links, and IPs without lookup tables | M1, M4 | explorer_survey_3_3 |
| F17 | Zero-Hardcoding Grep Audit Suite | Programmatic scanner asserting zero hardcoded IPs/node names in `workflow/*.py` | M4 | explorer_survey_3_3 |
| F18 | Web Scraping Programmatic Test | Test accepting FRR/Cisco doc URLs and verifying syntax and troubleshooting extraction | M2, M4 | explorer_survey_3_3 |
| F19 | Containerlab E2E Diagnostic Test | Diagnostic test verifying anomaly diagnosis succeeds using dynamic topology and scraped SOPs | M4 | explorer_survey_3_3 |
| F20 | Regression Suite Verification | Validate 100% pass across all 973 existing tests in `langgraph_netagent` | M4 | explorer_survey_3_3 |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Dynamic Topology Discovery Engine | Implement Containerlab YAML parser, static config extraction, `DiscoveredTopology` model, 172.16 fix, and topology discovery test (`test_topology_discovery.py`) | none | DONE |
| M2 | Dynamic Knowledge Base & Web Scraper | Implement `DocFetcher`, `DocCacheManager`, vendor HTML parsers, rollback generator, `DynamicSOPRetriever`, and scraper test (`test_vendor_scraper.py`) | none | DONE |
| M3 | Workflow Refactoring & Context Injection | Extend `OperationalState`, eliminate 13 hardcoded instances in `operational_nodes.py`, inject dynamic topology & scraped SOPs into LLM prompts | M1, M2 | DONE |
| M4 | Verification, Audit & Zero Regression | Execute topology test, grep scanner (`test_no_hardcoded_topology.py`), scraper test, Containerlab E2E diagnostic test, and 100% regression validation | M3 | DONE |

---

## Interface Contracts

### Topology Engine ↔ Workflow
- **Module**: `langgraph_netagent/tools/topology_discovery.py`
- **Class**: `TopologyDiscoverer`
- **Methods**:
  ```python
  def discover_from_yaml(self, yaml_path: Union[str, Path]) -> DiscoveredTopology: ...
  def discover_from_runtime(self, yaml_path: Optional[Union[str, Path]] = None) -> DiscoveredTopology: ...
  ```
- **Data Structure (`models/topology.py` or `models/discovered_topology.py`)**:
  ```python
  class DiscoveredTopology(BaseModel):
      name: str
      nodes: Dict[str, DiscoveredNode]
      links: List[DiscoveredLink]
      ip_to_node: Dict[str, str]
      subnet_to_nodes: Dict[str, List[str]]
      subnets: List[str]
      node_roles: Dict[str, str]  # router, egress, host, etc.
      def find_node_by_ip(self, ip: str) -> Optional[str]: ...
      def find_gateway_for_subnet(self, subnet: str) -> Optional[str]: ...
      def find_router_nodes(self) -> List[str]: ...
      def find_peer_interfaces(self, node: str) -> Dict[str, Tuple[str, str]]: ...
  ```

### Web Scraper ↔ Knowledge Base & Workflow
- **Module**: `langgraph_netagent/tools/vendor_doc_scraper.py`
- **Classes**: `DocFetcher`, `DocCacheManager`, `VendorDocScraper`
- **Methods**:
  ```python
  def scrape_vendor_doc(url: str, force_refresh: bool = False) -> ScrapedDocResult: ...
  def extract_troubleshooting_steps(soup: BeautifulSoup, vendor: str) -> List[TroubleshootingStep]: ...
  def extract_command_syntaxes(soup: BeautifulSoup, vendor: str) -> List[CommandSyntax]: ...
  ```
- **Integration**:
  `DynamicSOPRetriever` subclasses or wraps `SOPRetriever`, accepting dynamically scraped SOPs while maintaining the `retrieve(keywords, limit)` and `retrieve_dual(query, limit)` signatures and formatting output within `<500B`.

---

## Code Layout
- `langgraph_netagent/langgraph_netagent/models/topology.py`: Containerlab schema updates (`topology.defaults`, custom kinds, etc.)
- `langgraph_netagent/langgraph_netagent/models/discovered_topology.py`: `DiscoveredTopology`, `DiscoveredNode`, `DiscoveredLink`
- `langgraph_netagent/langgraph_netagent/tools/topology_discovery.py`: Standalone dynamic topology discovery engine
- `langgraph_netagent/langgraph_netagent/tools/vendor_doc_scraper.py`: Real-time web scraping module, DOM parsers, cache manager
- `langgraph_netagent/langgraph_netagent/tools/dynamic_sop_retriever.py`: SOP integration layer bridging scraper with dual retrieval
- `langgraph_netagent/langgraph_netagent/workflow/operational_state.py`: Enhanced state with `discovered_topology` and `scraped_sops`
- `langgraph_netagent/langgraph_netagent/workflow/operational_nodes.py`: Refactored nodes without hardcoded IPs/names
- `langgraph_netagent/langgraph_netagent/prompts/day2_prompts.py`: Enhanced prompts with dynamic topology and runtime context
- `langgraph_netagent/tests/test_topology_discovery.py`: Test taking `clos5_dhcp.yml` and testing programmatic topology extraction
- `langgraph_netagent/tests/test_vendor_scraper.py`: Test scraping vendor doc URLs and extracting syntax/troubleshooting
- `langgraph_netagent/tests/test_no_hardcoded_topology.py`: Grep scanner test verifying absence of hardcoded IPs/names in workflow
- `langgraph_netagent/tests/test_e2e_dynamic_workflow.py`: End-to-end Containerlab diagnostic verification test
