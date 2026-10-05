"""Command-Line Interface (CLI) Entrypoint for LangGraph NetOps Agent.

Provides the `netagent` CLI tool and `python -m langgraph_netagent.cli` entrypoint
for autonomous network design, validation, deployment, active telemetry verification,
and closed-loop self-healing.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Sequence

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from langgraph_netagent import __version__
except ImportError:
    try:
        from importlib.metadata import version as _pkg_version
        __version__ = _pkg_version("langgraph-netagent")
    except Exception:
        __version__ = "0.1.0"
from langgraph_netagent.llm.base import LLMConfig
from langgraph_netagent.llm.providers.mock_provider import MockLLMProvider
from langgraph_netagent.llm.providers.ollama_provider import OllamaProvider
from langgraph_netagent.llm.providers.qwen_openai import QwenOpenAIProvider
from langgraph_netagent.llm.providers.vllm_provider import VLLMProvider
from langgraph_netagent.models.diagnostic import DiagnosticReport, ErrorCategory, SeverityLevel
from langgraph_netagent.models.intent import (
    IsolationMode,
    LinkIntent,
    NetworkIntent,
    NodeIntent,
    ProtocolType,
    QoSLevel,
)
from langgraph_netagent.models.remediation import (
    ConfigurationPatch,
    RemediationActionType,
    RemediationPlan,
)
from langgraph_netagent.models.topology import (
    ContainerlabLinkEndpoint,
    ContainerlabMgmtConfig,
    ContainerlabNodeConfig,
    ContainerlabTopologyDefinition,
    ContainerlabTopologyFile,
    DeviceConfigFile,
    FullTopologyPackage,
    IPAllocation,
)
from langgraph_netagent.tools.clab_adapter import LiveContainerlabAdapter
from langgraph_netagent.tools.detector import EnvironmentDetector, ExecutionMode, SystemNetworkInventory
from langgraph_netagent.tools.exporter import TopologyExporter
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter
from langgraph_netagent.validation.offline_validator import OfflineValidator
from langgraph_netagent.workflow.graph import (
    build_network_agent_graph,
    run_network_agent_workflow,
)
from langgraph_netagent.workflow.nodes import DiagnosticAndRemediation
from langgraph_netagent.workflow.state import create_initial_state


# ANSI Color definitions
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_CYAN = "\033[36m"
COLOR_DIM = "\033[2m"


def _supports_color() -> bool:
    """Determine whether stdout supports ANSI color output."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _load_dotenv_if_present() -> None:
    """Load key-value pairs from .env into os.environ if present."""
    candidates = [
        Path.cwd() / ".env",
        Path(__file__).resolve().parent.parent / ".env",
        Path(__file__).resolve().parent.parent.parent / ".env",
    ]
    for candidate in candidates:
        if candidate.is_file():
            try:
                for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                    clean = line.strip()
                    if clean and not clean.startswith("#") and "=" in clean:
                        k, v = clean.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
                break
            except Exception:
                pass


def _format_stage(stage: str, message: str, level: str = "info") -> str:
    """Format a log or stage message for terminal display."""
    use_color = _supports_color()
    color_map = {
        "info": COLOR_GREEN if use_color else "",
        "warning": COLOR_YELLOW if use_color else "",
        "error": COLOR_RED if use_color else "",
        "critical": f"{COLOR_BOLD}{COLOR_RED}" if use_color else "",
    }
    reset = COLOR_RESET if use_color else ""
    bold = COLOR_BOLD if use_color else ""
    color = color_map.get(level.lower(), "")
    prefix = f"[{level.upper()}]"
    return f"{color}{bold}{prefix:<10}{reset} [{stage}] {message}"


def print_scan_inventory(inv: SystemNetworkInventory) -> None:
    """Print formatted inventory of NICs, bridges, and accessible network topologies."""
    use_color = _supports_color()
    bold = COLOR_BOLD if use_color else ""
    cyan = COLOR_CYAN if use_color else ""
    green = COLOR_GREEN if use_color else ""
    yellow = COLOR_YELLOW if use_color else ""
    dim = "\033[2m" if use_color else ""
    reset = COLOR_RESET if use_color else ""

    print(f"\n{bold}{cyan}=== 网络资产与拓扑环境检索报告 (Network & Topology Inventory) ==={reset}\n")

    print(f"{bold}1. 宿主机真实网络适配器 (Windows Host NICs):{reset}")
    if inv.host_interfaces:
        print(f"  {'网卡名称':<34} {'描述':<44} {'速率'}")
        print(f"  {'-' * 88}")
        for nic in inv.host_interfaces:
            print(f"  {nic.get('name', ''):<34} {nic.get('description', '')[:42]:<44} {nic.get('speed', '')}")
    else:
        print(f"  {dim}(未获取到活跃网卡或处于非 Windows 容器环境){reset}")

    print(f"\n{bold}2. WSL 虚拟桥接与容器网卡 (WSL Linux Bridges & Virtual Interfaces):{reset}")
    if inv.wsl_bridges:
        print(f"  {'网络接口/网桥':<34} {'状态':<10} {'绑定 IP 网段 / 角色'}")
        print(f"  {'-' * 88}")
        for br in inv.wsl_bridges:
            st_color = green if br.get("state") == "UP" else dim
            print(f"  {br.get('name', ''):<34} {st_color}{br.get('state', ''):<10}{reset} {br.get('addrs', '')}")
    else:
        print(f"  {dim}(未检测到 WSL 网桥){reset}")

    print(f"\n{bold}3. 当前可接入的网络拓扑 (Available Network Topologies):{reset}")
    print(f"  {'序号':<6} {'拓扑环境类型':<30} {'实验名称':<16} {'节点数':<8} {'详情与状态'}")
    print(f"  {'-' * 88}")
    for topo in inv.available_topologies:
        cur_mark = f" {green}<- [推荐接入]{reset}" if topo.name == inv.recommended_lab else ""
        print(f"  [{topo.id}]    {topo.display_type:<26} {topo.name:<16} {topo.node_count:<8} {topo.summary}{cur_mark}")

    print(f"\n{bold}人工接入与运行指引:{reset}")
    print(f"  {yellow}• 交互式控制台人工选择接入:{reset}")
    print(f"      python -m langgraph_netagent.cli -it")
    print(f"  {yellow}• 命令行直接绑定真实容器网络 (clos5):{reset}")
    print(f"      python -m langgraph_netagent.cli --harmonized --mode live --lab-name clos5")
    print(f"  {yellow}• 命令行绑定纯内存虚拟拓扑 (netagent-lab):{reset}")
    print(f"      python -m langgraph_netagent.cli --harmonized --mode mock\n")


def create_default_mock_llm(user_intent: str) -> MockLLMProvider:
    """Create a fully featured deterministic MockLLMProvider for offline CLI demos."""
    config = LLMConfig(provider_type="mock", model_name="mock-qwen-netagent", max_retries=3)
    provider = MockLLMProvider(config=config)

    # 1. Default parsed intent
    default_intent = NetworkIntent(
        intent_id="intent-cli-default",
        raw_intent=user_intent,
        summary=f"Automated topology generated from intent: {user_intent}",
        nodes=[
            NodeIntent(name="pc1", role="host", device_kind="linux", subnets=["10.1.1.0/24"]),
            NodeIntent(name="frr1", role="router", device_kind="frr", subnets=["10.1.1.0/24", "10.2.2.0/24"]),
            NodeIntent(name="pc2", role="host", device_kind="linux", subnets=["10.2.2.0/24"]),
        ],
        links=[
            LinkIntent(source_node="pc1", target_node="frr1", subnet="10.1.1.0/24"),
            LinkIntent(source_node="frr1", target_node="pc2", subnet="10.2.2.0/24"),
        ],
        protocols=[ProtocolType.STATIC],
        qos=QoSLevel.STANDARD,
        isolation=IsolationMode.NONE,
        source_endpoints=["pc1"],
        target_endpoints=["pc2"],
        verification_targets=["pc1 -> pc2 ping"],
    )

    # 2. Default topology package
    default_topo = ContainerlabTopologyFile(
        name="netagent-lab",
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
                "pc2": ContainerlabNodeConfig(
                    kind="linux",
                    image="alpine:latest",
                    binds=["config/pc2/setup.sh:/setup.sh"],
                    exec=["sh /setup.sh"],
                ),
            },
            links=[
                ContainerlabLinkEndpoint(endpoints=["pc1:eth1", "frr1:eth1"]),
                ContainerlabLinkEndpoint(endpoints=["frr1:eth2", "pc2:eth1"]),
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
 ip address 10.2.2.1/24
!
line vty
!
""",
            permissions="0644",
            description="frr1 configuration",
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
        IPAllocation(node_name="pc1", interface_name="eth1", ipv4_address="10.1.1.2/24", gateway_ipv4="10.1.1.1", peer_node="frr1", peer_interface="eth1"),
        IPAllocation(node_name="frr1", interface_name="eth1", ipv4_address="10.1.1.1/24", peer_node="pc1", peer_interface="eth1"),
        IPAllocation(node_name="frr1", interface_name="eth2", ipv4_address="10.2.2.1/24", peer_node="pc2", peer_interface="eth1"),
        IPAllocation(node_name="pc2", interface_name="eth1", ipv4_address="10.2.2.2/24", gateway_ipv4="10.2.2.1", peer_node="frr1", peer_interface="eth2"),
    ]

    default_package = FullTopologyPackage(
        topology=default_topo,
        configs=configs,
        ip_allocations=allocations,
    )

    # 3. Default diagnosis and remediation
    default_remediation = DiagnosticAndRemediation(
        diagnostic=DiagnosticReport(
            telemetry_trigger="Packet drop or route deficit detected",
            root_cause="Missing static route or interface configuration",
            affected_nodes=["frr1"],
            error_category=ErrorCategory.ROUTING_MISCONFIG,
            severity=SeverityLevel.HIGH,
            confidence_score=0.92,
            evidence=["Ping probing returned packet loss"],
        ),
        remediation=RemediationPlan(
            action_type=RemediationActionType.PATCH_CONFIG_FILE,
            target_entity="frr1",
            configuration_patch=ConfigurationPatch(
                file_path="config/frr/frr.conf",
                patch_type="FULL_REPLACE",
                new_content="""hostname frr1
service integrated-vtysh-config
!
interface eth1
 ip address 10.1.1.1/24
!
interface eth2
 ip address 10.2.2.1/24
!
line vty
!
""",
            ),
            expected_outcome="Route restored, ping reachability achieved",
            estimated_risk=SeverityLevel.LOW,
        ),
    )

    # Register pattern handlers
    provider.register_pattern("intent", lambda _: default_intent)
    provider.register_pattern("topology", lambda _: default_package)
    provider.register_pattern("package", lambda _: default_package)
    provider.register_pattern("diagnose", lambda _: default_remediation)
    provider.register_pattern("fix", lambda _: default_remediation)
    provider.register_pattern("remediation", lambda _: default_remediation)

    # Also register default responses as canned fallback queue
    provider.register_canned_response(default_intent)
    provider.register_canned_response(default_package)
    for _ in range(5):
        provider.register_canned_response(default_remediation)

    return provider


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for netagent."""
    parser = argparse.ArgumentParser(
        prog="netagent",
        description="LangGraph NetOps Autonomous Agent: Intent-Driven Closed-Loop Network Automation.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  netagent --mode mock --intent "Connect pc1 and pc2 via frr1"
  netagent --mode live --auto-approve --output-dir ./my_lab
  netagent --topo-only --output-dir ./configs
  netagent --provider qwen --model Qwen/Qwen2.5-7B-Instruct --api-key $DASHSCOPE_API_KEY
        """,
    )

    parser.add_argument(
        "--intent", "-i",
        type=str,
        default="Connect pc1 and pc2 via frr1 with static routing and verify reachability",
        help="Natural language network intent specification (default: standard host-router-host intent).",
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["mock", "live", "auto"],
        default="auto",
        help="Lab execution mode: 'mock' (zero Docker privileges), 'live' (Containerlab runtime), or 'auto' (default: auto-detect).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum self-healing and validation retries before circuit breaker trips (default: 3).",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        default=True,
        help="Automatically approve deployment at human approval checkpoint (default: True).",
    )
    parser.add_argument(
        "--no-auto-approve",
        dest="auto_approve",
        action="store_false",
        help="Pause for interactive operator approval before deploying to lab environment.",
    )
    parser.add_argument(
        "--interactive", "-it",
        action="store_true",
        default=False,
        help="Launch the interactive NetOps terminal REPL console.",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default="./clab_output",
        help="Directory to write Containerlab topology YAML and device configs (default: ./clab_output).",
    )
    parser.add_argument(
        "--topo-only",
        action="store_true",
        default=False,
        help="Generate and validate topology only, skipping deployment and telemetry probing.",
    )

    parser.add_argument(
        "--harmonized",
        action="store_true",
        default=False,
        help="Execute harmonized operational workflow across Day-1, Day-2, and Day-3.",
    )
    parser.add_argument(
        "--lab-name",
        type=str,
        default=None,
        help="Containerlab lab name for Day-2 operations or inspect/destroy.",
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        default=False,
        help="Scan and list host network adapters, WSL container bridges, and discoverable topologies, then exit.",
    )
    parser.add_argument(
        "--watch", "-w",
        action="store_true",
        default=False,
        help="Run persistent telemetry monitoring loop",
    )
    parser.add_argument(
        "--watch-interval",
        type=float,
        default=5.0,
        help="Polling interval in seconds between healthy checks",
    )
    parser.add_argument(
        "--max-watch-cycles",
        type=int,
        default=None,
        help="Maximum number of watch cycles before exiting (default: infinite)",
    )
    parser.add_argument(
        "--provider",
        choices=["mock", "qwen", "openai", "vllm", "ollama"],
        default="mock",
        help="LLM provider for intent parsing, topology generation, and self-healing (default: mock).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="LLM model name (e.g. Qwen/Qwen2.5-7B-Instruct, gpt-4o, etc.).",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="API key for Qwen/OpenAI provider (falls back to DASHSCOPE_API_KEY / OPENAI_API_KEY).",
    )
    parser.add_argument(
        "--base-url",
        type=str,
        default=None,
        help="Custom base URL for vLLM, Ollama, or OpenAI-compatible endpoint.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable detailed execution logging and trace dumps.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser


def run_cli(args: Optional[Sequence[str]] = None) -> int:
    """Execute the netagent CLI with command line arguments.

    Returns:
        0 on success (verified or valid topology generated).
        1 on validation failure, rejection, or unexpected error.
        2 on circuit breaker tripped.
    """
    _load_dotenv_if_present()
    parser = build_arg_parser()
    try:
        parsed_args = parser.parse_args(args)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1

    if getattr(parsed_args, "scan", False):
        detector = EnvironmentDetector()
        inv = detector.scan_inventory()
        print_scan_inventory(inv)
        return 0

    if parsed_args.interactive:
        from langgraph_netagent.interactive import start_repl
        effective_provider = parsed_args.provider
        if effective_provider == "mock" and (os.environ.get("OPENAI_API_KEY") or os.environ.get("DASHSCOPE_API_KEY")):
            effective_provider = "openai"
        start_repl(
            mode=parsed_args.mode,
            provider=effective_provider,
            model=parsed_args.model,
            api_key=parsed_args.api_key,
            lab_name=parsed_args.lab_name,
            base_url=parsed_args.base_url,
        )
        return 0

    out_dir = Path(parsed_args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    use_color = _supports_color()
    bold = COLOR_BOLD if use_color else ""
    reset = COLOR_RESET if use_color else ""
    cyan = COLOR_CYAN if use_color else ""

    print(f"\n{bold}{'=' * 80}{reset}")
    print(f"{bold}       LangGraph NetOps Autonomous Agent (Version {__version__}){reset}")
    print(f"{bold}{'=' * 80}{reset}")

    # 1. Resolve environment and execution mode
    detector = EnvironmentDetector()
    capabilities = detector.detect()
    resolved_mode = parsed_args.mode

    if resolved_mode == "auto":
        resolved_mode = "live" if capabilities.resolved_mode == ExecutionMode.LIVE else "mock"

    print(f"[{cyan}MODE{reset}]     Requested: {parsed_args.mode.upper()} | Resolved: {resolved_mode.upper()} ({capabilities.reason})")
    print(f"[{cyan}INTENT{reset}]   {parsed_args.intent}")
    print(f"[{cyan}OUTPUT{reset}]   {out_dir}")
    print(f"[{cyan}CONFIG{reset}]   Max Retries: {parsed_args.max_retries} | Auto-Approve: {parsed_args.auto_approve} | Topo-Only: {parsed_args.topo_only}")
    print(f"{'-' * 80}\n")

    # 2. Instantiate LLM provider
    provider_name = parsed_args.provider.lower()
    llm_provider: Any

    if provider_name == "mock":
        llm_provider = create_default_mock_llm(parsed_args.intent)
    elif provider_name in ("qwen", "openai"):
        api_key = parsed_args.api_key or os.environ.get("DASHSCOPE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        base_url = parsed_args.base_url or os.environ.get("OPENAI_BASE_URL")
        model = parsed_args.model or os.environ.get("OPENAI_MODEL") or os.environ.get("QWEN_MODEL") or "qwen-max"
        config = LLMConfig(
            provider_type="openai",
            model_name=model,
            api_key=api_key,
            base_url=base_url,
            max_retries=parsed_args.max_retries,
        )
        llm_provider = QwenOpenAIProvider(config=config)
    elif provider_name == "vllm":
        config = LLMConfig(
            provider_type="vllm",
            model_name=parsed_args.model or "Qwen/Qwen2.5-7B-Instruct",
            base_url=parsed_args.base_url or "http://localhost:8000/v1",
            max_retries=parsed_args.max_retries,
        )
        llm_provider = VLLMProvider(config=config)
    elif provider_name == "ollama":
        config = LLMConfig(
            provider_type="ollama",
            model_name=parsed_args.model or "qwen2.5:7b",
            base_url=parsed_args.base_url or "http://localhost:11434",
            max_retries=parsed_args.max_retries,
        )
        llm_provider = OllamaProvider(config=config)
    else:
        print(f"[ERROR] Unknown provider: {provider_name}", file=sys.stderr)
        return 1

    target_lab_name = parsed_args.lab_name
    if target_lab_name and (target_lab_name.endswith(".yml") or target_lab_name.endswith(".yaml")):
        target_lab_name = Path(target_lab_name).stem
        parsed_args.lab_name = target_lab_name

    lab_adapter: Any
    if resolved_mode == "live":
        if not target_lab_name:
            inv = detector.scan_inventory()
            if inv.recommended_lab and inv.recommended_lab != "netagent-lab":
                target_lab_name = inv.recommended_lab
                parsed_args.lab_name = target_lab_name
                print(f"[{COLOR_CYAN if use_color else ''}AUTO-DISCOVER{reset}] Auto-detected running Containerlab topology: {COLOR_BOLD if use_color else ''}{target_lab_name}{reset}")
        lab_adapter = LiveContainerlabAdapter(lab_name=target_lab_name)
    else:
        lab_adapter = MockContainerlabAdapter()

    # 4. Handle Topo-Only Legacy Deprecation Path
    if parsed_args.topo_only:
        print(f"[{COLOR_YELLOW if use_color else ''}DEPRECATED{reset}] Greenfield topology generation from natural language is deprecated.")
        print("[INFO] Exporting baseline network topology package to output directory...")
        initial_state = create_initial_state(
            user_intent=parsed_args.intent,
            max_retries=parsed_args.max_retries,
            auto_approve=parsed_args.auto_approve,
        )

        from langgraph_netagent.workflow.nodes import create_workflow_nodes
        nodes = create_workflow_nodes(
            llm_provider=llm_provider,
            lab_adapter=lab_adapter,
            export_dir=out_dir,
            auto_approve=parsed_args.auto_approve,
        )

        s1 = nodes["intent_parsing"](initial_state)
        initial_state.update(s1)
        s2 = nodes["topology_generation"](initial_state)
        initial_state.update(s2)
        s3 = nodes["offline_validation"](initial_state)
        initial_state.update(s3)

        try:
            package = FullTopologyPackage.model_validate(initial_state["raw_topology"])
            written = TopologyExporter().export(package=package, export_dir=out_dir)
            print(f"\n{bold}Exported Baseline Topology Files:{reset}")
            for rel, abs_p in written.items():
                print(f"  - {rel} ({abs_p.stat().st_size} bytes)")
        except Exception as exc:
            print(_format_stage("exporter", f"Export failed: {exc}", "error"))
            return 1

        print(f"\n{bold}{'=' * 80}{reset}")
        print(f"{bold}{COLOR_GREEN if use_color else ''}                     TOPO-ONLY GENERATION COMPLETED{reset}")
        print(f"{bold}{'=' * 80}{reset}\n")
        return 0

    # 5. Day-1: Ingest and baseline existing running Containerlab topology (Never deploy private labs in live mode)
    print(f"[{cyan}DAY-1 INGESTION{reset}] Ingesting running topology from Containerlab...")
    insp = lab_adapter.inspect(lab_name=target_lab_name)
    if insp.success and insp.nodes and (not target_lab_name or target_lab_name != insp.lab_name):
        target_lab_name = insp.lab_name
        parsed_args.lab_name = insp.lab_name
    if resolved_mode != "live" and (not insp.success or not insp.nodes):
        # Auto-seed in-memory mock topology for offline CLI testing
        for candidate in [
            Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
            Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
        ]:
            if candidate.exists():
                dep_res = lab_adapter.deploy(candidate)
                if not dep_res.success:
                    print(_format_stage("ingestion", f"Mock deployment failure: {dep_res.error_message}", "error"))
                    return 2
                break
        insp = lab_adapter.inspect(lab_name=parsed_args.lab_name)

    if not insp.success or not insp.nodes:
        print(_format_stage("ingestion", f"No running Containerlab topology detected: {insp.error_message}", "error"))
        return 1
    print(_format_stage("ingestion", f"Successfully ingested {len(insp.nodes)} running nodes from lab '{insp.lab_name}'", "info"))

    # Export ingested topology artifact to output dir
    if out_dir:
        for candidate in [
            Path(__file__).resolve().parent.parent / "clab_output" / "netagent-lab.clab.yml",
            Path(__file__).resolve().parent.parent.parent / "clab_output" / "netagent-lab.clab.yml",
        ]:
            if candidate.exists():
                import shutil
                target_clab = out_dir / f"{insp.lab_name}.clab.yml"
                if not target_clab.exists():
                    shutil.copy(candidate, target_clab)
                break

    # In non-interactive CLI mode without auto-approval, execution halts pending approval
    if not parsed_args.auto_approve and not parsed_args.interactive:
        print(_format_stage("human_approval", "Non-interactive mode without auto-approval: operator approval pending/rejected", "warning"))
        return 1

    # 6. Primary Operational Troubleshooting Workflow (UML Conformance / Harmonized Day-1/2/3)
    from langgraph_netagent.workflow.operational_graph import run_operational_workflow
    from langgraph_netagent.workflow.harmonized_graph import run_harmonized_workflow

    workflow_runner = run_harmonized_workflow if parsed_args.harmonized else run_operational_workflow
    flow_desc = "Harmonized Day-1/2/3" if parsed_args.harmonized else "UML Activity"

    print(f"[{cyan}OPERATIONAL{reset}] Executing {flow_desc} Troubleshooting State Machine...")
    print(f"[{cyan}FLOW{reset}]        Baseline Ingestion -> Telemetry/5-Tuple Extraction -> 2-Stage Diagnosis")
    print(f"[{cyan}FLOW{reset}]        -> AAL Sandbox Validation -> Human Approval -> Live Hot-Patch -> Re-verification")

    if parsed_args.watch:
        print(f"[{cyan}WATCH{reset}] Starting persistent telemetry monitoring loop (interval: {parsed_args.watch_interval}s, max_cycles: {parsed_args.max_watch_cycles or 'infinite'})...")
        session_state = None
        cycles_completed = 0
        last_printed_log_index = 0
        try:
            while True:
                cycles_completed += 1
                if parsed_args.max_watch_cycles is not None and cycles_completed > parsed_args.max_watch_cycles:
                    break

                try:
                    session_state = workflow_runner(
                        llm_provider=llm_provider,
                        lab_adapter=lab_adapter,
                        lab_name=parsed_args.lab_name,
                        max_retries=parsed_args.max_retries,
                        auto_approve=parsed_args.auto_approve,
                        interactive=parsed_args.interactive,
                        initial_state=session_state,
                        watch_mode=False,
                        watch_interval=parsed_args.watch_interval,
                    )
                except Exception as exc:
                    print(_format_stage("runtime", f"Fatal execution failure in watch cycle {cycles_completed}: {exc}", "critical"), file=sys.stderr)
                    return 1

                # Stream newly added execution logs live to terminal
                current_logs = session_state.get("execution_logs", [])
                enc = getattr(sys.stdout, "encoding", None) or "utf-8"
                if len(current_logs) > last_printed_log_index:
                    for log in current_logs[last_printed_log_index:]:
                        raw_msg = log.get("message", "")
                        safe_msg = raw_msg.encode(enc, errors="replace").decode(enc)
                        print("  " + _format_stage(log.get("stage", "stage"), safe_msg, log.get("level", "info")))
                    last_printed_log_index = len(current_logs)

                # Prune execution_logs when exceeding 100 entries
                logs = session_state.get("execution_logs", [])
                if len(logs) > 100:
                    session_state["execution_logs"] = logs[-50:]
                    last_printed_log_index = len(session_state["execution_logs"])

                final_status = session_state.get("status", "unknown")
                if final_status in ("fixed", "re_verified"):
                    print(_format_stage("remediation", f"Closed-loop self-healing successfully completed in watch cycle {cycles_completed}", "info"))

                if final_status == "circuit_broken":
                    print(_format_stage("circuit_breaker", "Circuit breaker tripped in watch loop", "critical"))
                    if session_state.get("error_message"):
                        print(_format_stage("circuit_breaker", f"Reason: {session_state['error_message']}", "error"))
                    print(f"\n{bold}Execution Trace Logs:{reset}")
                    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
                    for log in session_state.get("execution_logs", []):
                        raw_msg = log.get("message", "")
                        safe_msg = raw_msg.encode(enc, errors="replace").decode(enc)
                        print("  " + _format_stage(log.get("stage", "stage"), safe_msg, log.get("level", "info")))
                    final_state = session_state
                    return 2
                elif final_status in ("rejected", "pending_approval") and not parsed_args.auto_approve:
                    print(_format_stage("human_approval", f"Execution halted: plan {final_status}", "warning"))
                    final_state = session_state
                    return 1

                if parsed_args.max_watch_cycles is not None and cycles_completed >= parsed_args.max_watch_cycles:
                    break

                if parsed_args.watch_interval > 0:
                    import time
                    time.sleep(parsed_args.watch_interval)

        except KeyboardInterrupt:
            print("\n[WATCH] Gracefully terminated by operator (Ctrl+C)")
            return 0

        final_state = session_state or {}
    else:
        try:
            final_state = workflow_runner(
                llm_provider=llm_provider,
                lab_adapter=lab_adapter,
                lab_name=parsed_args.lab_name,
                max_retries=parsed_args.max_retries,
                auto_approve=parsed_args.auto_approve,
                interactive=parsed_args.interactive,
            )
        except Exception as exc:
            print(_format_stage("runtime", f"Fatal execution failure: {exc}", "critical"), file=sys.stderr)
            return 1

    # 7. Print Execution Trace Logs
    print(f"\n{bold}Execution Trace Logs:{reset}")
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    for log in final_state.get("execution_logs", []):
        raw_msg = log.get("message", "")
        safe_msg = raw_msg.encode(enc, errors="replace").decode(enc)
        print("  " + _format_stage(log.get("stage", "stage"), safe_msg, log.get("level", "info")))

    # 8. Print Final Status & Health Summary
    final_status = final_state.get("status", "unknown")
    retries = final_state.get("retry_count", 0)

    print(f"\n{bold}{'=' * 80}{reset}")
    if final_status in ("healthy", "fixed", "re_verified", "verified"):
        hdr_color = COLOR_GREEN if use_color else ""
        print(f"{bold}{hdr_color}                     OPERATIONAL NETOPS SUMMARY: {final_status.upper()}{reset}")
    elif final_status == "circuit_broken":
        hdr_color = COLOR_RED if use_color else ""
        print(f"{bold}{hdr_color}                     OPERATIONAL NETOPS SUMMARY: CIRCUIT BROKEN{reset}")
    elif final_status in ("rejected", "pending_approval"):
        hdr_color = COLOR_YELLOW if use_color else ""
        print(f"{bold}{hdr_color}                     OPERATIONAL NETOPS SUMMARY: {final_status.upper()}{reset}")
    else:
        hdr_color = COLOR_YELLOW if use_color else ""
        print(f"{bold}{hdr_color}                     OPERATIONAL NETOPS SUMMARY: {final_status.upper()}{reset}")
    print(f"{bold}{'=' * 80}{reset}")

    print(f"Status:      {final_status}")
    print(f"Retries:     {retries} / {parsed_args.max_retries}")
    if final_state.get("suspect_devices"):
        print(f"Suspects:    {', '.join(final_state['suspect_devices'])}")
    if final_state.get("diagnostic_report"):
        diag = final_state["diagnostic_report"]
        print(f"Root Cause:  {diag.get('root_cause')}")
    if final_state.get("remediation_plan"):
        rem = final_state["remediation_plan"]
        print(f"Remediation: {rem.get('plan_id')} ({len(rem.get('exec_commands', []))} commands on {rem.get('target_entity')})")
    if final_state.get("error_message"):
        print(f"Notice:      {final_state.get('error_message')}")

    print(f"Artifacts:   {out_dir}")
    print(f"{bold}{'=' * 80}{reset}\n")

    if final_status in ("healthy", "fixed", "re_verified", "verified"):
        return 0
    elif final_status == "circuit_broken":
        return 2
    else:
        return 1


def main() -> None:
    """Standard console script entrypoint."""
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
