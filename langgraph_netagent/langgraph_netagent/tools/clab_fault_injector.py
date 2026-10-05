"""Containerlab Fault Injector with Reversible Tokens and Isolation Guard.

Supports:
1. Dual adapter execution: LiveContainerlabAdapter (Docker/WSL) and MockContainerlabAdapter (In-memory).
2. Standard network fault scenarios:
   - LinkDownFault: 'ip link set dev <iface> down', rollback 'ip link set dev <iface> up'
   - RouteDropFault: 'ip route del <prefix>' or FRR BGP neighbor shutdown via vtysh
   - PacketLossFault: 'tc qdisc add dev <iface> root netem loss <loss_pct>%'
   - LatencyFault: 'tc qdisc add dev <iface> root netem delay <delay_ms>ms'
3. Reversible tokens (InjectedFaultToken) with exact inverse rollback commands.
4. Atomic LIFO cleanup with revert_all().
5. Safe scoped execution with fault_context() context manager.
6. LabIsolationGuard integration preventing any mutation to host interfaces, routes, or namespaces.
"""

from __future__ import annotations

from contextlib import contextmanager
import time
from typing import Any, Dict, Iterator, List, Optional, Union
import uuid

from pydantic import BaseModel, ConfigDict, Field

from langgraph_netagent.tools.base import BaseNetworkLabAdapter, CommandResult
from langgraph_netagent.tools.lab_isolation import LabIsolationGuard, LabIsolationViolationError
from langgraph_netagent.tools.mock_engine import MockContainerlabAdapter


class BaseFaultScenario(BaseModel):
    """Abstract base model for fault injection scenarios."""
    model_config = ConfigDict(populate_by_name=True)

    scenario_id: str = Field(default_factory=lambda: f"scen-{uuid.uuid4().hex[:8]}")
    scenario_type: str = Field(..., description="Fault scenario category")
    node: str = Field(..., description="Target node or container")
    description: str = Field(default="", description="Human-readable scenario description")

    @property
    def injection_command(self) -> str:
        raise NotImplementedError

    @property
    def rollback_command(self) -> str:
        raise NotImplementedError


class LinkDownFault(BaseFaultScenario):
    """Simulates a physical or virtual link failure by taking down an interface."""
    scenario_type: str = "link_down"
    interface: str = Field(..., description="Target network interface (e.g. eth1)")

    def __init__(self, node: str, interface: str, **kwargs: Any):
        desc = kwargs.pop("description", f"Link down on {node}:{interface}")
        super().__init__(
            node=node,
            interface=interface,
            scenario_type="link_down",
            description=desc,
            **kwargs,
        )

    @property
    def injection_command(self) -> str:
        return f"ip link set dev {self.interface} down"

    @property
    def rollback_command(self) -> str:
        return f"ip link set dev {self.interface} up"


class RouteDropFault(BaseFaultScenario):
    """Simulates route withdrawal or BGP peering drop."""
    scenario_type: str = "route_drop"
    prefix: str = Field(default="", description="Target destination prefix or network")
    via: Optional[str] = Field(default=None, description="Next hop IP for route restoration")
    dev: Optional[str] = Field(default=None, description="Egress device interface")
    bgp_neighbor: Optional[str] = Field(default=None, description="BGP neighbor interface or IP for FRR shutdown")
    bgp_as: Optional[int] = Field(default=None, description="Autonomous system number for FRR BGP")

    def __init__(
        self,
        node: str,
        prefix: str = "",
        via: Optional[str] = None,
        dev: Optional[str] = None,
        bgp_neighbor: Optional[str] = None,
        bgp_as: Optional[int] = None,
        **kwargs: Any,
    ):
        default_desc = f"BGP shutdown on {node}:{bgp_neighbor}" if bgp_neighbor else f"Route drop {prefix} on {node}"
        desc = kwargs.pop("description", default_desc)
        super().__init__(
            node=node,
            prefix=prefix,
            via=via,
            dev=dev,
            bgp_neighbor=bgp_neighbor,
            bgp_as=bgp_as,
            scenario_type="route_drop",
            description=desc,
            **kwargs,
        )

    @property
    def is_bgp(self) -> bool:
        return bool(self.bgp_neighbor)

    @property
    def injection_command(self) -> str:
        if self.is_bgp:
            as_num = self.bgp_as or 65001
            return f'vtysh -c "conf t" -c "router bgp {as_num}" -c "neighbor {self.bgp_neighbor} shutdown"'

        if self.via and self.dev:
            return f"ip route del {self.prefix} via {self.via} dev {self.dev}"
        if self.via:
            return f"ip route del {self.prefix} via {self.via}"
        if self.dev:
            return f"ip route del {self.prefix} dev {self.dev}"
        return f"ip route del {self.prefix}"

    @property
    def rollback_command(self) -> str:
        if self.is_bgp:
            as_num = self.bgp_as or 65001
            return f'vtysh -c "conf t" -c "router bgp {as_num}" -c "no neighbor {self.bgp_neighbor} shutdown"'

        if self.via and self.dev:
            return f"ip route add {self.prefix} via {self.via} dev {self.dev}"
        if self.via:
            return f"ip route add {self.prefix} via {self.via}"
        if self.dev:
            return f"ip route add {self.prefix} dev {self.dev}"
        return f"ip route add {self.prefix}"


class PacketLossFault(BaseFaultScenario):
    """Simulates network degradation by inducing packet loss via Linux netem."""
    scenario_type: str = "packet_loss"
    interface: str = Field(..., description="Target network interface")
    loss_pct: float = Field(..., ge=0.0, le=100.0, description="Packet loss percentage")

    def __init__(self, node: str, interface: str, loss_pct: float, **kwargs: Any):
        desc = kwargs.pop("description", f"Packet loss {loss_pct}% on {node}:{interface}")
        super().__init__(
            node=node,
            interface=interface,
            loss_pct=float(loss_pct),
            scenario_type="packet_loss",
            description=desc,
            **kwargs,
        )

    @property
    def injection_command(self) -> str:
        pct_formatted = f"{self.loss_pct:g}%"
        return f"tc qdisc add dev {self.interface} root netem loss {pct_formatted}"

    @property
    def rollback_command(self) -> str:
        return f"tc qdisc del dev {self.interface} root"


class LatencyFault(BaseFaultScenario):
    """Simulates WAN delay and jitter via Linux netem."""
    scenario_type: str = "latency"
    interface: str = Field(..., description="Target network interface")
    delay_ms: float = Field(..., gt=0.0, description="Injected latency in milliseconds")
    jitter_ms: Optional[float] = Field(default=None, ge=0.0, description="Optional delay jitter in milliseconds")

    def __init__(
        self,
        node: str,
        interface: str,
        delay_ms: float,
        jitter_ms: Optional[float] = None,
        **kwargs: Any,
    ):
        default_desc = f"Latency {delay_ms}ms" + (f" +/-{jitter_ms}ms" if jitter_ms else "") + f" on {node}:{interface}"
        desc = kwargs.pop("description", default_desc)
        super().__init__(
            node=node,
            interface=interface,
            delay_ms=float(delay_ms),
            jitter_ms=float(jitter_ms) if jitter_ms is not None else None,
            scenario_type="latency",
            description=desc,
            **kwargs,
        )

    @property
    def injection_command(self) -> str:
        delay_spec = f"{self.delay_ms:g}ms"
        if self.jitter_ms is not None and self.jitter_ms > 0:
            delay_spec += f" {self.jitter_ms:g}ms"
        return f"tc qdisc add dev {self.interface} root netem delay {delay_spec}"

    @property
    def rollback_command(self) -> str:
        return f"tc qdisc del dev {self.interface} root"


FaultScenario = Union[LinkDownFault, RouteDropFault, PacketLossFault, LatencyFault, BaseFaultScenario]


class InjectedFaultToken(BaseModel):
    """Receipt token holding rollback metadata for an active injected fault."""
    model_config = ConfigDict(populate_by_name=True)

    token_id: str = Field(default_factory=lambda: f"tok-{uuid.uuid4().hex[:8]}")
    node: str = Field(..., description="Target logical node name")
    container_name: str = Field(..., description="Canonical containerlab container name")
    injection_command: str = Field(..., description="Exact command executed to inject fault")
    rollback_command: str = Field(..., description="Exact command required to reverse fault")
    scenario_type: str = Field(..., description="Scenario type identifier")
    injected_at: float = Field(default_factory=time.time, description="Timestamp of injection")
    active: bool = Field(default=True, description="True while fault is active")
    mock_rule_id: Optional[str] = Field(default=None, description="Internal rule ID in MockEngine if applicable")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Scenario-specific attributes")


class ContainerlabFaultInjector:
    """Orchestrates fault injection and rollback across Live and Mock Containerlab environments."""

    def __init__(
        self,
        adapter: Optional[BaseNetworkLabAdapter] = None,
        isolation_guard: Optional[LabIsolationGuard] = None,
        lab_name: str = "clos5",
    ):
        """Initialize ContainerlabFaultInjector.

        Args:
            adapter: Lab adapter (LiveContainerlabAdapter or MockContainerlabAdapter).
                     Defaults to MockContainerlabAdapter if not provided.
            isolation_guard: Isolation guard enforcing container and host boundaries.
            lab_name: Target containerlab topology name (default 'clos5').
        """
        self.lab_name = lab_name
        self.isolation_guard = isolation_guard or LabIsolationGuard(lab_name=lab_name)
        self.adapter = adapter or MockContainerlabAdapter()

        # Active fault tracking: ID -> token
        self._active_tokens: Dict[str, InjectedFaultToken] = {}
        # LIFO stack of token IDs for deterministic rollback order
        self._token_stack: List[str] = []

    @property
    def active_faults_count(self) -> int:
        """Return number of currently active faults."""
        return len(self._active_tokens)

    def get_active_tokens(self) -> List[InjectedFaultToken]:
        """Return copy of all active fault tokens in injection order."""
        return [self._active_tokens[tid] for tid in self._token_stack if tid in self._active_tokens]

    def inject_fault(self, scenario: FaultScenario) -> InjectedFaultToken:
        """Inject a fault scenario into the target node.

        Enforces:
        1. Target container isolation verification via LabIsolationGuard.
        2. Command safety verification ensuring no host interface or namespace is targeted.
        3. Execution via adapter.
        4. Mock synchronization if adapter is MockContainerlabAdapter.
        5. Token generation storing the exact symmetric rollback command.

        Args:
            scenario: A LinkDownFault, RouteDropFault, PacketLossFault, or LatencyFault instance.

        Returns:
            InjectedFaultToken holding rollback metadata.

        Raises:
            LabIsolationViolationError: If node or command violates lab isolation boundaries.
            RuntimeError: If command execution fails on the adapter.
        """
        node = scenario.node
        canonical_container = self.isolation_guard.resolve_container_name(node)

        inj_cmd = scenario.injection_command
        roll_cmd = scenario.rollback_command

        # Validate command safety through isolation guard
        self.isolation_guard.assert_command_safety(inj_cmd, container_name=node)
        self.isolation_guard.assert_command_safety(roll_cmd, container_name=node)

        # Ensure node exists if mock adapter is in-memory
        self._ensure_mock_node(node)

        # Execute injection command on adapter
        exec_res: CommandResult = self.adapter.exec_command(node_name=node, command=inj_cmd)
        if not exec_res.success:
            raise RuntimeError(
                f"Failed to inject fault on '{node}': {exec_res.stderr or exec_res.stdout or 'non-zero exit code'}"
            )

        # Synchronize with MockEngine if mock adapter is used
        mock_rule_id = self._sync_mock_fault(scenario)

        # Construct and register token
        meta: Dict[str, Any] = {}
        if isinstance(scenario, LinkDownFault):
            meta["interface"] = scenario.interface
        elif isinstance(scenario, RouteDropFault):
            meta["prefix"] = scenario.prefix
            meta["via"] = scenario.via
            meta["bgp_neighbor"] = scenario.bgp_neighbor
        elif isinstance(scenario, PacketLossFault):
            meta["interface"] = scenario.interface
            meta["loss_pct"] = scenario.loss_pct
        elif isinstance(scenario, LatencyFault):
            meta["interface"] = scenario.interface
            meta["delay_ms"] = scenario.delay_ms

        token = InjectedFaultToken(
            node=node,
            container_name=canonical_container,
            injection_command=inj_cmd,
            rollback_command=roll_cmd,
            scenario_type=scenario.scenario_type,
            mock_rule_id=mock_rule_id,
            metadata=meta,
        )

        self._active_tokens[token.token_id] = token
        self._token_stack.append(token.token_id)
        return token

    def revert_fault(self, token: InjectedFaultToken) -> bool:
        """Revert an injected fault using its exact rollback command.

        Args:
            token: The InjectedFaultToken to reverse.

        Returns:
            True if fault was successfully reverted, False if token was not active.

        Raises:
            LabIsolationViolationError: If rollback command violates isolation rules.
            RuntimeError: If rollback execution fails on the adapter.
        """
        if token.token_id not in self._active_tokens or not token.active:
            return False

        # Validate rollback command safety
        self.isolation_guard.assert_command_safety(token.rollback_command, container_name=token.node)

        # Execute rollback command
        res: CommandResult = self.adapter.exec_command(node_name=token.node, command=token.rollback_command)
        if not res.success:
            raise RuntimeError(
                f"Failed to rollback fault '{token.token_id}' on '{token.node}': "
                f"{res.stderr or res.stdout or 'non-zero exit code'}"
            )

        # Clean up mock fault rule if applicable
        self._remove_mock_fault(token)

        token.active = False
        self._active_tokens.pop(token.token_id, None)
        if token.token_id in self._token_stack:
            self._token_stack.remove(token.token_id)

        return True

    def revert_all(self) -> int:
        """Revert all currently active faults in LIFO order (last in, first out).

        Returns:
            Count of faults successfully reverted.
        """
        reverted_count = 0
        # Iterate in reverse LIFO order
        token_ids_to_revert = list(reversed(self._token_stack))

        for tid in token_ids_to_revert:
            token = self._active_tokens.get(tid)
            if token and token.active:
                try:
                    if self.revert_fault(token):
                        reverted_count += 1
                except Exception:
                    # Continue best-effort rollback of remaining tokens
                    pass

        self._active_tokens.clear()
        self._token_stack.clear()
        return reverted_count

    @contextmanager
    def fault_context(self, scenario: FaultScenario) -> Iterator[InjectedFaultToken]:
        """Context manager guaranteeing safe fault injection and automatic rollback.

        Args:
            scenario: The fault scenario to inject.

        Yields:
            The active InjectedFaultToken.
        """
        token = self.inject_fault(scenario)
        try:
            yield token
        finally:
            if token.active:
                self.revert_fault(token)

    def _ensure_mock_node(self, node: str) -> None:
        """Ensure virtual node exists in mock graph if running against MockContainerlabAdapter."""
        mock_eng = getattr(self.adapter, "mock_engine", None)
        if mock_eng is not None and hasattr(mock_eng, "graph"):
            graph = getattr(mock_eng, "graph", None)
            if graph is not None and hasattr(graph, "nodes") and node not in graph.nodes:
                from langgraph_netagent.tools.mock_engine import VirtualNode, VirtualInterface
                vnode = VirtualNode(name=node, kind="frr" if ("leaf" in node or "spine" in node) else "linux")
                for ifc in ["lo", "eth1", "eth2", "eth3", "eth4"]:
                    vnode.add_interface(VirtualInterface(name=ifc, ip_cidr="172.16.1.1/24" if ifc == "eth1" else None))
                graph.nodes[node] = vnode

    def _sync_mock_fault(self, scenario: FaultScenario) -> Optional[str]:
        """Inject corresponding FaultRule into MockEngine if adapter is mock."""
        mock_injector = getattr(self.adapter, "fault_injector", None)
        if not mock_injector or not hasattr(mock_injector, "add_rule"):
            return None

        from langgraph_netagent.tools.fault_injector import FaultRule, FaultType

        rule_id = None
        if isinstance(scenario, LinkDownFault):
            rule = FaultRule(
                fault_type=FaultType.INTERFACE_DOWN,
                target_node=scenario.node,
                target_interface=scenario.interface,
            )
            rule_id = mock_injector.add_rule(rule)

        elif isinstance(scenario, RouteDropFault):
            if scenario.prefix:
                rule = FaultRule(
                    fault_type=FaultType.MISSING_ROUTE,
                    target_node=scenario.node,
                    target_ip_or_prefix=scenario.prefix,
                )
                rule_id = mock_injector.add_rule(rule)

        elif isinstance(scenario, PacketLossFault):
            rule = FaultRule(
                fault_type=FaultType.INTERMITTENT_LOSS,
                target_node=scenario.node,
                target_interface=scenario.interface,
                loss_pct=scenario.loss_pct,
            )
            rule_id = mock_injector.add_rule(rule)

        elif isinstance(scenario, LatencyFault):
            # Represent latency via mock fault rule with 0% loss to tag interface
            rule = FaultRule(
                fault_type=FaultType.INTERMITTENT_LOSS,
                target_node=scenario.node,
                target_interface=scenario.interface,
                loss_pct=0.0,
            )
            rule_id = mock_injector.add_rule(rule)

        return rule_id if isinstance(rule_id, str) else None

    def _remove_mock_fault(self, token: InjectedFaultToken) -> None:
        """Remove mock rule from MockEngine if rule ID is present."""
        if not token.mock_rule_id or not isinstance(token.mock_rule_id, str):
            return

        mock_injector = getattr(self.adapter, "fault_injector", None)
        if mock_injector and hasattr(mock_injector, "remove_rule"):
            mock_injector.remove_rule(token.mock_rule_id)

