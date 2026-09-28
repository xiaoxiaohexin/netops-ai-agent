"""Live Baseline Collector for Day-2 Operations.

Reads the current running state of all nodes in a deployed Containerlab
topology: container status, running configs, IP addresses, and routes.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from langgraph_netagent.tools.base import BaseNetworkLabAdapter, LabInspectionResult


class BaselineCollector:
    """Collects a structured baseline snapshot from a live Containerlab network."""

    @classmethod
    def collect(
        cls,
        adapter: BaseNetworkLabAdapter,
        lab_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Collect full baseline from all running lab nodes.

        Returns:
            Dictionary containing:
            - timestamp: ISO timestamp
            - lab_name: lab name
            - nodes: dict of node_name -> node baseline
            - topology_path: ordered list of nodes (inferred from inspection)
            - node_kinds: dict of node_name -> device kind
        """
        # 1. Inspect running containers
        inspection = adapter.inspect(lab_name=lab_name)
        if not inspection.success:
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "lab_name": lab_name or "unknown",
                "nodes": {},
                "topology_path": [],
                "node_kinds": {},
                "error": inspection.error_message or "Inspection failed",
            }

        nodes_baseline: Dict[str, Dict[str, Any]] = {}
        node_kinds: Dict[str, str] = {}

        for node_state in inspection.nodes:
            name = node_state.name
            kind = cls._detect_kind(node_state.kind, node_state.image)
            node_kinds[name] = kind

            node_data: Dict[str, Any] = {
                "container_id": node_state.container_id,
                "image": node_state.image,
                "kind": kind,
                "state": node_state.state,
                "mgmt_ipv4": node_state.ipv4_address,
            }

            # 2. Collect running config per device type
            try:
                node_data["running_config"] = cls._get_running_config(adapter, name, kind)
            except Exception as e:
                node_data["running_config"] = f"ERROR: {e}"

            # 3. Collect IP addresses
            try:
                ip_result = adapter.exec_command(node_name=name, command="ip addr show", timeout=10)
                node_data["ip_addr"] = ip_result.stdout if ip_result.success else ip_result.stderr
            except Exception as e:
                node_data["ip_addr"] = f"ERROR: {e}"

            # 4. Collect route table
            try:
                if kind == "frr":
                    rt_result = adapter.exec_command(node_name=name, command="vtysh -c 'show ip route'", timeout=10)
                elif kind == "srl":
                    rt_result = adapter.exec_command(node_name=name, command="sr_cli 'show network-instance default route-table'", timeout=10)
                else:
                    rt_result = adapter.exec_command(node_name=name, command="ip route show", timeout=10)
                node_data["route_table"] = rt_result.stdout if rt_result.success else rt_result.stderr
            except Exception as e:
                node_data["route_table"] = f"ERROR: {e}"

            nodes_baseline[name] = node_data

        # 5. Infer topology path from node ordering
        topology_path = cls._infer_topology_path(nodes_baseline, node_kinds)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "lab_name": lab_name or "unknown",
            "nodes": nodes_baseline,
            "topology_path": topology_path,
            "node_kinds": node_kinds,
        }

    @classmethod
    def _detect_kind(cls, kind: str, image: str) -> str:
        """Detect device kind from container metadata."""
        k = (kind or "").lower()
        img = (image or "").lower()
        if "frr" in k or "frr" in img or "frrouting" in img:
            return "frr"
        elif "srl" in k or "srlinux" in k or "srl" in img or "srlinux" in img:
            return "srl"
        return "linux"

    @classmethod
    def _get_running_config(cls, adapter: BaseNetworkLabAdapter, node: str, kind: str) -> str:
        """Retrieve running configuration from a node."""
        if kind == "frr":
            result = adapter.exec_command(node_name=node, command="vtysh -c 'show running-config'", timeout=10)
        elif kind == "srl":
            result = adapter.exec_command(node_name=node, command="sr_cli 'info flat'", timeout=10)
        else:
            # Linux PCs: combine network config
            result = adapter.exec_command(node_name=node, command="ip addr show; echo '---'; ip route show", timeout=10)
        return result.stdout if result.success else f"ERROR: {result.stderr}"

    @classmethod
    def _infer_topology_path(
        cls,
        nodes: Dict[str, Dict[str, Any]],
        node_kinds: Dict[str, str],
    ) -> List[str]:
        """Infer an ordered topology path.

        Heuristic: PCs at endpoints, routers in middle, ordered by name.
        For our lab: [pc1, frr1, srl1, pc2]
        """
        pcs = sorted([n for n, k in node_kinds.items() if k == "linux"])
        routers = sorted([n for n, k in node_kinds.items() if k in ("frr", "srl")])
        if len(pcs) == 2:
            return [pcs[0]] + routers + [pcs[1]]
        return list(nodes.keys()) if nodes else (pcs + routers)
