#!/bin/bash
# ==============================================================================
# Realistic Network Environment Profile for Clos5 Containerlab Topology
# Simulates physical WAN edge constraints, packet buffers, queue limits & latency
# ==============================================================================

set -e

ACTION="${1:-apply}"

WAN_RATE="50mbit"
WAN_DELAY="8ms"
WAN_JITTER="1ms"
WAN_BURST="16kbit"
WAN_LIMIT="32k"

DC_CORE_RATE="200mbit"
DC_CORE_DELAY="0.5ms"
DC_CORE_BURST="64kbit"
DC_CORE_LIMIT="128k"

clean_rules() {
    echo "[*] Cleaning up traffic control rules on all network devices..."
    docker exec clab-clos5-ext-router tc qdisc del dev eth1 root 2>/dev/null || true
    docker exec clab-clos5-ext-router tc qdisc del dev eth2 root 2>/dev/null || true
    docker exec clab-clos5-dc-egress tc qdisc del dev eth1 root 2>/dev/null || true
    docker exec clab-clos5-dc-egress tc qdisc del dev eth2 root 2>/dev/null || true
    docker exec clab-clos5-superspine2 tc qdisc del dev eth3 root 2>/dev/null || true
    echo "[+] Reset to default ideal virtual network (unlimited bandwidth, 0ms RTT)."
}

apply_rules() {
    clean_rules >/dev/null 2>&1 || true

    echo "[1/3] Applying WAN link constraints on ext-router..."
    # ext-router eth1 (facing DC egress 203.0.113.0/24)
    docker exec clab-clos5-ext-router tc qdisc add dev eth1 root handle 1: netem delay ${WAN_DELAY} ${WAN_JITTER}
    docker exec clab-clos5-ext-router tc qdisc add dev eth1 parent 1: handle 10: tbf rate ${WAN_RATE} burst ${WAN_BURST} limit ${WAN_LIMIT}

    # ext-router eth2 (facing external attacker 192.168.100.0/24)
    docker exec clab-clos5-ext-router tc qdisc add dev eth2 root handle 1: netem delay ${WAN_DELAY} ${WAN_JITTER}
    docker exec clab-clos5-ext-router tc qdisc add dev eth2 parent 1: handle 10: tbf rate 100mbit burst 32kbit limit 64k

    echo "[2/3] Applying WAN edge and DC Gateway constraints on dc-egress..."
    # dc-egress eth2 (WAN ingress from ext-router)
    docker exec clab-clos5-dc-egress tc qdisc add dev eth2 root handle 1: netem delay ${WAN_DELAY} ${WAN_JITTER}
    docker exec clab-clos5-dc-egress tc qdisc add dev eth2 parent 1: handle 10: tbf rate ${WAN_RATE} burst ${WAN_BURST} limit ${WAN_LIMIT}

    # dc-egress eth1 (DC core uplink to superspine2 172.16.254.0/24)
    docker exec clab-clos5-dc-egress tc qdisc add dev eth1 root handle 1: netem delay ${DC_CORE_DELAY}
    docker exec clab-clos5-dc-egress tc qdisc add dev eth1 parent 1: handle 10: tbf rate ${DC_CORE_RATE} burst ${DC_CORE_BURST} limit ${DC_CORE_LIMIT}

    echo "[3/3] Applying Core Fabric constraints on superspine2..."
    docker exec clab-clos5-superspine2 tc qdisc add dev eth3 root handle 1: netem delay ${DC_CORE_DELAY}
    docker exec clab-clos5-superspine2 tc qdisc add dev eth3 parent 1: handle 10: tbf rate ${DC_CORE_RATE} burst ${DC_CORE_BURST} limit ${DC_CORE_LIMIT}

    echo ""
    echo "================================================================="
    echo "[+] Realistic Network Environment Established Successfully!"
    echo "    - WAN Link Bandwidth: ${WAN_RATE} (Physical bottleneck simulation)"
    echo "    - WAN Round-Trip Latency: ~16ms-20ms (Delay: ${WAN_DELAY} +- ${WAN_JITTER})"
    echo "    - Hardware Buffer Depth: ${WAN_LIMIT} (Tail-drop queue on congestion)"
    echo "    - DC Internal Core Uplink: ${DC_CORE_RATE} (Delay: ${DC_CORE_DELAY})"
    echo "================================================================="
}

show_status() {
    echo "=== ext-router (eth1: DC WAN Uplink) ==="
    docker exec clab-clos5-ext-router tc -s qdisc show dev eth1
    echo ""
    echo "=== dc-egress (eth2: DC Ingress Gateway) ==="
    docker exec clab-clos5-dc-egress tc -s qdisc show dev eth2
    echo ""
    echo "=== Baseline RTT from Attacker ==="
    docker exec clab-clos5-attacker ping -c 3 -W 1 203.0.113.10
}

case "$ACTION" in
    apply)
        apply_rules
        ;;
    clean|reset)
        clean_rules
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {apply|clean|status}"
        exit 1
        ;;
esac
