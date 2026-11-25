from collections import defaultdict, deque
import ipaddress
import threading
import time
from typing import Any, Deque, Dict, List, Optional, Tuple


def _subnet_24(ip_str: str) -> str:
    """Extracts the /24 subnet prefix for IPv4 addresses (e.g. '203.0.113.0/24')."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            net = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            return str(net)
    except ValueError:
        pass
    return ip_str


class HeuristicLabeler:
    """
    Labels live network packets as 'LEGIT' or 'MALICIOUS' without peeking at any
    simulator secret tags, using sliding-window behavioral heuristics:
      1. SYN Flood: Many pure SYN (no ACK) packets from one IP or /24 subnet.
      2. Port Scan: One IP probing many distinct destination ports rapidly.
      3. UDP Flood: High-volume UDP burst from one IP or /24 subnet.
    """

    def __init__(
        self,
        window_seconds: float = 5.0,
        syn_threshold: int = 10,
        subnet_syn_threshold: int = 18,
        port_scan_threshold: int = 6,
        udp_threshold: int = 15,
        subnet_udp_threshold: int = 20,
    ):
        self.window_seconds = window_seconds
        self.syn_threshold = syn_threshold
        self.subnet_syn_threshold = subnet_syn_threshold
        self.port_scan_threshold = port_scan_threshold
        self.udp_threshold = udp_threshold
        self.subnet_udp_threshold = subnet_udp_threshold

        self._lock = threading.Lock()
        self._syn_by_ip: Dict[str, Deque[float]] = defaultdict(deque)
        self._syn_by_subnet: Dict[str, Deque[float]] = defaultdict(deque)
        self._ports_by_ip: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._udp_by_ip: Dict[str, Deque[float]] = defaultdict(deque)
        self._udp_by_subnet: Dict[str, Deque[float]] = defaultdict(deque)

    def _prune_timestamps(self, dq: Deque[float], cutoff: float) -> None:
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _prune_port_events(
        self, dq: Deque[Tuple[float, int]], cutoff: float
    ) -> None:
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def label_packet(
        self, packet: Dict[str, Any], now: Optional[float] = None
    ) -> str:
        """
        Records a newly arrived packet into sliding-window behavioral counters
        and returns 'LEGIT' or 'MALICIOUS'.
        """
        ts = float(packet.get("timestamp", time.time())) if now is None else now
        cutoff = ts - self.window_seconds

        src_ip = str(packet.get("src_ip", ""))
        subnet = _subnet_24(src_ip)
        protocol = packet.get("protocol", "")
        flags = str(packet.get("flags", ""))
        dst_port = packet.get("dst_port")

        with self._lock:
            is_pure_syn = protocol == "TCP" and "S" in flags and "A" not in flags
            if is_pure_syn:
                ip_syns = self._syn_by_ip[src_ip]
                ip_syns.append(ts)
                self._prune_timestamps(ip_syns, cutoff)

                sub_syns = self._syn_by_subnet[subnet]
                sub_syns.append(ts)
                self._prune_timestamps(sub_syns, cutoff)

                if dst_port is not None:
                    ip_ports = self._ports_by_ip[src_ip]
                    ip_ports.append((ts, int(dst_port)))
                    self._prune_port_events(ip_ports, cutoff)

                distinct_ports = len({p for _, p in self._ports_by_ip[src_ip]})
                if (
                    len(ip_syns) >= self.syn_threshold
                    or len(sub_syns) >= self.subnet_syn_threshold
                    or distinct_ports >= self.port_scan_threshold
                ):
                    return "MALICIOUS"

            elif protocol == "TCP" and dst_port is not None:
                # Track non-SYN TCP probes too if scanning ports rapidly
                ip_ports = self._ports_by_ip[src_ip]
                ip_ports.append((ts, int(dst_port)))
                self._prune_port_events(ip_ports, cutoff)
                if len({p for _, p in ip_ports}) >= self.port_scan_threshold:
                    return "MALICIOUS"

            elif protocol == "UDP":
                ip_udps = self._udp_by_ip[src_ip]
                ip_udps.append(ts)
                self._prune_timestamps(ip_udps, cutoff)

                sub_udps = self._udp_by_subnet[subnet]
                sub_udps.append(ts)
                self._prune_timestamps(sub_udps, cutoff)

                if (
                    len(ip_udps) >= self.udp_threshold
                    or len(sub_udps) >= self.subnet_udp_threshold
                ):
                    return "MALICIOUS"

        return "LEGIT"

    def label_window(self, packets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Re-evaluates a batch/snapshot of recent packets collectively so even
        the earliest packets of an active burst get tagged 'MALICIOUS'.
        Returns new dicts with updated 'label' fields.
        """
        if not packets:
            return []

        latest_ts = max(float(p.get("timestamp", 0.0)) for p in packets)
        cutoff = latest_ts - self.window_seconds if latest_ts > 0 else -1.0

        syn_ip_counts: Dict[str, int] = defaultdict(int)
        syn_subnet_counts: Dict[str, int] = defaultdict(int)
        ports_by_ip: Dict[str, set] = defaultdict(set)
        udp_ip_counts: Dict[str, int] = defaultdict(int)
        udp_subnet_counts: Dict[str, int] = defaultdict(int)

        for pkt in packets:
            ts = float(pkt.get("timestamp", latest_ts))
            if cutoff > 0 and ts < cutoff:
                continue
            src_ip = str(pkt.get("src_ip", ""))
            subnet = _subnet_24(src_ip)
            protocol = pkt.get("protocol", "")
            flags = str(pkt.get("flags", ""))
            dst_port = pkt.get("dst_port")

            if protocol == "TCP":
                if dst_port is not None:
                    ports_by_ip[src_ip].add(int(dst_port))
                if "S" in flags and "A" not in flags:
                    syn_ip_counts[src_ip] += 1
                    syn_subnet_counts[subnet] += 1
            elif protocol == "UDP":
                udp_ip_counts[src_ip] += 1
                udp_subnet_counts[subnet] += 1

        labeled: List[Dict[str, Any]] = []
        for pkt in packets:
            copy_pkt = dict(pkt)
            src_ip = str(copy_pkt.get("src_ip", ""))
            subnet = _subnet_24(src_ip)
            protocol = copy_pkt.get("protocol", "")
            flags = str(copy_pkt.get("flags", ""))

            is_malicious = False
            if protocol == "TCP":
                if len(ports_by_ip[src_ip]) >= self.port_scan_threshold:
                    is_malicious = True
                elif "S" in flags and "A" not in flags:
                    if (
                        syn_ip_counts[src_ip] >= self.syn_threshold
                        or syn_subnet_counts[subnet] >= self.subnet_syn_threshold
                    ):
                        is_malicious = True
            elif protocol == "UDP":
                if (
                    udp_ip_counts[src_ip] >= self.udp_threshold
                    or udp_subnet_counts[subnet] >= self.subnet_udp_threshold
                ):
                    is_malicious = True

            copy_pkt["label"] = "MALICIOUS" if is_malicious else "LEGIT"
            labeled.append(copy_pkt)

        return labeled
