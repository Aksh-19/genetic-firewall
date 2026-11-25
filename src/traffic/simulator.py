import json
import random
import socket
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from scapy.all import Ether, IP, TCP, UDP, wrpcap

from src.traffic.buffer import RollingTrafficBuffer

console = Console()

SERVER_IP = "192.168.1.100"
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
TRAFFIC_PHASES = ["NORMAL", "SYN_FLOOD", "NORMAL", "PORT_SCAN", "UDP_FLOOD"]


def generate_random_ip() -> str:
    """Helper function to generate a fake random IP address (e.g., 12.34.56.78)."""
    return (
        f"{random.randint(1, 254)}.{random.randint(0, 254)}."
        f"{random.randint(0, 254)}.{random.randint(1, 254)}"
    )


def make_legit_packet() -> Dict[str, Any]:
    """Builds a realistic benign HTTP, HTTPS, or DNS packet."""
    client_subnet = random.choice(["192.168.1", "10.0.1", "10.0.2"])
    src_ip = f"{client_subnet}.{random.randint(2, 250)}"
    dst_port = random.choices([80, 443, 53], weights=[0.35, 0.50, 0.15], k=1)[0]
    protocol = "TCP" if dst_port in (80, 443) else "UDP"
    flags = (
        random.choices(["A", "PA", "FA", "S"], weights=[0.40, 0.35, 0.15, 0.10], k=1)[0]
        if protocol == "TCP"
        else ""
    )
    return {
        "src_ip": src_ip,
        "dst_ip": SERVER_IP,
        "src_port": random.randint(1024, 65535),
        "dst_port": dst_port,
        "protocol": protocol,
        "flags": flags,
        "timestamp": time.time(),
    }


def make_syn_flood_packet(subnet_prefix: str = "203.0.113") -> Dict[str, Any]:
    """Builds a malicious pure-SYN packet targeting web port 80."""
    return {
        "src_ip": f"{subnet_prefix}.{random.randint(1, 254)}",
        "dst_ip": SERVER_IP,
        "src_port": random.randint(1024, 65535),
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
        "timestamp": time.time(),
    }


def make_port_scan_packet(scanner_ip: str = "198.51.100.55") -> Dict[str, Any]:
    """Builds a malicious TCP SYN probe hitting varied service ports."""
    return {
        "src_ip": scanner_ip,
        "dst_ip": SERVER_IP,
        "src_port": random.randint(30000, 65000),
        "dst_port": random.choice(SCAN_PORTS),
        "protocol": "TCP",
        "flags": "S",
        "timestamp": time.time(),
    }


def make_udp_flood_packet(subnet_prefix: str = "192.0.2") -> Dict[str, Any]:
    """Builds a malicious high-volume UDP flood packet."""
    return {
        "src_ip": f"{subnet_prefix}.{random.randint(1, 254)}",
        "dst_ip": SERVER_IP,
        "src_port": random.randint(1024, 65535),
        "dst_port": random.choice([80, 443, 53, 8080]),
        "protocol": "UDP",
        "flags": "",
        "timestamp": time.time(),
    }


def create_dataset(
    num_packets: int = 1000, attack_ratio: float = 0.3
) -> Tuple[List[Dict[str, Any]], List[Any]]:
    """
    Generates a static mix of good and bad network packets (Phase 1 deliverable).
    num_packets: Total number of postcards to create.
    attack_ratio: 0.3 means 30% of them will be bad (attacks).
    """
    packets: List[Dict[str, Any]] = []
    scapy_packets: List[Any] = []

    num_attack = int(num_packets * attack_ratio)
    num_legit = num_packets - num_attack

    for _ in range(num_legit):
        src_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53])
        flags = random.choice(["S", "A", "PA", "FA"])
        protocol = "TCP" if dst_port in [80, 443] else "UDP"

        packet_dict = {
            "src_ip": src_ip,
            "dst_ip": SERVER_IP,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "label": "LEGIT",
        }
        packets.append(packet_dict)

        if protocol == "TCP":
            pkt = (
                Ether()
                / IP(src=src_ip, dst=SERVER_IP)
                / TCP(sport=src_port, dport=dst_port, flags=flags)
            )
        else:
            pkt = (
                Ether()
                / IP(src=src_ip, dst=SERVER_IP)
                / UDP(sport=src_port, dport=dst_port)
            )
        scapy_packets.append(pkt)

    for _ in range(num_attack):
        src_ip = generate_random_ip()
        src_port = random.randint(1024, 65535)
        dst_port = 80
        flags = "S"
        protocol = "TCP"

        packet_dict = {
            "src_ip": src_ip,
            "dst_ip": SERVER_IP,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "label": "MALICIOUS",
        }
        packets.append(packet_dict)

        pkt = (
            Ether()
            / IP(src=src_ip, dst=SERVER_IP)
            / TCP(sport=src_port, dport=dst_port, flags=flags)
        )
        scapy_packets.append(pkt)

    combined = list(zip(packets, scapy_packets))
    random.shuffle(combined)
    packets_t, scapy_t = zip(*combined)

    return list(packets_t), list(scapy_t)


class LiveTrafficStream:
    """
    Background producer thread feeding live simulated packets into a
    RollingTrafficBuffer, cycling through normal and attack phases and
    optionally accepting external attack bursts over localhost UDP.
    """

    def __init__(
        self,
        buffer: RollingTrafficBuffer,
        legit_pps: float = 20.0,
        attack_pps: float = 80.0,
        phase_duration: float = 10.0,
        auto_cycle: bool = True,
        udp_listen_port: Optional[int] = None,
    ):
        self.buffer = buffer
        self.legit_pps = legit_pps
        self.attack_pps = attack_pps
        self.phase_duration = phase_duration
        self.auto_cycle = auto_cycle
        self.udp_listen_port = udp_listen_port

        self._phase_index = 0
        self._current_phase = TRAFFIC_PHASES[0]
        self._phase_lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._udp_thread: Optional[threading.Thread] = None
        self._external_attack_until = 0.0
        self._external_phase = ""

    @property
    def current_phase(self) -> str:
        with self._phase_lock:
            if time.time() < self._external_attack_until and self._external_phase:
                return f"EXTERNAL:{self._external_phase}"
            return self._current_phase

    def set_phase(self, phase: str) -> None:
        with self._phase_lock:
            self._current_phase = phase

    def inject_burst(self, attack_type: str, count: int = 100) -> None:
        """Immediately injects a burst of packets into the rolling buffer."""
        builders = {
            "syn_flood": make_syn_flood_packet,
            "port_scan": make_port_scan_packet,
            "udp_flood": make_udp_flood_packet,
        }
        builder = builders.get(attack_type.lower().replace("-", "_"), make_syn_flood_packet)
        batch = [builder() for _ in range(count)]
        self.buffer.add_packets(batch, auto_label=True)

    def _run_udp_listener(self, stop_event: threading.Event) -> None:
        if self.udp_listen_port is None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.25)
        try:
            sock.bind(("127.0.0.1", self.udp_listen_port))
            while not stop_event.is_set():
                try:
                    data, _ = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    pkt = json.loads(data.decode("utf-8"))
                    pkt["timestamp"] = time.time()
                    self.buffer.add_packet(pkt, auto_label=True)
                    with self._phase_lock:
                        self._external_attack_until = time.time() + 3.0
                        self._external_phase = str(pkt.get("attack_type", "BURST"))
                except (ValueError, UnicodeDecodeError):
                    continue
        finally:
            sock.close()

    def _run_stream(self, stop_event: threading.Event) -> None:
        tick = 0.1
        last_switch = time.monotonic()

        while not stop_event.is_set():
            now = time.monotonic()
            if self.auto_cycle and (now - last_switch) >= self.phase_duration:
                self._phase_index = (self._phase_index + 1) % len(TRAFFIC_PHASES)
                self.set_phase(TRAFFIC_PHASES[self._phase_index])
                last_switch = now

            phase = self.current_phase
            legit_count = max(1, int(round(self.legit_pps * tick)))
            batch = [make_legit_packet() for _ in range(legit_count)]

            if phase == "SYN_FLOOD":
                atk_count = max(1, int(round(self.attack_pps * tick)))
                batch.extend(make_syn_flood_packet() for _ in range(atk_count))
            elif phase == "PORT_SCAN":
                atk_count = max(1, int(round(self.attack_pps * tick)))
                batch.extend(make_port_scan_packet() for _ in range(atk_count))
            elif phase == "UDP_FLOOD":
                atk_count = max(1, int(round(self.attack_pps * tick)))
                batch.extend(make_udp_flood_packet() for _ in range(atk_count))

            random.shuffle(batch)
            self.buffer.add_packets(batch, auto_label=True)
            stop_event.wait(tick)

    def start(self, stop_event: threading.Event) -> None:
        """Starts the stream (and optional UDP listener) in background threads."""
        self._thread = threading.Thread(
            target=self._run_stream, args=(stop_event,), daemon=True, name="traffic-stream"
        )
        self._thread.start()

        if self.udp_listen_port is not None:
            self._udp_thread = threading.Thread(
                target=self._run_udp_listener,
                args=(stop_event,),
                daemon=True,
                name="udp-attack-listener",
            )
            self._udp_thread.start()

    def join(self, timeout: float = 2.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        if self._udp_thread is not None and self._udp_thread.is_alive():
            self._udp_thread.join(timeout=timeout)


def send_external_attack(
    attack_type: str = "syn_flood",
    count: int = 300,
    host: str = "127.0.0.1",
    port: int = 9999,
    delay: float = 0.005,
) -> int:
    """
    Sends simulated attack packets over localhost UDP to a running live firewall
    instance (so a second terminal can launch attacks without sudo).
    """
    builders = {
        "syn_flood": make_syn_flood_packet,
        "port_scan": make_port_scan_packet,
        "udp_flood": make_udp_flood_packet,
    }
    normalized = attack_type.lower().replace("-", "_")
    builder = builders.get(normalized, make_syn_flood_packet)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    try:
        for _ in range(count):
            pkt = builder()
            pkt["attack_type"] = normalized.upper()
            sock.sendto(json.dumps(pkt).encode("utf-8"), (host, port))
            sent += 1
            if delay > 0:
                time.sleep(delay)
    finally:
        sock.close()
    return sent


if __name__ == "__main__":
    console.print("[bold cyan]Generating Traffic Dataset...[/bold cyan]")
    dataset_dicts, dataset_pcap = create_dataset(1000, 0.3)

    with open("dataset.json", "w") as f:
        json.dump(dataset_dicts, f, indent=4)

    wrpcap("dataset.pcap", dataset_pcap)

    console.print("[bold green]Done! Generated 1000 packets.[/bold green]")
    console.print(
        "Saved to [bold yellow]dataset.json[/bold yellow] and "
        "[bold yellow]dataset.pcap[/bold yellow]"
    )
