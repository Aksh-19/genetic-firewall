import threading
import time
from typing import Any, Dict, Optional

from rich.console import Console
from scapy.all import IP, TCP, UDP, sniff

from src.traffic.buffer import RollingTrafficBuffer

console = Console()


def scapy_packet_to_dict(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Extracts normalized firewall-relevant fields from a raw Scapy packet.
    Returns None if the packet does not carry an IPv4/IPv6 IP layer.
    """
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if TCP in packet:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(packet[TCP].sport),
            "dst_port": int(packet[TCP].dport),
            "protocol": "TCP",
            "flags": str(packet[TCP].flags),
            "timestamp": time.time(),
        }
    if UDP in packet:
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(packet[UDP].sport),
            "dst_port": int(packet[UDP].dport),
            "protocol": "UDP",
            "flags": "",
            "timestamp": time.time(),
        }
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "OTHER",
        "flags": "",
        "timestamp": time.time(),
    }


class LiveSniffer:
    """
    Background Scapy sniffer thread that captures live packets from a network
    interface (requires root/sudo on macOS/Linux) and feeds RollingTrafficBuffer.
    """

    def __init__(
        self, buffer: RollingTrafficBuffer, iface: Optional[str] = None
    ):
        self.buffer = buffer
        self.iface = iface
        self._thread: Optional[threading.Thread] = None
        self.error: Optional[str] = None

    def _on_packet(self, packet: Any) -> None:
        pkt_dict = scapy_packet_to_dict(packet)
        if pkt_dict is not None:
            self.buffer.add_packet(pkt_dict, auto_label=True)

    def _sniff_loop(self, stop_event: threading.Event) -> None:
        try:
            sniff(
                iface=self.iface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: stop_event.is_set(),
                timeout=1,
            )
            while not stop_event.is_set():
                sniff(
                    iface=self.iface,
                    prn=self._on_packet,
                    store=False,
                    stop_filter=lambda _: stop_event.is_set(),
                    timeout=1,
                )
        except Exception as exc:
            self.error = str(exc)

    def start(self, stop_event: threading.Event) -> None:
        self._thread = threading.Thread(
            target=self._sniff_loop,
            args=(stop_event,),
            daemon=True,
            name="scapy-sniffer",
        )
        self._thread.start()

    def join(self, timeout: float = 2.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)


def packet_callback(packet: Any) -> None:
    """
    This function gets called every time our standalone sniffer catches a packet.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")

        if TCP in packet:
            flags = packet[TCP].flags
            console.print(
                f"[green]Caught Packet:[/green] {src_ip} -> {dst_ip} | "
                f"[yellow]{protocol}[/yellow] | Flags: [red]{flags}[/red]"
            )
        else:
            console.print(
                f"[green]Caught Packet:[/green] {src_ip} -> {dst_ip} | "
                f"[yellow]{protocol}[/yellow]"
            )


def start_sniffing(packet_count: int = 15) -> None:
    """Starts listening to the network for packet_count packets."""
    console.print(
        f"[bold cyan]Starting sniffer... listening for the next {packet_count} packets![/bold cyan]"
    )
    sniff(prn=packet_callback, count=packet_count, store=False)
    console.print("[bold green]Sniffing complete![/bold green]")


if __name__ == "__main__":
    start_sniffing(15)
