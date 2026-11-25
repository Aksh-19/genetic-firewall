import threading
import time
from scapy.all import IP, TCP, UDP

from src.traffic.buffer import RollingTrafficBuffer
from src.traffic.labeler import HeuristicLabeler
from src.traffic.simulator import (
    LiveTrafficStream,
    create_dataset,
    make_legit_packet,
    make_port_scan_packet,
    make_syn_flood_packet,
    make_udp_flood_packet,
)
from src.traffic.sniffer import scapy_packet_to_dict


def test_create_dataset_ratios():
    dicts, pcaps = create_dataset(num_packets=100, attack_ratio=0.3)
    assert len(dicts) == 100
    assert len(pcaps) == 100
    malicious = sum(1 for p in dicts if p["label"] == "MALICIOUS")
    legit = sum(1 for p in dicts if p["label"] == "LEGIT")
    assert malicious == 30
    assert legit == 70


def test_heuristic_labeler_legit_and_syn_flood():
    labeler = HeuristicLabeler(
        window_seconds=5.0, syn_threshold=5, subnet_syn_threshold=6
    )

    # Normal ACK/PA packets from distinct normal users stay LEGIT
    for i in range(10):
        pkt = {
            "src_ip": f"10.0.1.{i + 1}",
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "PA",
            "timestamp": 100.0 + i * 0.1,
        }
        assert labeler.label_packet(pkt, now=100.0 + i * 0.1) == "LEGIT"

    # Rapid SYN flood across a /24 subnet crosses threshold
    labels = []
    for i in range(10):
        pkt = make_syn_flood_packet("203.0.113")
        labels.append(labeler.label_packet(pkt, now=105.0 + i * 0.05))
    assert "MALICIOUS" in labels
    assert labels[-1] == "MALICIOUS"


def test_heuristic_labeler_port_scan_and_udp_flood():
    labeler = HeuristicLabeler(
        window_seconds=5.0, port_scan_threshold=5, udp_threshold=6
    )

    # Port scan from one IP touching 6 distinct ports
    scan_labels = []
    for port in [21, 22, 23, 80, 443, 8080]:
        pkt = {
            "src_ip": "198.51.100.55",
            "dst_port": port,
            "protocol": "TCP",
            "flags": "S",
        }
        scan_labels.append(labeler.label_packet(pkt, now=200.0))
    assert scan_labels[-1] == "MALICIOUS"

    # UDP flood from one IP
    udp_labels = []
    for _ in range(8):
        pkt = {
            "src_ip": "192.0.2.10",
            "dst_port": 80,
            "protocol": "UDP",
            "flags": "",
        }
        udp_labels.append(labeler.label_packet(pkt, now=200.0))
    assert udp_labels[-1] == "MALICIOUS"


def test_heuristic_label_window_retroactive():
    labeler = HeuristicLabeler(
        window_seconds=5.0, syn_threshold=5, subnet_syn_threshold=5
    )
    now = time.time()
    packets = [
        {
            "src_ip": "203.0.113.10",
            "dst_port": 80,
            "protocol": "TCP",
            "flags": "S",
            "timestamp": now,
        }
        for _ in range(6)
    ]
    packets.append(
        {
            "src_ip": "10.0.1.5",
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "A",
            "timestamp": now,
        }
    )

    relabeled = labeler.label_window(packets)
    assert all(p["label"] == "MALICIOUS" for p in relabeled[:6])
    assert relabeled[6]["label"] == "LEGIT"


def test_rolling_buffer_capacity_and_thread_safety():
    buf = RollingTrafficBuffer(capacity=50)
    errors = []

    def producer():
        try:
            for _ in range(120):
                buf.add_packet(make_legit_packet(), auto_label=True)
        except Exception as exc:
            errors.append(exc)

    def consumer():
        try:
            for _ in range(60):
                snap = buf.snapshot(relabel_window=True)
                assert len(snap) <= 50
        except Exception as exc:
            errors.append(exc)

    t1 = threading.Thread(target=producer)
    t2 = threading.Thread(target=consumer)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors
    assert len(buf) == 50
    assert buf.stats()["total_received"] == 120


def test_live_traffic_stream_graceful_shutdown():
    buf = RollingTrafficBuffer(capacity=500)
    stream = LiveTrafficStream(
        buffer=buf, legit_pps=40.0, attack_pps=80.0, phase_duration=0.2
    )
    stop_event = threading.Event()
    stream.start(stop_event)

    time.sleep(0.35)
    stream.inject_burst("port_scan", count=15)
    stream.inject_burst("udp_flood", count=15)

    stop_event.set()
    stream.join(timeout=2.0)

    assert len(buf) > 0
    stats = buf.stats()
    assert stats["total_received"] >= 30


def test_scapy_packet_to_dict():
    tcp_pkt = IP(src="1.2.3.4", dst="10.0.0.1") / TCP(
        sport=12345, dport=80, flags="S"
    )
    udp_pkt = IP(src="5.6.7.8", dst="10.0.0.1") / UDP(sport=5555, dport=53)

    d1 = scapy_packet_to_dict(tcp_pkt)
    d2 = scapy_packet_to_dict(udp_pkt)

    assert d1 is not None and d1["protocol"] == "TCP" and d1["dst_port"] == 80
    assert d1["flags"] == "S"
    assert d2 is not None and d2["protocol"] == "UDP" and d2["dst_port"] == 53
    assert make_port_scan_packet()["protocol"] == "TCP"
    assert make_udp_flood_packet()["protocol"] == "UDP"
