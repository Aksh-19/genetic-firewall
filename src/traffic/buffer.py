from collections import deque
import threading
from typing import Any, Deque, Dict, List, Optional

from src.traffic.labeler import HeuristicLabeler


class RollingTrafficBuffer:
    """
    Thread-safe sliding window (conveyor belt) holding the most recent N packets.
    Uses collections.deque(maxlen=capacity) protected by a threading.Lock so a
    background traffic producer and background GA evaluator never collide.
    """

    def __init__(
        self,
        capacity: int = 1000,
        labeler: Optional[HeuristicLabeler] = None,
    ):
        self.capacity = capacity
        self.labeler = labeler or HeuristicLabeler()
        self._buffer: Deque[Dict[str, Any]] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self.total_received = 0

    def add_packet(
        self, packet: Dict[str, Any], auto_label: bool = True
    ) -> Dict[str, Any]:
        """Adds a single packet to the rolling window, optionally labeling it."""
        pkt = dict(packet)
        if auto_label and self.labeler is not None:
            pkt["label"] = self.labeler.label_packet(pkt)

        with self._lock:
            self._buffer.append(pkt)
            self.total_received += 1

        return pkt

    def add_packets(
        self, packets: List[Dict[str, Any]], auto_label: bool = True
    ) -> None:
        """Adds a batch of packets safely."""
        processed = []
        for raw_pkt in packets:
            pkt = dict(raw_pkt)
            if auto_label and self.labeler is not None:
                pkt["label"] = self.labeler.label_packet(pkt)
            processed.append(pkt)

        with self._lock:
            self._buffer.extend(processed)
            self.total_received += len(processed)

    def snapshot(self, relabel_window: bool = False) -> List[Dict[str, Any]]:
        """
        Returns a safe copy of all packets currently in the window.
        If relabel_window=True, re-runs HeuristicLabeler across the full window
        so early burst packets share the burst label.
        """
        with self._lock:
            items = [dict(p) for p in self._buffer]

        if relabel_window and self.labeler is not None and items:
            return self.labeler.label_window(items)
        return items

    def stats(self) -> Dict[str, int]:
        """Returns summary metrics for the current window."""
        with self._lock:
            window_size = len(self._buffer)
            legit = sum(1 for p in self._buffer if p.get("label") == "LEGIT")
            malicious = sum(
                1 for p in self._buffer if p.get("label") == "MALICIOUS"
            )
            total = self.total_received

        return {
            "window_size": window_size,
            "capacity": self.capacity,
            "total_received": total,
            "legit_count": legit,
            "malicious_count": malicious,
        }

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)
