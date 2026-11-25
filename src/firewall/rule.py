from dataclasses import dataclass
from functools import lru_cache
import ipaddress
from typing import Any, Dict, List, Optional, Union

from src.ga.chromosome import Chromosome

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@lru_cache(maxsize=64)
def _parse_network(cidr: str) -> IPNetwork:
    """Caches parsed CIDR network objects so rule matching stays fast."""
    return ipaddress.ip_network(cidr, strict=False)


@lru_cache(maxsize=4096)
def _parse_ip(ip_str: str) -> Optional[IPAddress]:
    """Caches parsed packet IP addresses; returns None on malformed input."""
    try:
        return ipaddress.ip_address(ip_str)
    except ValueError:
        return None


def _ip_matches(packet_ip: Optional[str], rule_cidr: str) -> bool:
    """Checks whether a packet IP falls inside a rule's CIDR range or 'ANY'."""
    if rule_cidr == "ANY":
        return True
    if not packet_ip:
        return False
    ip_obj = _parse_ip(packet_ip)
    if ip_obj is None:
        return False
    net_obj = _parse_network(rule_cidr)
    return ip_obj.version == net_obj.version and ip_obj in net_obj


@dataclass
class Rule:
    """
    Represents a single human-readable firewall filtering rule.
    Example: RULE 1: DROP TCP 203.0.113.0/24 -> any:80 [SYN, !ACK]
    """

    protocol: str  # "ANY", "TCP", "UDP"
    dst_port: Optional[int]  # None means ANY, or specific port (80, 443, 53, 22)
    flags_pattern: str  # "ANY", "SYN_ONLY", "ACK"
    action: str  # "ALLOW", "DROP"
    src_ip: str = "ANY"  # "ANY" or CIDR subnet (e.g., "192.168.1.0/24")
    dst_ip: str = "ANY"  # "ANY" or CIDR subnet

    def matches(self, packet: Dict[str, Any]) -> bool:
        """
        Determines whether an incoming packet matches all criteria of this rule.
        Fields set to 'ANY' or None act as wildcards (matching everything).
        """
        # 1. Protocol Match
        if self.protocol != "ANY" and packet.get("protocol") != self.protocol:
            return False

        # 2. Source & Destination IP CIDR Match
        if not _ip_matches(packet.get("src_ip"), self.src_ip):
            return False
        if not _ip_matches(packet.get("dst_ip"), self.dst_ip):
            return False

        # 3. Destination Port Match
        if (
            self.dst_port is not None
            and packet.get("dst_port") != self.dst_port
        ):
            return False

        # 4. Flags Match
        pkt_flags = packet.get("flags", "")
        if self.flags_pattern == "SYN_ONLY":
            # Must have 'S' flag and NOT 'A' (pure SYN attack packet)
            if "S" not in pkt_flags or "A" in pkt_flags:
                return False
        elif self.flags_pattern == "ACK":
            # Must have 'A' flag (part of normal conversation)
            if "A" not in pkt_flags:
                return False

        return True

    def format_flags(self) -> str:
        """Formats flags into human-readable firewall notation."""
        if self.flags_pattern == "SYN_ONLY":
            return "[SYN, !ACK]"
        if self.flags_pattern == "ACK":
            return "[ACK]"
        return "[any flags]"

    def to_export_line(self, index: int) -> str:
        """Formats the rule in standard Phase 4 export syntax."""
        src = "any" if self.src_ip == "ANY" else self.src_ip
        dst = "any" if self.dst_ip == "ANY" else self.dst_ip
        port = "any" if self.dst_port is None else str(self.dst_port)
        return (
            f"RULE {index}: {self.action:<5} {self.protocol:<3} "
            f"{src} -> {dst}:{port}  {self.format_flags()}"
        )

    def __repr__(self) -> str:
        port_str = str(self.dst_port) if self.dst_port is not None else "ANY"
        src_str = "any" if self.src_ip == "ANY" else self.src_ip
        return (
            f"Rule({self.action} {self.protocol} {src_str} -> "
            f"Port:{port_str} [{self.flags_pattern}])"
        )


# Bit length per rule = 12 bits
BITS_PER_RULE = 12

# Mapping tables to translate binary chunks into rule attributes
PORT_MAP = {
    0: None,  # ANY port (wildcard)
    1: 80,  # HTTP web traffic
    2: 443,  # HTTPS secure web traffic
    3: 53,  # DNS domain lookups
    4: 22,  # SSH remote administration
}

PROTOCOL_MAP = {
    0: "ANY",
    1: "TCP",
    2: "UDP",
    3: "ANY",
}

FLAGS_MAP = {
    0: "ANY",
    1: "SYN_ONLY",
    2: "ACK",
    3: "ANY",
}

# 4-bit source IP subnet map (heavily weighted toward ANY so rules generalize well,
# while still letting evolution isolate specific malicious or internal subnets).
SRC_IP_MAP = {
    0: "ANY",
    1: "ANY",
    2: "ANY",
    3: "ANY",
    4: "ANY",
    5: "ANY",
    6: "192.168.1.0/24",
    7: "192.168.1.0/24",
    8: "10.0.0.0/8",
    9: "172.16.0.0/16",
    10: "203.0.113.0/24",
    11: "203.0.113.0/24",
    12: "198.51.100.0/24",
    13: "198.51.100.0/24",
    14: "192.0.2.0/24",
    15: "127.0.0.0/8",
}


def decode_chromosome_to_ruleset(
    chromosome: Chromosome, bits_per_rule: int = BITS_PER_RULE
) -> List[Rule]:
    """
    Translates a binary chromosome (e.g. 60 bits) into a list of structured rules.
    Every 12 bits represents 1 rule:
      - Bits 0-1  (2 bits) -> Protocol
      - Bits 2-4  (3 bits) -> Destination Port
      - Bits 5-6  (2 bits) -> Flags pattern
      - Bit 7     (1 bit)  -> Action (0=ALLOW, 1=DROP)
      - Bits 8-11 (4 bits) -> Source IP CIDR subnet
    """
    rules: List[Rule] = []
    total_bits = len(chromosome.genes)

    for i in range(0, total_bits, bits_per_rule):
        end = i + bits_per_rule
        chunk = chromosome.genes[i:end]
        if len(chunk) < bits_per_rule:
            break

        proto_val = (chunk[0] << 1) | chunk[1]
        protocol = PROTOCOL_MAP.get(proto_val, "ANY")

        port_val = (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        dst_port = PORT_MAP.get(port_val, None)

        flags_val = (chunk[5] << 1) | chunk[6]
        flags_pattern = FLAGS_MAP.get(flags_val, "ANY")

        action_val = chunk[7]
        action = "DROP" if action_val == 1 else "ALLOW"

        src_ip_val = (
            (chunk[8] << 3) | (chunk[9] << 2) | (chunk[10] << 1) | chunk[11]
        )
        src_ip = SRC_IP_MAP.get(src_ip_val, "ANY")

        rules.append(
            Rule(
                protocol=protocol,
                dst_port=dst_port,
                flags_pattern=flags_pattern,
                action=action,
                src_ip=src_ip,
            )
        )

    return rules


def format_ruleset(rules: List[Rule]) -> str:
    """Converts a ruleset into multi-line human-readable firewall output."""
    return "\n".join(rule.to_export_line(idx) for idx, rule in enumerate(rules, 1))
