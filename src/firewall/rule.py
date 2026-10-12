from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from src.ga.chromosome import Chromosome


@dataclass
class Rule:
    """
    Represents a single human-readable firewall filtering rule.
    Example: DROP TCP ANY -> ANY:80 [SYN]
    """

    protocol: str  # "ANY", "TCP", "UDP"
    dst_port: Optional[int]  # None means ANY, or specific port (80, 443, 53, 22)
    flags_pattern: str  # "ANY", "SYN_ONLY", "ACK"
    action: str  # "ALLOW", "DROP"

    def matches(self, packet: Dict[str, Any]) -> bool:
        """
        Determines whether an incoming packet matches all criteria of this rule.
        If a field is 'ANY' or None, it acts as a wildcard (matches everything).
        """
        # 1. Protocol Match
        if self.protocol != "ANY" and packet.get("protocol") != self.protocol:
            return False

        # 2. Destination Port Match
        if (
            self.dst_port is not None
            and packet.get("dst_port") != self.dst_port
        ):
            return False

        # 3. Flags Match
        pkt_flags = packet.get("flags", "")
        if self.flags_pattern == "SYN_ONLY":
            # Must have 'S' flag and NOT 'A' (pure SYN attack packet)
            if "S" not in pkt_flags or "A" in pkt_flags:
                return False
        elif self.flags_pattern == "ACK":
            # Must have 'A' flag (part of normal conversation)
            if "A" not in pkt_flags:
                return False
        # If "ANY", flags are ignored (wildcard)

        return True

    def __repr__(self) -> str:
        port_str = str(self.dst_port) if self.dst_port is not None else "ANY"
        return f"Rule({self.action} {self.protocol} -> Port:{port_str} [{self.flags_pattern}])"


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


def decode_chromosome_to_ruleset(
    chromosome: Chromosome, bits_per_rule: int = BITS_PER_RULE
) -> List[Rule]:
    """
    Translates a binary chromosome (e.g. 60 bits) into a list of 5 structured rules.
    Every 12 bits represents 1 rule:
      - Bits 0-1 (2 bits) -> Protocol
      - Bits 2-4 (3 bits) -> Destination Port
      - Bits 5-6 (2 bits) -> Flags pattern
      - Bit 7   (1 bit)  -> Action (0=ALLOW, 1=DROP)
      - Bits 8-11 (4 bits) -> Reserved / wildcards
    """
    rules: List[Rule] = []
    total_bits = len(chromosome.genes)

    for i in range(0, total_bits, bits_per_rule):
        chunk = chromosome.genes[i : i + bits_per_rule]
        if len(chunk) < bits_per_rule:
            break

        # Convert bit segments to integers
        proto_val = (chunk[0] << 1) | chunk[1]
        protocol = PROTOCOL_MAP.get(proto_val, "ANY")

        port_val = (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
        dst_port = PORT_MAP.get(port_val, None)

        flags_val = (chunk[5] << 1) | chunk[6]
        flags_pattern = FLAGS_MAP.get(flags_val, "ANY")

        action_val = chunk[7]
        action = "DROP" if action_val == 1 else "ALLOW"

        rules.append(
            Rule(
                protocol=protocol,
                dst_port=dst_port,
                flags_pattern=flags_pattern,
                action=action,
            )
        )

    return rules
