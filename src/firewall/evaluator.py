from typing import List, Dict, Any, Tuple, Callable
from src.ga.chromosome import Chromosome
from src.firewall.rule import Rule, decode_chromosome_to_ruleset, BITS_PER_RULE


def evaluate_packet(
    ruleset: List[Rule], packet: Dict[str, Any], default_action: str = "ALLOW"
) -> str:
    """
    Evaluates a single packet against a sequential ruleset.
    Principle: 'FIRST MATCH WINS'.
    If no rule matches, falls back to default_action.
    """
    for rule in ruleset:
        if rule.matches(packet):
            return rule.action
    return default_action


def evaluate_ruleset(
    ruleset: List[Rule],
    dataset: List[Dict[str, Any]],
    tp_weight: float = 1.0,
    tn_weight: float = 1.0,
    fn_weight: float = -2.0,
    fp_weight: float = -1.5,
) -> Tuple[float, Dict[str, int]]:
    """
    Runs an entire traffic dataset through a ruleset.
    Scores each outcome using Asymmetric Penalties:
      - True Positive (TP) : Malicious packet DROPPED (+1.0)
      - True Negative (TN) : Legit packet ALLOWED     (+1.0)
      - False Negative (FN): Malicious packet ALLOWED  (-2.0) [DANGEROUS]
      - False Positive (FP): Legit packet DROPPED      (-1.5) [ANNOYING]
    """
    stats = {"tp": 0, "tn": 0, "fp": 0, "fn": 0}
    total_score = 0.0

    for packet in dataset:
        decision = evaluate_packet(ruleset, packet, default_action="ALLOW")
        label = packet.get("label", "LEGIT")

        if label == "MALICIOUS":
            if decision == "DROP":
                stats["tp"] += 1
                total_score += tp_weight
            else:
                stats["fn"] += 1
                total_score += fn_weight
        else:  # LEGIT packet
            if decision == "ALLOW":
                stats["tn"] += 1
                total_score += tn_weight
            else:
                stats["fp"] += 1
                total_score += fp_weight

    return total_score, stats


def create_firewall_fitness_fn(
    dataset: List[Dict[str, Any]],
    bits_per_rule: int = BITS_PER_RULE,
) -> Callable[[Chromosome], float]:
    """
    Factory creating a fitness evaluation function tailored for the GA engine.
    Given a binary chromosome, it decodes it to a ruleset, tests it against
    the dataset, and returns the net fitness score.
    """

    def fitness_fn(chromosome: Chromosome) -> float:
        ruleset = decode_chromosome_to_ruleset(
            chromosome, bits_per_rule=bits_per_rule
        )
        score, _ = evaluate_ruleset(ruleset, dataset)
        return score

    return fitness_fn
