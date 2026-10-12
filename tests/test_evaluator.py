from src.firewall.rule import (
    Rule,
    decode_chromosome_to_ruleset,
    BITS_PER_RULE,
)
from src.firewall.evaluator import (
    evaluate_packet,
    evaluate_ruleset,
    create_firewall_fitness_fn,
)
from src.ga.chromosome import Chromosome
from src.ga.engine import GAEngine


def test_rule_matching_syn_flood():
    # Rule: DROP TCP to port 80 with SYN_ONLY
    drop_syn_rule = Rule(
        protocol="TCP",
        dst_port=80,
        flags_pattern="SYN_ONLY",
        action="DROP",
    )

    attack_packet = {
        "src_ip": "1.2.3.4",
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
    }
    legit_packet = {
        "src_ip": "1.2.3.4",
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "A",
    }

    assert drop_syn_rule.matches(attack_packet) is True
    assert drop_syn_rule.matches(legit_packet) is False


def test_decode_chromosome_to_ruleset():
    # Create 12 bits representing:
    # proto=1 (TCP), port=1 (80), flags=1 (SYN_ONLY), action=1 (DROP), plus padding
    genes = [0, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0]
    chrom = Chromosome(genes)

    rules = decode_chromosome_to_ruleset(chrom, bits_per_rule=12)
    assert len(rules) == 1
    rule = rules[0]
    assert rule.protocol == "TCP"
    assert rule.dst_port == 80
    assert rule.flags_pattern == "SYN_ONLY"
    assert rule.action == "DROP"


def test_first_match_wins():
    # Rule 1: ALLOW TCP 80
    # Rule 2: DROP TCP 80
    r1 = Rule("TCP", 80, "ANY", "ALLOW")
    r2 = Rule("TCP", 80, "ANY", "DROP")

    packet = {"protocol": "TCP", "dst_port": 80, "flags": "S"}
    # Because Rule 1 appears first, it must match and ALLOW immediately
    decision = evaluate_packet([r1, r2], packet)
    assert decision == "ALLOW"


def test_asymmetric_scoring():
    ruleset = [Rule("TCP", 80, "SYN_ONLY", "DROP")]

    dataset = [
        # True Positive: Malicious dropped (+1.0)
        {"protocol": "TCP", "dst_port": 80, "flags": "S", "label": "MALICIOUS"},
        # True Negative: Legit allowed (+1.0)
        {"protocol": "TCP", "dst_port": 443, "flags": "A", "label": "LEGIT"},
        # False Negative: Malicious allowed (-2.0)
        {"protocol": "UDP", "dst_port": 53, "flags": "", "label": "MALICIOUS"},
        # False Positive: Legit dropped (-1.5)
        {"protocol": "TCP", "dst_port": 80, "flags": "S", "label": "LEGIT"},
    ]

    score, stats = evaluate_ruleset(ruleset, dataset)
    assert stats["tp"] == 1
    assert stats["tn"] == 1
    assert stats["fn"] == 1
    assert stats["fp"] == 1
    # Expected score: 1.0 + 1.0 - 2.0 - 1.5 = -1.5
    assert score == -1.5


def test_ga_evolves_firewall_rules():
    # Mini dataset: 20 packets (14 legit, 6 attacks on port 80 with SYN)
    mini_dataset = []
    for _ in range(14):
        mini_dataset.append(
            {"protocol": "TCP", "dst_port": 443, "flags": "A", "label": "LEGIT"}
        )
    for _ in range(6):
        mini_dataset.append(
            {"protocol": "TCP", "dst_port": 80, "flags": "S", "label": "MALICIOUS"}
        )

    # 5 rules * 12 bits = 60 bits
    rules_count = 5
    chromosome_length = rules_count * BITS_PER_RULE
    fitness_fn = create_firewall_fitness_fn(mini_dataset, bits_per_rule=BITS_PER_RULE)

    engine = GAEngine(
        chromosome_length=chromosome_length,
        population_size=40,
        generations=25,
        crossover_rate=0.8,
        mutation_rate=0.03,
        tournament_size=3,
        elitism_count=2,
        fitness_fn=fitness_fn,
    )

    champion = engine.run(verbose=False)
    # Total possible score if 100% accurate: 14*1 + 6*1 = 20.0
    # The champion ruleset should achieve high positive fitness (at least > 10.0)
    assert champion.fitness is not None
    assert champion.fitness >= 10.0
