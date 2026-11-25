import json

from src.firewall.exporter import GenerationLogger, export_best_rules
from src.firewall.rule import (
    Rule,
    decode_chromosome_to_ruleset,
    format_ruleset,
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


def test_rule_src_ip_cidr_matching():
    rule = Rule(
        protocol="TCP",
        dst_port=80,
        flags_pattern="SYN_ONLY",
        action="DROP",
        src_ip="203.0.113.0/24",
    )

    inside_subnet = {
        "src_ip": "203.0.113.42",
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
    }
    outside_subnet = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.100",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
    }
    malformed_ip = {
        "src_ip": "not-an-ip",
        "dst_port": 80,
        "protocol": "TCP",
        "flags": "S",
    }

    assert rule.matches(inside_subnet) is True
    assert rule.matches(outside_subnet) is False
    assert rule.matches(malformed_ip) is False


def test_decode_chromosome_with_src_ip_and_format():
    # proto=1 (TCP), port=1 (80), flags=1 (SYN_ONLY),
    # action=1 (DROP), src_ip=10 (203.0.113.0/24 -> 1010)
    genes = [0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0]
    chrom = Chromosome(genes)

    rules = decode_chromosome_to_ruleset(chrom, bits_per_rule=12)
    assert len(rules) == 1
    assert rules[0].src_ip == "203.0.113.0/24"
    assert rules[0].action == "DROP"

    exported = format_ruleset(rules)
    assert exported == "RULE 1: DROP  TCP 203.0.113.0/24 -> any:80  [SYN, !ACK]"


def test_rule_export_and_generation_logger(tmp_path):
    rules = [
        Rule("TCP", 80, "SYN_ONLY", "DROP", src_ip="203.0.113.0/24"),
        Rule("TCP", 443, "ANY", "ALLOW", src_ip="ANY"),
    ]
    export_file = tmp_path / "best_rules.txt"
    export_best_rules(
        rules,
        output_path=export_file,
        generation=7,
        fitness=420.5,
        traffic_phase="SYN_FLOOD",
    )

    text = export_file.read_text(encoding="utf-8")
    assert "Generation: 7" in text
    assert "Fitness: 420.50" in text
    assert "RULE 1: DROP  TCP 203.0.113.0/24 -> any:80  [SYN, !ACK]" in text
    assert "RULE 2: ALLOW TCP any -> any:443  [any flags]" in text

    log_file = tmp_path / "generations.jsonl"
    logger = GenerationLogger(log_path=log_file)
    logger.log_generation(
        generation=7,
        best_fitness=420.5,
        avg_fitness=310.2,
        rules=rules,
        stats={"tp": 100, "tn": 325, "fp": 3, "fn": 0},
        traffic_phase="SYN_FLOOD",
    )

    lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["generation"] == 7
    assert entry["num_rules"] == 2
    assert entry["traffic_phase"] == "SYN_FLOOD"
    assert entry["stats"]["tp"] == 100
