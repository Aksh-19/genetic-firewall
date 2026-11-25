import json
import threading
import time

from src.firewall.evaluator import (
    create_firewall_fitness_fn,
    evaluate_ruleset,
)
from src.firewall.exporter import GenerationLogger, export_best_rules
from src.firewall.rule import BITS_PER_RULE, decode_chromosome_to_ruleset
from src.ga.engine import GAEngine
from src.traffic.buffer import RollingTrafficBuffer
from src.traffic.labeler import HeuristicLabeler
from src.traffic.simulator import LiveTrafficStream


def test_end_to_end_live_pipeline(tmp_path):
    labeler = HeuristicLabeler(
        window_seconds=5.0,
        syn_threshold=5,
        subnet_syn_threshold=8,
        port_scan_threshold=5,
    )
    buffer = RollingTrafficBuffer(capacity=200, labeler=labeler)
    stream = LiveTrafficStream(
        buffer=buffer,
        legit_pps=30.0,
        attack_pps=80.0,
        phase_duration=0.3,
        auto_cycle=True,
    )
    engine = GAEngine(
        chromosome_length=5 * BITS_PER_RULE,
        population_size=20,
        crossover_rate=0.85,
        mutation_rate=0.04,
        tournament_size=3,
        elitism_count=2,
        immigrant_rate=0.15,
    )

    rules_file = tmp_path / "best_rules.txt"
    log_file = tmp_path / "generations.jsonl"
    logger = GenerationLogger(log_path=log_file)
    stop_event = threading.Event()
    snapshot_holder = {"packets": []}

    def fitness_fn_provider():
        snap = buffer.snapshot(relabel_window=True)
        if len(snap) < 10:
            return None
        snapshot_holder["packets"] = snap
        return create_firewall_fitness_fn(snap, bits_per_rule=BITS_PER_RULE)

    def on_generation(stats):
        rules = decode_chromosome_to_ruleset(
            stats["best_chromosome"], bits_per_rule=BITS_PER_RULE
        )
        score, eval_stats = evaluate_ruleset(rules, snapshot_holder["packets"])
        export_best_rules(
            rules,
            output_path=rules_file,
            generation=stats["generation"],
            fitness=score,
            traffic_phase=stream.current_phase,
        )
        logger.log_generation(
            generation=stats["generation"],
            best_fitness=score,
            avg_fitness=stats["avg_fitness"],
            rules=rules,
            stats=eval_stats,
            traffic_phase=stream.current_phase,
        )
        if stats["generation"] >= 4:
            stop_event.set()

    stream.start(stop_event)
    ga_thread = threading.Thread(
        target=engine.run_continuous,
        kwargs={
            "fitness_fn_provider": fitness_fn_provider,
            "stop_event": stop_event,
            "on_generation": on_generation,
            "step_delay": 0.02,
        },
        daemon=True,
    )
    ga_thread.start()

    # Wait up to 4 seconds for 4 generations to complete cleanly
    deadline = time.monotonic() + 4.0
    while not stop_event.is_set() and time.monotonic() < deadline:
        time.sleep(0.05)

    stop_event.set()
    stream.join(timeout=2.0)
    ga_thread.join(timeout=2.0)

    assert rules_file.exists()
    assert "RULE 1:" in rules_file.read_text(encoding="utf-8")

    log_lines = log_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(log_lines) >= 4
    last_entry = json.loads(log_lines[-1])
    assert last_entry["generation"] >= 4
    assert last_entry["num_rules"] == 5
