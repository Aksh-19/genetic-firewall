import threading

from src.ga.chromosome import Chromosome
from src.ga.fitness import one_max_fitness
from src.ga.engine import GAEngine


def test_one_max_fitness():
    chrom = Chromosome([1, 0, 1, 1, 0, 1])
    assert one_max_fitness(chrom) == 4.0

    zero_chrom = Chromosome([0, 0, 0])
    assert one_max_fitness(zero_chrom) == 0.0


def test_ga_engine_solves_onemax():
    # Test that the GA can successfully evolve a random 30-bit chromosome to all 1s (fitness=30.0)
    engine = GAEngine(
        chromosome_length=30,
        population_size=50,
        generations=40,
        crossover_rate=0.8,
        mutation_rate=0.02,
        tournament_size=3,
        elitism_count=2,
        fitness_fn=one_max_fitness,
    )
    champion = engine.run(verbose=False)
    # The GA should reach or get extremely close to optimal fitness 30.0
    assert champion.fitness is not None
    assert champion.fitness >= 28.0


def test_continuous_adaptation_with_random_immigrants():
    # Phase A: prefer all 1s. Phase B: target flips to all 0s!
    target_is_ones = {"value": True}

    def dynamic_fitness_fn(chrom: Chromosome) -> float:
        if target_is_ones["value"]:
            return float(sum(chrom.genes))
        return float(len(chrom.genes) - sum(chrom.genes))

    engine = GAEngine(
        chromosome_length=16,
        population_size=40,
        crossover_rate=0.85,
        mutation_rate=0.05,
        tournament_size=3,
        elitism_count=2,
        immigrant_rate=0.15,
    )
    engine.initialize_population()

    for _ in range(15):
        stats_a = engine.step(dynamic_fitness_fn)
    assert stats_a["best_fitness"] >= 14.0

    # Flip the target mid-stream (simulating new traffic pattern)
    target_is_ones["value"] = False
    for _ in range(25):
        stats_b = engine.step(dynamic_fitness_fn)
    assert stats_b["best_fitness"] >= 14.0


def test_run_continuous_graceful_stop():
    engine = GAEngine(
        chromosome_length=12,
        population_size=20,
        immigrant_rate=0.1,
    )
    stop_event = threading.Event()
    seen_gens = []

    def on_gen(stats):
        seen_gens.append(stats["generation"])
        if len(seen_gens) >= 3:
            stop_event.set()

    best = engine.run_continuous(
        fitness_fn_provider=lambda: one_max_fitness,
        stop_event=stop_event,
        on_generation=on_gen,
        step_delay=0.01,
    )
    assert best is not None
    assert len(seen_gens) >= 3
