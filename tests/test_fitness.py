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
    best = engine.run(verbose=False)
    # The GA should reach or get extremely close to optimal fitness 30.0
    assert best.fitness is not None
    assert best.fitness >= 28.0
