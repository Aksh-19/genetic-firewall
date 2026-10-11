import random
from src.ga.chromosome import Chromosome
from src.ga.population import Population
from src.ga.operators import (
    tournament_selection,
    single_point_crossover,
    bit_flip_mutation,
    get_elites,
)


def test_tournament_selection():
    c1 = Chromosome([0, 0, 0])
    c1.fitness = 1.0
    c2 = Chromosome([1, 1, 1])
    c2.fitness = 10.0
    c3 = Chromosome([1, 0, 0])
    c3.fitness = 3.0

    pop = Population([c1, c2, c3])
    # With k=3, c2 must always win because it has the highest fitness
    winner = tournament_selection(pop, k=3)
    assert winner.genes == [1, 1, 1]
    assert winner.fitness == 10.0


def test_single_point_crossover():
    random.seed(42)
    p1 = Chromosome([0, 0, 0, 0, 0])
    p2 = Chromosome([1, 1, 1, 1, 1])

    c1, c2 = single_point_crossover(p1, p2, crossover_rate=1.0)
    assert len(c1) == len(p1)
    assert len(c2) == len(p2)
    # The child genes should not be all 0s or all 1s if crossover occurred
    assert 0 in c1.genes and 1 in c1.genes
    assert 0 in c2.genes and 1 in c2.genes


def test_bit_flip_mutation():
    chrom = Chromosome([0, 0, 0, 0, 0])
    # With mutation_rate=1.0, every single bit must flip from 0 to 1
    mutated = bit_flip_mutation(chrom, mutation_rate=1.0)
    assert mutated.genes == [1, 1, 1, 1, 1]

    # With mutation_rate=0.0, no bits change
    unmutated = bit_flip_mutation(chrom, mutation_rate=0.0)
    assert unmutated.genes == [0, 0, 0, 0, 0]


def test_elitism():
    c1 = Chromosome([0])
    c1.fitness = 2.0
    c2 = Chromosome([0])
    c2.fitness = 10.0
    c3 = Chromosome([0])
    c3.fitness = 8.0

    pop = Population([c1, c2, c3])
    elites = get_elites(pop, n_elites=2)
    assert len(elites) == 2
    assert elites[0].fitness == 10.0
    assert elites[1].fitness == 8.0
