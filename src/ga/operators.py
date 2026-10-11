import random
from typing import List, Tuple
from src.ga.chromosome import Chromosome
from src.ga.population import Population


def tournament_selection(population: Population, k: int = 3) -> Chromosome:
    """
    Tournament Selection:
    Picks k random candidates from the population.
    The one with the highest fitness wins the tournament and earns the right to reproduce.
    """
    if len(population) < k:
        raise ValueError("Tournament size k cannot exceed population size.")
    contestants = random.sample(population.individuals, k)
    winner = max(
        contestants,
        key=lambda ind: ind.fitness if ind.fitness is not None else float("-inf"),
    )
    return winner.copy()


def single_point_crossover(
    parent1: Chromosome, parent2: Chromosome, crossover_rate: float = 0.8
) -> Tuple[Chromosome, Chromosome]:
    """
    Single-Point Crossover (Mating):
    With probability crossover_rate, picks a cut point and swaps the tails of both parents.
    If crossover does not trigger, returns exact clones of the parents.
    """
    if len(parent1) != len(parent2):
        raise ValueError("Both parents must have identical chromosome lengths.")

    if random.random() > crossover_rate or len(parent1) < 2:
        return parent1.copy(), parent2.copy()

    # Pick a cut point strictly inside the gene strand (1 to len - 1)
    cut = random.randint(1, len(parent1) - 1)
    child1_genes = parent1.genes[:cut] + parent2.genes[cut:]
    child2_genes = parent2.genes[:cut] + parent1.genes[cut:]

    return Chromosome(child1_genes), Chromosome(child2_genes)


def bit_flip_mutation(
    chromosome: Chromosome, mutation_rate: float = 0.01
) -> Chromosome:
    """
    Bit-Flip Mutation:
    Walks across each bit in the chromosome. With probability mutation_rate,
    flips 0 -> 1 or 1 -> 0 to introduce genetic diversity.
    """
    new_genes = []
    for gene in chromosome.genes:
        if random.random() < mutation_rate:
            new_genes.append(1 - gene)  # 0 becomes 1, 1 becomes 0
        else:
            new_genes.append(gene)
    return Chromosome(new_genes)


def get_elites(population: Population, n_elites: int = 2) -> List[Chromosome]:
    """
    Elitism:
    Preserves the top n_elites champions untouched into the next generation.
    Guarantees the best solution discovered so far is never lost.
    """
    if n_elites <= 0:
        return []
    sorted_individuals = sorted(
        population.individuals,
        key=lambda ind: ind.fitness if ind.fitness is not None else float("-inf"),
        reverse=True,
    )
    return [ind.copy() for ind in sorted_individuals[:n_elites]]
