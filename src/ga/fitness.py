from src.ga.chromosome import Chromosome


def one_max_fitness(chromosome: Chromosome) -> float:
    """
    The classic 'One-Max' benchmark problem:
    Fitness equals the total count of 1s in the chromosome.
    Example: [1, 0, 1, 1, 0] -> 3.0
    The maximum possible score is len(chromosome).
    """
    return float(sum(chromosome.genes))
