from typing import List, Callable, Iterator
from src.ga.chromosome import Chromosome


class Population:
    """
    Represents a collection of chromosomes living together in one generation.
    """

    def __init__(self, individuals: List[Chromosome]):
        self.individuals = list(individuals)

    @classmethod
    def generate_random(cls, size: int, chromosome_length: int) -> "Population":
        """Spawns an initial population composed of randomly generated chromosomes."""
        individuals = [Chromosome.random(chromosome_length) for _ in range(size)]
        return cls(individuals)

    def evaluate(self, fitness_fn: Callable[[Chromosome], float]) -> None:
        """Calculates and stores the fitness score for every individual in the population."""
        for ind in self.individuals:
            ind.fitness = fitness_fn(ind)

    def get_fittest(self) -> Chromosome:
        """Returns the champion individual with the highest fitness score."""
        if not self.individuals:
            raise ValueError("Cannot get fittest from an empty population.")
        return max(
            self.individuals,
            key=lambda ind: ind.fitness if ind.fitness is not None else float("-inf"),
        )

    def average_fitness(self) -> float:
        """Computes the mean fitness score across the entire population."""
        if not self.individuals:
            return 0.0
        scores = [ind.fitness for ind in self.individuals if ind.fitness is not None]
        return sum(scores) / len(scores) if scores else 0.0

    def __len__(self) -> int:
        return len(self.individuals)

    def __iter__(self) -> Iterator[Chromosome]:
        return iter(self.individuals)
