from typing import Callable, Dict, List, Any, Optional
from rich.console import Console
from src.ga.chromosome import Chromosome
from src.ga.population import Population
from src.ga.operators import (
    tournament_selection,
    single_point_crossover,
    bit_flip_mutation,
    get_elites,
)

console = Console()


class GAEngine:
    """
    The Evolutionary Orchestrator.
    Controls the generational lifecycle:
      Init -> Evaluate -> Record -> Elitism -> Selection/Crossover/Mutation -> Next Gen.
    """

    def __init__(
        self,
        chromosome_length: int,
        population_size: int = 100,
        generations: int = 50,
        crossover_rate: float = 0.8,
        mutation_rate: float = 0.01,
        tournament_size: int = 3,
        elitism_count: int = 2,
        fitness_fn: Optional[Callable[[Chromosome], float]] = None,
    ):
        self.chromosome_length = chromosome_length
        self.population_size = population_size
        self.generations = generations
        self.crossover_rate = crossover_rate
        self.mutation_rate = mutation_rate
        self.tournament_size = tournament_size
        self.elitism_count = elitism_count
        self.fitness_fn = fitness_fn
        self.history: List[Dict[str, Any]] = []

    def run(self, verbose: bool = True) -> Chromosome:
        """
        Executes the genetic algorithm loop over the specified number of generations.
        Returns the champion chromosome discovered across all generations.
        """
        if self.fitness_fn is None:
            raise ValueError(
                "A fitness function must be supplied before running the GA engine."
            )

        # 1. Spawn the initial primordial population & evaluate their fitness
        population = Population.generate_random(
            self.population_size, self.chromosome_length
        )
        population.evaluate(self.fitness_fn)

        best_overall = population.get_fittest().copy()

        if verbose:
            console.print(
                f"[bold cyan]🧬 Starting Evolution ({self.generations} gens, "
                f"pop={self.population_size}, len={self.chromosome_length})...[/bold cyan]"
            )

        # 2. Generational Loop
        for gen in range(1, self.generations + 1):
            current_fittest = population.get_fittest()
            avg_fit = population.average_fitness()

            # Track global all-time champion
            if (
                current_fittest.fitness is not None
                and (
                    best_overall.fitness is None
                    or current_fittest.fitness > best_overall.fitness
                )
            ):
                best_overall = current_fittest.copy()

            self.history.append(
                {
                    "generation": gen,
                    "best_fitness": current_fittest.fitness,
                    "avg_fitness": avg_fit,
                }
            )

            if verbose and (gen == 1 or gen % 10 == 0 or gen == self.generations):
                console.print(
                    f"Gen [yellow]{gen:>3}/{self.generations}[/yellow] | "
                    f"Best Fitness: [green]{current_fittest.fitness:.2f}[/green] | "
                    f"Avg: [blue]{avg_fit:.2f}[/blue]"
                )

            # Early termination if maximum theoretical fitness is achieved
            if current_fittest.fitness == float(self.chromosome_length):
                if verbose:
                    console.print(
                        f"[bold green]✨ Perfection achieved at Gen {gen}! Fitness: {current_fittest.fitness:.2f}[/bold green]"
                    )
                break

            # 3. Elitism: Directly pass the top champions to the next generation
            next_generation_individuals: List[Chromosome] = get_elites(
                population, self.elitism_count
            )

            # 4. Breed offspring to fill up the remaining spots in the population
            while len(next_generation_individuals) < self.population_size:
                parent1 = tournament_selection(
                    population, k=self.tournament_size
                )
                parent2 = tournament_selection(
                    population, k=self.tournament_size
                )

                child1, child2 = single_point_crossover(
                    parent1, parent2, crossover_rate=self.crossover_rate
                )

                child1 = bit_flip_mutation(
                    child1, mutation_rate=self.mutation_rate
                )
                child2 = bit_flip_mutation(
                    child2, mutation_rate=self.mutation_rate
                )

                next_generation_individuals.append(child1)
                if len(next_generation_individuals) < self.population_size:
                    next_generation_individuals.append(child2)

            # 5. Form the next generation and calculate their fitness
            population = Population(next_generation_individuals)
            population.evaluate(self.fitness_fn)

        return best_overall
