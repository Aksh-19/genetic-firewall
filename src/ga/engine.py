import threading
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console

from src.ga.chromosome import Chromosome
from src.ga.operators import (
    bit_flip_mutation,
    get_elites,
    single_point_crossover,
    spawn_immigrants,
    tournament_selection,
)
from src.ga.population import Population

console = Console()


class GAEngine:
    """
    The Evolutionary Orchestrator.
    Supports both fixed-dataset batch runs (`run()`) and continuous
    real-time evolution against shifting live traffic (`step()` / `run_continuous()`).
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
        immigrant_rate: float = 0.0,
        target_fitness: Optional[float] = None,
        fitness_fn: Optional[Callable[[Chromosome], float]] = None,
    ):
        self.chromosome_length = chromosome_length
        self.population_size = population_size
        self.generations = generations
        self.crossover_rate = crossover_rate
        self.mutation_rate = mutation_rate
        self.tournament_size = tournament_size
        self.elitism_count = elitism_count
        self.immigrant_rate = immigrant_rate
        self.target_fitness = target_fitness
        self.fitness_fn = fitness_fn

        self.population: Optional[Population] = None
        self.generation: int = 0
        self.best_overall: Optional[Chromosome] = None
        self.history: List[Dict[str, Any]] = []

    def initialize_population(self) -> Population:
        """Spawns a fresh random population and resets generational counters."""
        self.population = Population.generate_random(
            self.population_size, self.chromosome_length
        )
        self.generation = 0
        self.best_overall = None
        self.history = []
        return self.population

    def _breed_next_generation(self, evaluated_pop: Population) -> Population:
        """
        Builds the next generation from elites, optional random immigrants,
        and offspring produced via tournament selection, crossover, and mutation.
        """
        next_gen: List[Chromosome] = get_elites(
            evaluated_pop, self.elitism_count
        )

        # Inject fresh random chromosomes to prevent premature convergence
        immigrant_count = int(round(self.population_size * self.immigrant_rate))
        available_slots = max(0, self.population_size - len(next_gen))
        immigrant_count = min(immigrant_count, available_slots)
        next_gen.extend(
            spawn_immigrants(immigrant_count, self.chromosome_length)
        )

        k = min(self.tournament_size, len(evaluated_pop))
        while len(next_gen) < self.population_size:
            parent1 = tournament_selection(evaluated_pop, k=k)
            parent2 = tournament_selection(evaluated_pop, k=k)

            child1, child2 = single_point_crossover(
                parent1, parent2, crossover_rate=self.crossover_rate
            )
            child1 = bit_flip_mutation(child1, mutation_rate=self.mutation_rate)
            child2 = bit_flip_mutation(child2, mutation_rate=self.mutation_rate)

            next_gen.append(child1)
            if len(next_gen) < self.population_size:
                next_gen.append(child2)

        return Population(next_gen)

    def step(
        self, fitness_fn: Optional[Callable[[Chromosome], float]] = None
    ) -> Dict[str, Any]:
        """
        Executes exactly ONE evolutionary generation against the provided fitness
        function (re-evaluating all individuals, including elites, on fresh traffic).
        """
        fn = fitness_fn or self.fitness_fn
        if fn is None:
            raise ValueError(
                "A fitness function must be supplied before stepping the GA engine."
            )

        if self.population is None:
            self.initialize_population()

        assert self.population is not None
        self.population.evaluate(fn)
        self.generation += 1

        current_fittest = self.population.get_fittest().copy()
        avg_fit = self.population.average_fitness()

        if (
            self.best_overall is None
            or (
                current_fittest.fitness is not None
                and (
                    self.best_overall.fitness is None
                    or current_fittest.fitness > self.best_overall.fitness
                )
            )
        ):
            self.best_overall = current_fittest.copy()

        record = {
            "generation": self.generation,
            "best_fitness": current_fittest.fitness,
            "avg_fitness": avg_fit,
            "best_chromosome": current_fittest,
        }
        self.history.append(
            {
                "generation": self.generation,
                "best_fitness": current_fittest.fitness,
                "avg_fitness": avg_fit,
            }
        )

        self.population = self._breed_next_generation(self.population)
        return record

    def run(self, verbose: bool = True) -> Chromosome:
        """
        Executes the genetic algorithm loop for a fixed number of generations.
        Returns the champion chromosome discovered across all generations.
        """
        if self.fitness_fn is None:
            raise ValueError(
                "A fitness function must be supplied before running the GA engine."
            )

        self.initialize_population()

        if verbose:
            console.print(
                f"[bold cyan]🧬 Starting Evolution ({self.generations} gens, "
                f"pop={self.population_size}, len={self.chromosome_length})...[/bold cyan]"
            )

        is_onemax = getattr(self.fitness_fn, "__name__", "") == "one_max_fitness"

        for gen in range(1, self.generations + 1):
            stats = self.step(self.fitness_fn)
            best_fit = stats["best_fitness"]
            avg_fit = stats["avg_fitness"]

            if verbose and (gen == 1 or gen % 10 == 0 or gen == self.generations):
                console.print(
                    f"Gen [yellow]{gen:>3}/{self.generations}[/yellow] | "
                    f"Best Fitness: [green]{best_fit:.2f}[/green] | "
                    f"Avg: [blue]{avg_fit:.2f}[/blue]"
                )

            if self.target_fitness is not None and best_fit >= self.target_fitness:
                if verbose:
                    console.print(
                        f"[bold green]✨ Target fitness reached at Gen {gen}! "
                        f"Fitness: {best_fit:.2f}[/bold green]"
                    )
                break

            if is_onemax and best_fit == float(self.chromosome_length):
                if verbose:
                    console.print(
                        f"[bold green]✨ Perfection achieved at Gen {gen}! "
                        f"Fitness: {best_fit:.2f}[/bold green]"
                    )
                break

        assert self.best_overall is not None
        return self.best_overall

    def run_continuous(
        self,
        fitness_fn_provider: Callable[[], Optional[Callable[[Chromosome], float]]],
        stop_event: threading.Event,
        on_generation: Optional[Callable[[Dict[str, Any]], None]] = None,
        step_delay: float = 0.05,
    ) -> Optional[Chromosome]:
        """
        Continuously evolves the population in a background loop until stop_event
        is triggered. Re-fetches the fitness function every generation so the GA
        adapts to shifting live traffic windows.
        """
        if self.population is None:
            self.initialize_population()

        while not stop_event.is_set():
            fn = fitness_fn_provider()
            if fn is None:
                stop_event.wait(step_delay)
                continue

            stats = self.step(fn)
            if on_generation is not None:
                on_generation(stats)

            stop_event.wait(step_delay)

        return self.best_overall
