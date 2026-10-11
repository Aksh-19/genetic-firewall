import sys
from pathlib import Path

# Ensure project root is in sys.path when running as a standalone script
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from rich.console import Console
from rich.panel import Panel
from src.ga.engine import GAEngine
from src.ga.fitness import one_max_fitness

console = Console()


def main():
    console.print(
        Panel.fit(
            "[bold green]🧬 The Genetic Firewall — GA Engine Live Demo (Phase 2)[/bold green]\n"
            "[dim]Watch Darwinian evolution solve the One-Max benchmark in real time![/dim]",
            border_style="cyan",
        )
    )

    chromosome_length = 30
    population_size = 50
    generations = 35

    console.print(
        f"[bold yellow]🎯 The Challenge:[/bold yellow] Start with completely random 30-bit strings.\n"
        f"Evolve the population until a champion has all 1s (Max Score: [bold green]{chromosome_length}.0[/bold green]).\n"
    )

    engine = GAEngine(
        chromosome_length=chromosome_length,
        population_size=population_size,
        generations=generations,
        crossover_rate=0.8,
        mutation_rate=0.02,
        tournament_size=3,
        elitism_count=2,
        fitness_fn=one_max_fitness,
    )

    champion = engine.run(verbose=True)

    gene_str = "".join(str(g) for g in champion.genes)
    console.print("\n[bold green]🏆 Evolution Finished![/bold green]")
    console.print(f"Champion DNA : [bold magenta]{gene_str}[/bold magenta]")
    console.print(
        f"Final Fitness: [bold green]{champion.fitness:.0f}/{chromosome_length}[/bold green] "
        f"({(champion.fitness / chromosome_length) * 100:.1f}% optimal)\n"
    )


if __name__ == "__main__":
    main()
