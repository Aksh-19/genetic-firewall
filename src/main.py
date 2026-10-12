import sys
import json
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.ga.engine import GAEngine
from src.firewall.rule import decode_chromosome_to_ruleset, BITS_PER_RULE
from src.firewall.evaluator import (
    create_firewall_fitness_fn,
    evaluate_ruleset,
)

console = Console()


def plot_fitness_history(history, output_path="logs/fitness_history.png"):
    """Saves a plot of fitness climbing over generations."""
    try:
        import matplotlib.pyplot as plt

        generations = [h["generation"] for h in history]
        best_fitness = [h["best_fitness"] for h in history]
        avg_fitness = [h["avg_fitness"] for h in history]

        plt.figure(figsize=(9, 5))
        plt.plot(
            generations, best_fitness, label="Best Fitness", color="green", lw=2
        )
        plt.plot(
            generations,
            avg_fitness,
            label="Average Fitness",
            color="blue",
            ls="--",
            lw=1.5,
        )
        plt.title(
            "Genetic Firewall - Fitness Evolution (Phase 3)", fontsize=14
        )
        plt.xlabel("Generation", fontsize=12)
        plt.ylabel("Fitness Score", fontsize=12)
        plt.grid(True, linestyle=":", alpha=0.6)
        plt.legend(fontsize=11)
        plt.tight_layout()

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path, dpi=150)
        plt.close()
        console.print(
            f"[dim]📈 Fitness progression graph saved to: {output_path}[/dim]"
        )
    except Exception as e:
        console.print(f"[dim red]Could not save plot: {e}[/dim red]")


def main():
    console.print(
        Panel.fit(
            "[bold green]🧬 The Genetic Firewall — Evolving Rules Against Live Attack Traffic[/bold green]\n"
            "[dim]Phase 3: Connecting the GA Engine to the 1,000 Traffic Packets![/dim]",
            border_style="cyan",
        )
    )

    dataset_path = project_root / "dataset.json"
    if not dataset_path.exists():
        console.print(
            "[bold red]❌ dataset.json not found! Run src/traffic/simulator.py first.[/bold red]"
        )
        return

    with open(dataset_path, "r") as f:
        dataset = json.load(f)

    legit_count = sum(1 for p in dataset if p.get("label") == "LEGIT")
    attack_count = sum(1 for p in dataset if p.get("label") == "MALICIOUS")

    console.print(
        f"📦 [bold yellow]Loaded Dataset:[/bold yellow] {len(dataset)} total packets "
        f"([green]{legit_count} Legit[/green], [red]{attack_count} Malicious SYN Floods[/red])\n"
    )

    # 5 rules * 12 bits per rule = 60 bits
    rules_count = 5
    chromosome_length = rules_count * BITS_PER_RULE
    population_size = 50
    generations = 30

    fitness_fn = create_firewall_fitness_fn(
        dataset, bits_per_rule=BITS_PER_RULE
    )

    engine = GAEngine(
        chromosome_length=chromosome_length,
        population_size=population_size,
        generations=generations,
        crossover_rate=0.85,
        mutation_rate=0.02,
        tournament_size=3,
        elitism_count=2,
        fitness_fn=fitness_fn,
    )

    champion = engine.run(verbose=True)

    # Decode the champion into English rules
    champion_rules = decode_chromosome_to_ruleset(
        champion, bits_per_rule=BITS_PER_RULE
    )
    score, stats = evaluate_ruleset(champion_rules, dataset)

    # Print champion rules table
    rules_table = Table(
        title="🏆 Champion Firewall Rulebook (First Match Wins)",
        border_style="green",
    )
    rules_table.add_column("Order", style="bold yellow", width=8)
    rules_table.add_column("Action", style="bold", width=10)
    rules_table.add_column("Protocol", style="cyan", width=10)
    rules_table.add_column("Port", style="magenta", width=12)
    rules_table.add_column("Flag Pattern", style="red", width=14)

    for idx, r in enumerate(champion_rules, 1):
        action_style = (
            "[bold red]DROP[/bold red]"
            if r.action == "DROP"
            else "[bold green]ALLOW[/bold green]"
        )
        port_display = str(r.dst_port) if r.dst_port is not None else "ANY (*)"
        rules_table.add_row(
            f"Rule {idx}",
            action_style,
            r.protocol,
            port_display,
            r.flags_pattern,
        )

    console.print()
    console.print(rules_table)

    # Print results score table
    results_table = Table(
        title="📊 Inspection Performance", border_style="cyan"
    )
    results_table.add_column("Metric", style="bold")
    results_table.add_column("Count", style="bold yellow")
    results_table.add_column("Score Impact", style="dim")

    results_table.add_row(
        "🟢 True Positives (Attacks Dropped)",
        str(stats["tp"]),
        f"+{stats['tp'] * 1.0:.1f}",
    )
    results_table.add_row(
        "🟢 True Negatives (Legit Allowed)",
        str(stats["tn"]),
        f"+{stats['tn'] * 1.0:.1f}",
    )
    results_table.add_row(
        "🔴 False Negatives (Attacks Missed)",
        str(stats["fn"]),
        f"{stats['fn'] * -2.0:.1f}",
    )
    results_table.add_row(
        "🟠 False Positives (Legit Blocked)",
        str(stats["fp"]),
        f"{stats['fp'] * -1.5:.1f}",
    )
    results_table.add_row(
        "⭐ Total Fitness Score", f"{score:.1f}", f"Max Possible: {len(dataset)}"
    )

    console.print(results_table)

    # Plot fitness graph to logs/
    plot_fitness_history(engine.history)


if __name__ == "__main__":
    main()
