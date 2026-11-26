import json
from pathlib import Path
import sys
import threading
import time
from typing import Any, Dict, List, Optional

import click
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
import yaml

# Ensure project root is in sys.path when executed directly
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.firewall.applier import (  # noqa: E402
    PacketFilterProxy,
    RuleApplier,
    TargetServer,
    check_proxy_connectivity,
)
from src.firewall.evaluator import (  # noqa: E402
    create_firewall_fitness_fn,
    evaluate_ruleset,
)
from src.firewall.exporter import (  # noqa: E402
    GenerationLogger,
    export_best_rules,
)
from src.firewall.rule import (  # noqa: E402
    BITS_PER_RULE,
    Rule,
    decode_chromosome_to_ruleset,
)
from src.ga.engine import GAEngine  # noqa: E402
from src.traffic.buffer import RollingTrafficBuffer  # noqa: E402
from src.traffic.labeler import HeuristicLabeler  # noqa: E402
from src.traffic.simulator import (  # noqa: E402
    LiveTrafficStream,
    send_external_attack,
)

console = Console()


def load_config(config_path: Path) -> Dict[str, Any]:
    """Loads YAML configuration, falling back to sensible defaults."""
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
            return data
    return {}


def plot_fitness_history(
    history: List[Dict[str, Any]], output_path: str = "logs/fitness_history.png"
) -> None:
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
        plt.title("Genetic Firewall - Fitness Evolution (Phase 3)", fontsize=14)
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
    except Exception as exc:
        console.print(f"[dim red]Could not save plot: {exc}[/dim red]")


def build_rules_table(
    rules: List[Rule],
    title: str = "🏆 Champion Firewall Rulebook (First Match Wins)",
    safety_count: int = 0,
) -> Table:
    """Constructs a formatted Rich table for a decoded firewall ruleset."""
    rules_table = Table(title=title, border_style="green", expand=True)
    rules_table.add_column("Order", style="bold yellow", width=10)
    rules_table.add_column("Action", style="bold", width=8)
    rules_table.add_column("Protocol", style="cyan", width=9)
    rules_table.add_column("Source IP", style="blue", width=16)
    rules_table.add_column("Dst Port", style="magenta", width=10)
    rules_table.add_column("Flags", style="red", width=13)

    for idx, r in enumerate(rules, 1):
        action_style = (
            "[bold red]DROP[/bold red]"
            if r.action == "DROP"
            else "[bold green]ALLOW[/bold green]"
        )
        port_display = str(r.dst_port) if r.dst_port is not None else "ANY (*)"
        src_display = "ANY (*)" if r.src_ip == "ANY" else r.src_ip
        order_label = (
            f"🔒 Safe {idx}" if idx <= safety_count else f"Rule {idx - safety_count}"
        )
        rules_table.add_row(
            order_label,
            action_style,
            r.protocol,
            src_display,
            port_display,
            escape(r.format_flags()),
        )
    return rules_table


def render_live_dashboard(
    state: Dict[str, Any],
    mode: str,
    rules_export_path: str,
    log_path: str,
    enforce: bool = True,
) -> Layout:
    """Builds the live terminal layout for real-time evolution & packet filtering."""
    display_rules = state.get("active_rules") or state.get("best_rules", [])
    safety_count = int(state.get("safety_count", 0))
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="status", size=7),
        Layout(name="rules", size=max(12, len(display_rules) + 6)),
        Layout(name="footer", size=4),
    )

    enforce_badge = "PROXY ENFORCED" if enforce else "OBSERVE ONLY"
    layout["header"].update(
        Panel(
            f"[bold green]🧬 Genetic Firewall Live[/bold green] "
            f"[dim](mode={mode} | {enforce_badge} | Ctrl+C to stop)[/dim]",
            border_style="cyan",
        )
    )

    layout["status"].split_row(
        Layout(name="traffic"),
        Layout(name="proxy_server"),
        Layout(name="evolution"),
    )

    buf_stats = state.get("buffer_stats", {})
    phase = state.get("traffic_phase", "WARMING_UP")
    phase_color = "green" if phase == "NORMAL" else "bold red"

    traffic_text = (
        f"Phase  : [{phase_color}]{phase}[/{phase_color}]\n"
        f"Window : [cyan]{buf_stats.get('window_size', 0)}[/cyan]/"
        f"{buf_stats.get('capacity', 0)}\n"
        f"Total  : [yellow]{buf_stats.get('total_received', 0)}[/yellow]\n"
        f"Mix    : [green]{buf_stats.get('legit_count', 0)} OK[/green] | "
        f"[red]{buf_stats.get('malicious_count', 0)} BAD[/red]"
    )
    layout["traffic"].update(
        Panel(traffic_text, title="📡 Traffic Buffer", border_style="blue")
    )

    proxy_stats = state.get("proxy_stats", {})
    server_stats = state.get("server_stats", {})
    if enforce:
        proxy_text = (
            f"Proxy Fwd  : [green]{proxy_stats.get('forwarded_total', 0)}[/green]\n"
            f"Proxy Drop : [red]{proxy_stats.get('dropped_total', 0)}[/red] "
            f"([cyan]{proxy_stats.get('dropped_attacks', 0)} atk[/cyan])\n"
            f"Srv Legit  : [green]{server_stats.get('legit_received', 0)}[/green]\n"
            f"Srv Leak   : [red]{server_stats.get('attack_received', 0)}[/red] | "
            f"HC: [cyan]{server_stats.get('health_checks_ok', 0)}[/cyan]"
        )
    else:
        proxy_text = "[dim]Proxy disabled (--no-enforce)\nDry-run translation active[/dim]"
    layout["proxy_server"].update(
        Panel(proxy_text, title="🛡️ Proxy -> ☕ Server", border_style="yellow")
    )

    eval_stats = state.get("eval_stats", {})
    applier_stats = state.get("applier_stats", {})
    gen = state.get("generation", 0)
    best_fit = state.get("best_fitness", 0.0)
    evo_text = (
        f"Gen    : [bold yellow]{gen}[/bold yellow] "
        f"(Fit: [bold green]{best_fit:.1f}[/bold green])\n"
        f"TP/TN  : [green]{eval_stats.get('tp', 0)}[/green] / "
        f"[green]{eval_stats.get('tn', 0)}[/green]\n"
        f"FN/FP  : [red]{eval_stats.get('fn', 0)}[/red] / "
        f"[yellow]{eval_stats.get('fp', 0)}[/yellow]\n"
        f"Apply  : [cyan]{applier_stats.get('updates_applied', 0)}[/cyan] | "
        f"Skip: {applier_stats.get('updates_skipped_rate_limit', 0)} | "
        f"RB: [red]{applier_stats.get('rollbacks_triggered', 0)}[/red]"
    )
    layout["evolution"].update(
        Panel(evo_text, title="🧬 GA & Applier", border_style="magenta")
    )

    if display_rules:
        title = (
            "🛡️ Active Enforced Rulebook (Safety + Champion)"
            if enforce
            else "🏆 Champion Firewall Rulebook (First Match Wins)"
        )
        layout["rules"].update(
            build_rules_table(display_rules, title=title, safety_count=safety_count)
        )
    else:
        layout["rules"].update(
            Panel(
                "[dim]Waiting for initial packets in rolling buffer...[/dim]",
                title="🏆 Champion Firewall Rulebook",
                border_style="green",
            )
        )

    layout["footer"].update(
        Panel(
            f"[dim]Rules: [yellow]{rules_export_path}[/yellow] | "
            f"OS Dry-Run: [yellow]logs/rules_iptables.sh[/yellow], "
            f"[yellow]logs/rules_pf.conf[/yellow]\n"
            f"Attack from another terminal: "
            f"[cyan]python src/main.py attack --type syn-flood[/cyan][/dim]",
            border_style="dim",
        )
    )
    return layout


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """🧬 The Genetic Firewall CLI."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(live)


@cli.command()
@click.option(
    "--mode",
    type=click.Choice(["simulator", "sniffer"], case_sensitive=False),
    default="simulator",
    show_default=True,
    help="Traffic source: simulated stream (no sudo) or live Scapy sniffer.",
)
@click.option(
    "--iface",
    default=None,
    help="Network interface for sniffer mode (e.g., lo0 or en0).",
)
@click.option(
    "--duration",
    type=float,
    default=None,
    help="Optional duration in seconds before graceful auto-stop.",
)
@click.option(
    "--auto-cycle/--no-auto-cycle",
    default=True,
    show_default=True,
    help="Cycle automatically between normal traffic and attack bursts in simulator mode.",
)
@click.option(
    "--enforce/--no-enforce",
    default=True,
    show_default=True,
    help="Enforce evolved rules live via PacketFilterProxy -> TargetServer.",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=project_root / "configs" / "default.yaml",
    show_default=True,
    help="Path to YAML configuration file.",
)
def live(
    mode: str,
    iface: Optional[str],
    duration: Optional[float],
    auto_cycle: bool,
    enforce: bool,
    config_path: Path,
) -> None:
    """Runs real-time packet buffering, GA evolution, and live proxy filtering."""
    cfg = load_config(config_path)
    ga_cfg = cfg.get("ga", {})
    tr_cfg = cfg.get("traffic", {})
    lb_cfg = cfg.get("labeler", {})
    ap_cfg = cfg.get("applier", {})
    lg_cfg = cfg.get("logging", {})

    rules_count = int(ga_cfg.get("rules_count", 8))
    rules_export_path = str(lg_cfg.get("rules_export_path", "logs/best_rules.txt"))
    log_path = str(lg_cfg.get("generations_log_path", "logs/generations.jsonl"))

    labeler = HeuristicLabeler(
        window_seconds=float(lb_cfg.get("window_seconds", 5.0)),
        syn_threshold=int(lb_cfg.get("syn_threshold", 10)),
        subnet_syn_threshold=int(lb_cfg.get("subnet_syn_threshold", 18)),
        port_scan_threshold=int(lb_cfg.get("port_scan_threshold", 6)),
        udp_threshold=int(lb_cfg.get("udp_threshold", 15)),
        subnet_udp_threshold=int(lb_cfg.get("subnet_udp_threshold", 20)),
    )
    buffer = RollingTrafficBuffer(
        capacity=int(tr_cfg.get("buffer_capacity", 600)),
        labeler=labeler,
    )

    stop_event = threading.Event()
    state_lock = threading.Lock()

    use_proxy = enforce and bool(ap_cfg.get("enabled", True)) and mode == "simulator"
    proxy: Optional[PacketFilterProxy] = None
    target_server: Optional[TargetServer] = None
    proxy_host = str(ap_cfg.get("proxy_host", "127.0.0.1"))
    proxy_port = int(ap_cfg.get("proxy_port", 8888))
    server_host = str(ap_cfg.get("server_host", "127.0.0.1"))
    server_port = int(ap_cfg.get("server_port", 8889))
    health_timeout = float(ap_cfg.get("health_check_timeout", 0.5))

    if use_proxy:
        target_server = TargetServer(host=server_host, port=server_port)
        actual_server_port = target_server.start(stop_event)
        proxy = PacketFilterProxy(
            listen_host=proxy_host,
            listen_port=proxy_port,
            target_host=server_host,
            target_port=actual_server_port,
            traffic_buffer=buffer,
        )
        actual_proxy_port = proxy.start(stop_event)
        health_fn = lambda: check_proxy_connectivity(  # noqa: E731
            proxy_host, actual_proxy_port, timeout=health_timeout
        )
    else:
        actual_proxy_port = None
        health_fn = None

    applier = RuleApplier(
        proxy=proxy,
        min_generations_between_updates=int(
            ap_cfg.get("min_generations_between_updates", 8)
        ),
        min_fitness_improvement_pct=float(
            ap_cfg.get("min_fitness_improvement_pct", 0.05)
        ),
        health_check_fn=health_fn,
        rollback_timeout=health_timeout * 2.0,
        dry_run_export_dir=(
            project_root / "logs" if ap_cfg.get("export_os_rules", True) else None
        ),
    )

    latest_state: Dict[str, Any] = {
        "generation": 0,
        "best_fitness": 0.0,
        "avg_fitness": 0.0,
        "best_rules": [],
        "active_rules": applier.stats()["active_rules"],
        "safety_count": len(applier.safety_rules),
        "eval_stats": {},
        "buffer_stats": buffer.stats(),
        "proxy_stats": proxy.stats() if proxy is not None else {},
        "server_stats": target_server.stats() if target_server is not None else {},
        "applier_stats": applier.stats(),
        "traffic_phase": "STARTING",
    }

    if mode == "sniffer":
        from src.traffic.sniffer import LiveSniffer

        traffic_source: Any = LiveSniffer(buffer=buffer, iface=iface)
        phase_provider = lambda: "LIVE_SNIFFER"  # noqa: E731
    else:
        traffic_source = LiveTrafficStream(
            buffer=buffer,
            legit_pps=float(tr_cfg.get("legit_pps", 20.0)),
            attack_pps=float(tr_cfg.get("attack_pps", 80.0)),
            phase_duration=float(tr_cfg.get("phase_duration", 10.0)),
            auto_cycle=auto_cycle,
            udp_listen_port=(
                None if use_proxy else int(tr_cfg.get("udp_listen_port", 9999))
            ),
            proxy_host=proxy_host if use_proxy else None,
            proxy_port=actual_proxy_port,
        )

        def _get_phase() -> str:
            if proxy is not None:
                ext = proxy.external_phase()
                if ext:
                    return ext
            return traffic_source.current_phase

        phase_provider = _get_phase

    engine = GAEngine(
        chromosome_length=rules_count * BITS_PER_RULE,
        population_size=int(ga_cfg.get("population_size", 50)),
        crossover_rate=float(ga_cfg.get("crossover_rate", 0.85)),
        mutation_rate=float(ga_cfg.get("mutation_rate", 0.03)),
        tournament_size=int(ga_cfg.get("tournament_size", 3)),
        elitism_count=int(ga_cfg.get("elitism_count", 2)),
        immigrant_rate=float(ga_cfg.get("immigrant_rate", 0.12)),
    )
    logger = GenerationLogger(log_path=project_root / log_path)
    snapshot_holder: Dict[str, List[Dict[str, Any]]] = {"packets": []}

    def fitness_fn_provider():
        snap = buffer.snapshot(relabel_window=True)
        if len(snap) < 10:
            return None
        snapshot_holder["packets"] = snap
        return create_firewall_fitness_fn(snap, bits_per_rule=BITS_PER_RULE)

    def on_generation(gen_stats: Dict[str, Any]) -> None:
        champ = gen_stats["best_chromosome"]
        rules = decode_chromosome_to_ruleset(champ, bits_per_rule=BITS_PER_RULE)
        packets = snapshot_holder["packets"]
        score, eval_stats = evaluate_ruleset(rules, packets)
        phase = phase_provider()

        # Re-score the currently active ruleset on this traffic snapshot so a sudden
        # attack triggers immediate replacement instead of waiting on cooldown.
        packet_count = max(1, len(packets))
        active_rules = applier.stats()["active_rules"]
        active_score, _ = evaluate_ruleset(active_rules, packets)

        applier.apply_rules(
            rules,
            generation=gen_stats["generation"],
            fitness=score / packet_count,
            current_active_fitness=active_score / packet_count,
        )

        export_best_rules(
            rules,
            output_path=project_root / rules_export_path,
            generation=gen_stats["generation"],
            fitness=score,
            traffic_phase=phase,
        )
        logger.log_generation(
            generation=gen_stats["generation"],
            best_fitness=score,
            avg_fitness=gen_stats["avg_fitness"],
            rules=rules,
            stats=eval_stats,
            traffic_phase=phase,
        )

        ap_stats = applier.stats()
        with state_lock:
            latest_state["generation"] = gen_stats["generation"]
            latest_state["best_fitness"] = score
            latest_state["avg_fitness"] = gen_stats["avg_fitness"]
            latest_state["best_rules"] = rules
            latest_state["active_rules"] = ap_stats["active_rules"]
            latest_state["applier_stats"] = ap_stats
            latest_state["eval_stats"] = eval_stats
            latest_state["buffer_stats"] = buffer.stats()
            if proxy is not None:
                latest_state["proxy_stats"] = proxy.stats()
            if target_server is not None:
                latest_state["server_stats"] = target_server.stats()
            latest_state["traffic_phase"] = phase

    traffic_source.start(stop_event)
    ga_thread = threading.Thread(
        target=engine.run_continuous,
        kwargs={
            "fitness_fn_provider": fitness_fn_provider,
            "stop_event": stop_event,
            "on_generation": on_generation,
            "step_delay": float(ga_cfg.get("step_delay", 0.25)),
        },
        daemon=True,
        name="ga-evolution-loop",
    )
    ga_thread.start()

    start_time = time.monotonic()
    try:
        with Live(
            render_live_dashboard(
                latest_state, mode, rules_export_path, log_path, enforce=use_proxy
            ),
            refresh_per_second=4,
            console=console,
        ) as live_view:
            while not stop_event.is_set():
                if duration is not None and (time.monotonic() - start_time) >= duration:
                    stop_event.set()
                    break

                if getattr(traffic_source, "error", None):
                    stop_event.set()
                    break

                with state_lock:
                    latest_state["buffer_stats"] = buffer.stats()
                    if proxy is not None:
                        latest_state["proxy_stats"] = proxy.stats()
                    if target_server is not None:
                        latest_state["server_stats"] = target_server.stats()
                    latest_state["traffic_phase"] = phase_provider()
                    snapshot_state = dict(latest_state)

                live_view.update(
                    render_live_dashboard(
                        snapshot_state,
                        mode,
                        rules_export_path,
                        log_path,
                        enforce=use_proxy,
                    )
                )
                time.sleep(0.25)
    except KeyboardInterrupt:
        stop_event.set()
    finally:
        stop_event.set()
        traffic_source.join(timeout=2.0)
        ga_thread.join(timeout=2.0)
        if proxy is not None:
            proxy.join(timeout=2.0)
        if target_server is not None:
            target_server.join(timeout=2.0)

    if getattr(traffic_source, "error", None):
        console.print(
            f"\n[bold red]❌ Sniffer error:[/bold red] {traffic_source.error}\n"
            "[yellow]Tip: Live sniffing on macOS requires sudo, or run without "
            "--mode sniffer to use the live simulator stream.[/yellow]"
        )
    else:
        p_stats = proxy.stats() if proxy is not None else {}
        s_stats = target_server.stats() if target_server is not None else {}
        summary_extra = (
            f" Proxy dropped [red]{p_stats.get('dropped_total', 0)}[/red] packets; "
            f"Server served [green]{s_stats.get('legit_received', 0)}[/green] legit "
            f"(leaked [red]{s_stats.get('attack_received', 0)}[/red] attacks)."
            if use_proxy
            else ""
        )
        console.print(
            f"\n[bold green]✅ Graceful shutdown complete.[/bold green] "
            f"Ran [yellow]{latest_state['generation']}[/yellow] generations."
            f"{summary_extra} Rules saved to [cyan]{rules_export_path}[/cyan]."
        )


@cli.command()
@click.option(
    "--type",
    "attack_type",
    type=click.Choice(["syn-flood", "port-scan", "udp-flood"], case_sensitive=False),
    default="syn-flood",
    show_default=True,
    help="Type of simulated attack burst to launch.",
)
@click.option(
    "--count",
    type=int,
    default=300,
    show_default=True,
    help="Number of attack packets to transmit.",
)
@click.option(
    "--port",
    type=int,
    default=8888,
    show_default=True,
    help="Localhost Proxy UDP port of the running firewall.",
)
@click.option(
    "--delay",
    type=float,
    default=0.005,
    show_default=True,
    help="Delay in seconds between injected packets.",
)
def attack(attack_type: str, count: int, port: int, delay: float) -> None:
    """Launches a simulated attack burst from a second terminal into live mode."""
    console.print(
        f"[bold red]🚨 Launching {attack_type.upper()}[/bold red] "
        f"({count} packets -> 127.0.0.1:{port})..."
    )
    sent = send_external_attack(
        attack_type=attack_type, count=count, port=port, delay=delay
    )
    console.print(f"[bold green]✅ Sent {sent} attack packets.[/bold green]")


@cli.command()
def static() -> None:
    """Runs Phase 3 batch evolution against static dataset.json."""
    console.print(
        Panel.fit(
            "[bold green]🧬 The Genetic Firewall — Static Dataset Mode (Phase 3)[/bold green]\n"
            "[dim]Connecting the GA Engine to the 1,000 Traffic Packets in dataset.json[/dim]",
            border_style="cyan",
        )
    )

    dataset_path = project_root / "dataset.json"
    if not dataset_path.exists():
        console.print(
            "[bold red]❌ dataset.json not found! Run src/traffic/simulator.py first.[/bold red]"
        )
        return

    with dataset_path.open("r", encoding="utf-8") as f:
        dataset = json.load(f)

    legit_count = sum(1 for p in dataset if p.get("label") == "LEGIT")
    attack_count = sum(1 for p in dataset if p.get("label") == "MALICIOUS")

    console.print(
        f"📦 [bold yellow]Loaded Dataset:[/bold yellow] {len(dataset)} total packets "
        f"([green]{legit_count} Legit[/green], [red]{attack_count} Malicious SYN Floods[/red])\n"
    )

    cfg = load_config(project_root / "configs" / "default.yaml")
    rules_count = int(cfg.get("ga", {}).get("rules_count", 8))
    fitness_fn = create_firewall_fitness_fn(
        dataset, bits_per_rule=BITS_PER_RULE
    )

    engine = GAEngine(
        chromosome_length=rules_count * BITS_PER_RULE,
        population_size=50,
        generations=30,
        crossover_rate=0.85,
        mutation_rate=0.02,
        tournament_size=3,
        elitism_count=2,
        fitness_fn=fitness_fn,
    )

    champion = engine.run(verbose=True)
    champion_rules = decode_chromosome_to_ruleset(
        champion, bits_per_rule=BITS_PER_RULE
    )
    score, stats = evaluate_ruleset(champion_rules, dataset)

    console.print()
    console.print(build_rules_table(champion_rules))

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
        "⭐ Total Fitness Score",
        f"{score:.1f}",
        f"Max Possible: {len(dataset)}",
    )

    console.print(results_table)
    plot_fitness_history(engine.history)


if __name__ == "__main__":
    cli()
