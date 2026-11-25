from datetime import datetime, timezone
import json
from pathlib import Path
import threading
from typing import Any, Dict, List, Optional, Union

from src.firewall.rule import Rule, format_ruleset


def export_best_rules(
    rules: List[Rule],
    output_path: Union[str, Path] = "logs/best_rules.txt",
    generation: Optional[int] = None,
    fitness: Optional[float] = None,
    traffic_phase: Optional[str] = None,
) -> Path:
    """
    Exports the current champion ruleset to a human-readable text file.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header_parts = [f"Updated: {timestamp}"]
    if generation is not None:
        header_parts.append(f"Generation: {generation}")
    if fitness is not None:
        header_parts.append(f"Fitness: {fitness:.2f}")
    if traffic_phase:
        header_parts.append(f"Phase: {traffic_phase}")

    content = (
        "# Genetic Firewall - Exported Champion Ruleset\n"
        f"# {' | '.join(header_parts)}\n"
        f"{format_ruleset(rules)}\n"
    )
    path.write_text(content, encoding="utf-8")
    return path


class GenerationLogger:
    """
    Thread-safe JSON Lines logger recording generation metrics and evolved
    rulesets to logs/ for experiment tracking and post-run analysis.
    """

    def __init__(self, log_path: Union[str, Path] = "logs/generations.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_generation(
        self,
        generation: int,
        best_fitness: float,
        avg_fitness: float,
        rules: List[Rule],
        stats: Optional[Dict[str, int]] = None,
        traffic_phase: str = "UNKNOWN",
    ) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generation": generation,
            "best_fitness": round(float(best_fitness), 4),
            "avg_fitness": round(float(avg_fitness), 4),
            "num_rules": len(rules),
            "traffic_phase": traffic_phase,
            "stats": stats or {},
            "best_rules": [
                rule.to_export_line(idx) for idx, rule in enumerate(rules, 1)
            ],
        }

        line = json.dumps(record) + "\n"
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()

        return record
