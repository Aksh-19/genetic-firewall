import json
from pathlib import Path
import socket
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from src.firewall.evaluator import evaluate_packet
from src.firewall.rule import Rule

DEFAULT_SAFETY_RULES: List[Rule] = [
    Rule(
        protocol="TCP",
        dst_port=22,
        flags_pattern="ANY",
        action="ALLOW",
        src_ip="ANY",
    ),
]


def _iptables_flag_args(flags_pattern: str) -> List[str]:
    if flags_pattern == "SYN_ONLY":
        return ["--syn"]
    if flags_pattern == "ACK":
        return ["--tcp-flags", "ACK", "ACK"]
    return []


def translate_rule_to_iptables(rule: Rule, chain: str = "INPUT") -> List[str]:
    """
    Translates an internal Rule into one or more Linux iptables CLI commands.
    If protocol is ANY and flags are matched (SYN_ONLY/ACK), scopes to tcp
    because TCP flags only apply to TCP. If protocol is ANY with dst_port and
    no flags filter, emits both tcp and udp rules.
    """
    target = "DROP" if rule.action == "DROP" else "ACCEPT"
    if rule.protocol == "ANY":
        if rule.flags_pattern != "ANY":
            protocols: List[Optional[str]] = ["tcp"]
        elif rule.dst_port is not None:
            protocols = ["tcp", "udp"]
        else:
            protocols = [None]
    else:
        protocols = [rule.protocol.lower()]

    commands: List[str] = []
    for proto in protocols:
        parts = ["iptables", "-A", chain]
        if proto is not None:
            parts.extend(["-p", proto])
        if rule.src_ip != "ANY":
            parts.extend(["-s", rule.src_ip])
        if rule.dst_ip != "ANY":
            parts.extend(["-d", rule.dst_ip])
        if rule.dst_port is not None:
            parts.extend(["--dport", str(rule.dst_port)])
        if proto == "tcp":
            parts.extend(_iptables_flag_args(rule.flags_pattern))
        parts.extend(["-j", target])
        commands.append(" ".join(parts))

    return commands


def translate_ruleset_to_iptables(
    ruleset: List[Rule],
    chain: str = "INPUT",
    safety_rules: Optional[List[Rule]] = None,
) -> List[str]:
    """Translates an ordered ruleset (plus safety rules) into iptables commands."""
    lines = ["#!/usr/bin/env bash", "# Dry-run iptables commands (Linux)", f"iptables -F {chain}"]
    effective_safety = DEFAULT_SAFETY_RULES if safety_rules is None else safety_rules
    if effective_safety:
        lines.append("# --- Immutable Safety Rules ---")
        for rule in effective_safety:
            lines.extend(translate_rule_to_iptables(rule, chain=chain))
    lines.append("# --- Evolved Rules ---")
    for rule in ruleset:
        lines.extend(translate_rule_to_iptables(rule, chain=chain))
    return lines


def translate_rule_to_pf(rule: Rule) -> str:
    """
    Translates an internal Rule into macOS Packet Filter (pf / pfctl) syntax.
    Uses `quick` so pf matches first-match-wins instead of its default last-match.
    """
    action = "block drop" if rule.action == "DROP" else "pass"
    parts = [action, "in", "quick"]
    has_tcp_flags = rule.flags_pattern != "ANY"
    if rule.protocol == "UDP":
        parts.extend(["proto", "udp"])
    elif rule.protocol == "TCP" or has_tcp_flags:
        parts.extend(["proto", "tcp"])
    elif rule.dst_port is not None:
        parts.extend(["proto", "{ tcp udp }"])

    src = "any" if rule.src_ip == "ANY" else rule.src_ip
    dst = "any" if rule.dst_ip == "ANY" else rule.dst_ip
    parts.extend(["from", src, "to", dst])

    if rule.dst_port is not None:
        parts.extend(["port", str(rule.dst_port)])

    if rule.protocol != "UDP":
        if rule.flags_pattern == "SYN_ONLY":
            parts.extend(["flags", "S/SA"])
        elif rule.flags_pattern == "ACK":
            parts.extend(["flags", "A/A"])

    return " ".join(parts)


def translate_ruleset_to_pf(
    ruleset: List[Rule],
    safety_rules: Optional[List[Rule]] = None,
) -> List[str]:
    """Translates an ordered ruleset (plus safety rules) into macOS pf syntax."""
    lines = ["# Dry-run macOS pf (pfctl) anchor rules"]
    effective_safety = DEFAULT_SAFETY_RULES if safety_rules is None else safety_rules
    if effective_safety:
        lines.append("# --- Immutable Safety Rules ---")
        for rule in effective_safety:
            lines.append(translate_rule_to_pf(rule))
    lines.append("# --- Evolved Rules ---")
    for rule in ruleset:
        lines.append(translate_rule_to_pf(rule))
    return lines


def export_os_firewall_rules(
    ruleset: List[Rule],
    output_dir: Union[str, Path] = "logs",
    safety_rules: Optional[List[Rule]] = None,
) -> Dict[str, Path]:
    """Writes dry-run iptables and macOS pf rule translations to disk."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    iptables_path = out / "rules_iptables.sh"
    pf_path = out / "rules_pf.conf"

    iptables_text = "\n".join(
        translate_ruleset_to_iptables(ruleset, safety_rules=safety_rules)
    ) + "\n"
    pf_text = "\n".join(
        translate_ruleset_to_pf(ruleset, safety_rules=safety_rules)
    ) + "\n"

    iptables_path.write_text(iptables_text, encoding="utf-8")
    pf_path.write_text(pf_text, encoding="utf-8")
    return {"iptables": iptables_path, "pf": pf_path}


class TargetServer:
    """
    Lightweight protected backend server sitting behind PacketFilterProxy.
    Counts legitimate vs attack packets that make it past the firewall and
    responds 'OK' to health-check probes so RuleApplier can verify connectivity.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8889):
        self.host = host
        self.port = port
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self.total_received = 0
        self.legit_received = 0
        self.attack_received = 0
        self.health_checks_ok = 0
        self.bound_port = port

    def bind(self) -> int:
        if self._sock is not None:
            return self.bound_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        sock.bind((self.host, self.port))
        self._sock = sock
        self.bound_port = int(sock.getsockname()[1])
        return self.bound_port

    def _serve_loop(self, stop_event: threading.Event) -> None:
        assert self._sock is not None
        try:
            while not stop_event.is_set():
                try:
                    data, addr = self._sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    pkt = json.loads(data.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue

                if pkt.get("is_health_check"):
                    with self._lock:
                        self.health_checks_ok += 1
                    try:
                        self._sock.sendto(b'{"status":"OK"}', addr)
                    except OSError:
                        pass
                    continue

                kind = pkt.get("_sim_kind", "LEGIT")
                with self._lock:
                    self.total_received += 1
                    if kind == "MALICIOUS":
                        self.attack_received += 1
                    else:
                        self.legit_received += 1
        finally:
            if self._sock is not None:
                self._sock.close()
                self._sock = None

    def start(self, stop_event: threading.Event) -> int:
        port = self.bind()
        self._thread = threading.Thread(
            target=self._serve_loop,
            args=(stop_event,),
            daemon=True,
            name="target-server",
        )
        self._thread.start()
        return port

    def join(self, timeout: float = 2.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_received": self.total_received,
                "legit_received": self.legit_received,
                "attack_received": self.attack_received,
                "health_checks_ok": self.health_checks_ok,
            }


class PacketFilterProxy:
    """
    Filtering proxy sitting in front of TargetServer.
    Intercepts incoming packets, inspects them against the active ruleset,
    silently drops DROP matches, forwards ALLOW packets to TargetServer,
    and optionally taps observed traffic into RollingTrafficBuffer.
    """

    def __init__(
        self,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8888,
        target_host: str = "127.0.0.1",
        target_port: int = 8889,
        traffic_buffer: Optional[Any] = None,
        initial_rules: Optional[List[Rule]] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.traffic_buffer = traffic_buffer

        self._rules_lock = threading.Lock()
        self._active_rules: List[Rule] = list(initial_rules or DEFAULT_SAFETY_RULES)

        self._stats_lock = threading.Lock()
        self.received_total = 0
        self.forwarded_total = 0
        self.dropped_total = 0
        self.dropped_attacks = 0
        self.dropped_legit = 0
        self._external_phase = ""
        self._external_until = 0.0

        self._sock: Optional[socket.socket] = None
        self._forward_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self.bound_port = listen_port

    def set_rules(self, rules: List[Rule]) -> None:
        with self._rules_lock:
            self._active_rules = list(rules)

    def get_rules(self) -> List[Rule]:
        with self._rules_lock:
            return list(self._active_rules)

    def bind(self) -> int:
        if self._sock is not None:
            return self.bound_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        sock.bind((self.listen_host, self.listen_port))
        self._sock = sock
        self._forward_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bound_port = int(sock.getsockname()[1])
        return self.bound_port

    def _forward_health_check(self, raw_data: bytes, client_addr: Tuple[str, int]) -> None:
        assert self._sock is not None
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe_sock.settimeout(0.4)
        try:
            probe_sock.sendto(raw_data, (self.target_host, self.target_port))
            reply, _ = probe_sock.recvfrom(1024)
            self._sock.sendto(reply, client_addr)
        except OSError:
            pass
        finally:
            probe_sock.close()

    def _proxy_loop(self, stop_event: threading.Event) -> None:
        assert self._sock is not None
        assert self._forward_sock is not None
        try:
            while not stop_event.is_set():
                try:
                    data, client_addr = self._sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break

                try:
                    pkt = json.loads(data.decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue

                pkt.setdefault("timestamp", time.time())
                is_probe = bool(pkt.get("is_health_check", False))

                # Tap real non-probe packets into RollingTrafficBuffer with any
                # scoreboard metadata stripped so HeuristicLabeler cannot cheat.
                if not is_probe and self.traffic_buffer is not None:
                    if pkt.get("attack_type"):
                        with self._stats_lock:
                            self._external_phase = str(pkt["attack_type"])
                            self._external_until = time.time() + 3.0
                    observed = {
                        k: v for k, v in pkt.items() if not k.startswith("_")
                    }
                    self.traffic_buffer.add_packet(observed, auto_label=True)

                rules = self.get_rules()
                decision = evaluate_packet(rules, pkt, default_action="ALLOW")

                if is_probe:
                    if decision == "ALLOW":
                        self._forward_health_check(data, client_addr)
                    continue

                kind = pkt.get("_sim_kind", "LEGIT")
                if decision == "DROP":
                    with self._stats_lock:
                        self.received_total += 1
                        self.dropped_total += 1
                        if kind == "MALICIOUS":
                            self.dropped_attacks += 1
                        else:
                            self.dropped_legit += 1
                    continue

                with self._stats_lock:
                    self.received_total += 1
                    self.forwarded_total += 1

                try:
                    self._forward_sock.sendto(data, (self.target_host, self.target_port))
                except OSError:
                    pass
        finally:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            if self._forward_sock is not None:
                self._forward_sock.close()
                self._forward_sock = None

    def start(self, stop_event: threading.Event) -> int:
        port = self.bind()
        self._thread = threading.Thread(
            target=self._proxy_loop,
            args=(stop_event,),
            daemon=True,
            name="packet-filter-proxy",
        )
        self._thread.start()
        return port

    def join(self, timeout: float = 2.0) -> None:
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def external_phase(self) -> Optional[str]:
        with self._stats_lock:
            if time.time() < self._external_until and self._external_phase:
                return f"EXTERNAL:{self._external_phase}"
            return None

    def stats(self) -> Dict[str, int]:
        with self._stats_lock:
            return {
                "received_total": self.received_total,
                "forwarded_total": self.forwarded_total,
                "dropped_total": self.dropped_total,
                "dropped_attacks": self.dropped_attacks,
                "dropped_legit": self.dropped_legit,
            }


def check_proxy_connectivity(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 8888,
    timeout: float = 0.5,
) -> bool:
    """
    Sends real SSH (port 22) and normal HTTPS (port 443 ACK) health-check probes
    through the live proxy to verify TargetServer remains reachable.
    """
    probes = [
        {
            "src_ip": "10.0.1.250",
            "dst_ip": "192.168.1.100",
            "dst_port": 22,
            "protocol": "TCP",
            "flags": "A",
            "is_health_check": True,
        },
        {
            "src_ip": "10.0.1.250",
            "dst_ip": "192.168.1.100",
            "dst_port": 443,
            "protocol": "TCP",
            "flags": "A",
            "is_health_check": True,
        },
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for probe in probes:
            sock.sendto(json.dumps(probe).encode("utf-8"), (proxy_host, proxy_port))
            reply, _ = sock.recvfrom(1024)
            payload = json.loads(reply.decode("utf-8"))
            if payload.get("status") != "OK":
                return False
        return True
    except (OSError, ValueError):
        return False
    finally:
        sock.close()


class RuleApplier:
    """
    Safely deploys evolved rulesets to the live firewall proxy (and dry-run OS
    rule exports) with four production safeguards:
      1. Immutable safety rules pinned above all evolved rules.
      2. Rate limiting (every N generations or >X% fitness improvement).
      3. Backup of previous working ruleset before every swap.
      4. Automatic rollback if post-apply connectivity health check fails/times out.
    """

    def __init__(
        self,
        proxy: Optional[PacketFilterProxy] = None,
        safety_rules: Optional[List[Rule]] = None,
        min_generations_between_updates: int = 8,
        min_fitness_improvement_pct: float = 0.05,
        health_check_fn: Optional[Callable[[], bool]] = None,
        rollback_timeout: float = 1.0,
        dry_run_export_dir: Optional[Union[str, Path]] = None,
    ):
        self.proxy = proxy
        self.safety_rules = list(
            DEFAULT_SAFETY_RULES if safety_rules is None else safety_rules
        )
        self.min_generations_between_updates = min_generations_between_updates
        self.min_fitness_improvement_pct = min_fitness_improvement_pct
        self.health_check_fn = health_check_fn
        self.rollback_timeout = rollback_timeout
        self.dry_run_export_dir = dry_run_export_dir

        self._lock = threading.Lock()
        self.active_rules: List[Rule] = list(self.safety_rules)
        self.backup_rules: Optional[List[Rule]] = None
        self.active_fitness: Optional[float] = None
        self.last_update_generation = 0

        self.updates_applied = 0
        self.updates_skipped_rate_limit = 0
        self.rollbacks_triggered = 0
        self.last_status = "INITIALIZED (safety rules only)"

        if self.proxy is not None:
            self.proxy.set_rules(self.active_rules)

    def compose_safe_ruleset(self, evolved_rules: List[Rule]) -> List[Rule]:
        """Pins immutable safety rules at the top before any evolved rules."""
        return list(self.safety_rules) + list(evolved_rules)

    def should_update(self, generation: int, candidate_fitness: float) -> Tuple[bool, str]:
        """Applies rate limiting so live rules don't flicker every generation."""
        if self.active_fitness is None:
            return True, "initial_apply"

        gens_elapsed = generation - self.last_update_generation
        if gens_elapsed >= self.min_generations_between_updates:
            return True, "periodic_interval"

        # Significant fitness jump overrides the periodic cooldown
        if self.active_fitness <= 0:
            if candidate_fitness > self.active_fitness:
                return True, "significant_improvement"
        else:
            improvement = (candidate_fitness - self.active_fitness) / abs(
                self.active_fitness
            )
            if improvement > self.min_fitness_improvement_pct:
                return True, "significant_improvement"

        return False, "rate_limited"

    def _verify_health(self) -> bool:
        if self.health_check_fn is None:
            return True
        started = time.monotonic()
        try:
            ok = bool(self.health_check_fn())
        except Exception:
            return False
        elapsed = time.monotonic() - started
        return ok and elapsed <= self.rollback_timeout

    def apply_rules(
        self,
        evolved_rules: List[Rule],
        generation: int,
        fitness: float,
        force: bool = False,
    ) -> Dict[str, Any]:
        """
        Safely deploys a candidate evolved ruleset, backing up the previous
        rules and rolling back automatically if health verification fails.
        """
        with self._lock:
            if not force:
                allowed, reason = self.should_update(generation, fitness)
                if not allowed:
                    self.updates_skipped_rate_limit += 1
                    self.last_status = f"RATE_LIMITED (gen={generation})"
                    return {
                        "applied": False,
                        "rolled_back": False,
                        "reason": reason,
                    }
            else:
                reason = "forced"

            prev_rules = list(self.active_rules)
            prev_fitness = self.active_fitness
            candidate = self.compose_safe_ruleset(evolved_rules)

            self.active_rules = candidate
            if self.proxy is not None:
                self.proxy.set_rules(candidate)

            if not self._verify_health():
                self.active_rules = prev_rules
                self.active_fitness = prev_fitness
                if self.proxy is not None:
                    self.proxy.set_rules(prev_rules)
                self.rollbacks_triggered += 1
                self.last_status = f"ROLLED_BACK (gen={generation})"
                return {
                    "applied": False,
                    "rolled_back": True,
                    "reason": "health_check_failed",
                }

            self.backup_rules = prev_rules
            self.active_fitness = fitness
            self.last_update_generation = generation
            self.updates_applied += 1
            self.last_status = f"APPLIED ({reason} @ gen={generation})"

            if self.dry_run_export_dir is not None:
                export_os_firewall_rules(
                    evolved_rules,
                    output_dir=self.dry_run_export_dir,
                    safety_rules=self.safety_rules,
                )

            return {
                "applied": True,
                "rolled_back": False,
                "reason": reason,
                "rule_count": len(candidate),
            }

    def rollback(self) -> bool:
        """Manually reverts to the last backed-up ruleset."""
        with self._lock:
            if self.backup_rules is None:
                return False
            self.active_rules = list(self.backup_rules)
            if self.proxy is not None:
                self.proxy.set_rules(self.active_rules)
            self.rollbacks_triggered += 1
            self.last_status = "MANUAL_ROLLBACK"
            return True

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "active_rule_count": len(self.active_rules),
                "active_rules": list(self.active_rules),
                "active_fitness": self.active_fitness,
                "last_update_generation": self.last_update_generation,
                "updates_applied": self.updates_applied,
                "updates_skipped_rate_limit": self.updates_skipped_rate_limit,
                "rollbacks_triggered": self.rollbacks_triggered,
                "last_status": self.last_status,
            }
