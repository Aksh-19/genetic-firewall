import json
import socket
import threading
import time

from src.firewall.applier import (
    PacketFilterProxy,
    RuleApplier,
    TargetServer,
    check_proxy_connectivity,
    export_os_firewall_rules,
    translate_rule_to_iptables,
    translate_rule_to_pf,
    translate_ruleset_to_iptables,
    translate_ruleset_to_pf,
)
from src.firewall.evaluator import (
    create_firewall_fitness_fn,
    evaluate_packet,
    evaluate_ruleset,
)
from src.firewall.rule import BITS_PER_RULE, Rule, decode_chromosome_to_ruleset
from src.ga.engine import GAEngine
from src.traffic.buffer import RollingTrafficBuffer
from src.traffic.labeler import HeuristicLabeler
from src.traffic.simulator import (
    make_legit_packet,
    make_syn_flood_packet,
    send_external_attack,
)


def _send_udp_packet(host: str, port: int, pkt: dict) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(json.dumps(pkt).encode("utf-8"), (host, port))
    finally:
        sock.close()


def test_translate_rules_to_iptables_and_pf(tmp_path):
    syn_drop = Rule(
        protocol="TCP",
        dst_port=80,
        flags_pattern="SYN_ONLY",
        action="DROP",
        src_ip="203.0.113.0/24",
    )
    any_port_rule = Rule(
        protocol="ANY",
        dst_port=53,
        flags_pattern="ANY",
        action="ALLOW",
    )

    ipt_cmds = translate_rule_to_iptables(syn_drop)
    assert ipt_cmds == [
        "iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 80 --syn -j DROP"
    ]
    # Protocol ANY with a specific port expands cleanly to tcp + udp for iptables
    assert len(translate_rule_to_iptables(any_port_rule)) == 2

    # Protocol ANY with SYN_ONLY scopes safely to tcp in both iptables and pf
    any_proto_syn = Rule(
        protocol="ANY",
        dst_port=None,
        flags_pattern="SYN_ONLY",
        action="DROP",
        src_ip="203.0.113.0/24",
    )
    assert translate_rule_to_iptables(any_proto_syn) == [
        "iptables -A INPUT -p tcp -s 203.0.113.0/24 --syn -j DROP"
    ]
    assert (
        translate_rule_to_pf(any_proto_syn)
        == "block drop in quick proto tcp from 203.0.113.0/24 to any flags S/SA"
    )

    pf_line = translate_rule_to_pf(syn_drop)
    assert (
        pf_line
        == "block drop in quick proto tcp from 203.0.113.0/24 to any port 80 flags S/SA"
    )

    ipt_script = "\n".join(translate_ruleset_to_iptables([syn_drop]))
    pf_conf = "\n".join(translate_ruleset_to_pf([syn_drop]))
    assert "--dport 22 -j ACCEPT" in ipt_script
    assert "pass in quick proto tcp from any to any port 22" in pf_conf

    exported = export_os_firewall_rules([syn_drop], output_dir=tmp_path)
    assert exported["iptables"].exists()
    assert exported["pf"].exists()


def test_immutable_safety_rule_prevents_ssh_lockout():
    applier = RuleApplier()
    # Even if evolution creates a rule dropping EVERYTHING, SSH (port 22) stays allowed
    hostile_evolved = [Rule(protocol="ANY", dst_port=None, flags_pattern="ANY", action="DROP")]
    safe_set = applier.compose_safe_ruleset(hostile_evolved)

    ssh_packet = {
        "src_ip": "10.0.1.15",
        "dst_ip": "192.168.1.100",
        "dst_port": 22,
        "protocol": "TCP",
        "flags": "S",
    }
    assert evaluate_packet(safe_set, ssh_packet) == "ALLOW"


def test_rate_limiting_and_significant_improvement_override():
    applier = RuleApplier(
        min_generations_between_updates=10,
        min_fitness_improvement_pct=0.05,
    )
    r1 = [Rule("TCP", 80, "SYN_ONLY", "DROP", src_ip="203.0.113.0/24")]

    # Gen 1: initial apply always succeeds
    res1 = applier.apply_rules(r1, generation=1, fitness=100.0)
    assert res1["applied"] is True

    # Gen 3 with tiny improvement (102.0 -> +2% < 5%): rate-limited
    res2 = applier.apply_rules(r1, generation=3, fitness=102.0)
    assert res2["applied"] is False
    assert res2["reason"] == "rate_limited"

    # Gen 4 with big improvement (120.0 -> +20% > 5%): overrides cooldown
    res3 = applier.apply_rules(r1, generation=4, fitness=120.0)
    assert res3["applied"] is True
    assert res3["reason"] == "significant_improvement"

    # Gen 14 (10 gens after Gen 4) with equal fitness: periodic interval triggers
    res4 = applier.apply_rules(r1, generation=14, fitness=120.0)
    assert res4["applied"] is True
    assert res4["reason"] == "periodic_interval"


def test_rate_limiting_detects_active_ruleset_degradation():
    applier = RuleApplier(
        min_generations_between_updates=10,
        min_fitness_improvement_pct=0.05,
    )
    calm_rules = [Rule("TCP", 443, "ANY", "ALLOW")]
    attack_rules = [Rule("TCP", 80, "SYN_ONLY", "DROP", src_ip="203.0.113.0/24")]

    # Gen 1: calm rules scored 1.0 per packet on calm traffic
    assert applier.apply_rules(calm_rules, generation=1, fitness=1.0)["applied"] is True

    # Gen 2: calm traffic continues -> active rules still score 1.0 -> rate-limited
    res_calm = applier.apply_rules(
        calm_rules, generation=2, fitness=1.0, current_active_fitness=1.0
    )
    assert res_calm["applied"] is False
    assert res_calm["reason"] == "rate_limited"

    # Gen 3: attack starts -> calm_rules degrade to 0.25 on current traffic,
    # while attack_rules score 1.0 -> overrides cooldown immediately!
    res_atk = applier.apply_rules(
        attack_rules, generation=3, fitness=1.0, current_active_fitness=0.25
    )
    assert res_atk["applied"] is True
    assert res_atk["reason"] == "significant_improvement"


def test_live_proxy_and_automatic_rollback(tmp_path):
    stop_event = threading.Event()
    server = TargetServer(host="127.0.0.1", port=0)
    srv_port = server.start(stop_event)

    proxy = PacketFilterProxy(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=srv_port,
    )
    proxy_port = proxy.start(stop_event)

    try:
        applier = RuleApplier(
            proxy=proxy,
            min_generations_between_updates=1,
            health_check_fn=lambda: check_proxy_connectivity(
                "127.0.0.1", proxy_port, timeout=0.25
            ),
            rollback_timeout=1.0,
            dry_run_export_dir=tmp_path,
        )

        good_rules = [
            Rule("TCP", 80, "SYN_ONLY", "DROP", src_ip="203.0.113.0/24"),
            Rule("TCP", 443, "ANY", "ALLOW", src_ip="ANY"),
        ]
        res_good = applier.apply_rules(good_rules, generation=1, fitness=500.0)
        assert res_good["applied"] is True
        assert res_good["rolled_back"] is False

        # Send a real attack packet + legit packet through the live socket proxy
        atk = make_syn_flood_packet("203.0.113")
        atk["_sim_kind"] = "MALICIOUS"
        legit = make_legit_packet()
        legit["dst_port"] = 443
        legit["protocol"] = "TCP"
        legit["flags"] = "A"
        legit["_sim_kind"] = "LEGIT"

        _send_udp_packet("127.0.0.1", proxy_port, atk)
        _send_udp_packet("127.0.0.1", proxy_port, legit)
        time.sleep(0.15)

        assert proxy.stats()["dropped_attacks"] == 1
        assert server.stats()["attack_received"] == 0
        assert server.stats()["legit_received"] == 1

        # Now try deploying a catastrophic rule dropping ALL traffic (breaking port 443).
        # Health check must fail and automatically roll back to good_rules!
        bad_rules = [Rule("ANY", None, "ANY", "DROP", src_ip="ANY")]
        res_bad = applier.apply_rules(bad_rules, generation=2, fitness=600.0, force=True)
        assert res_bad["applied"] is False
        assert res_bad["rolled_back"] is True
        assert applier.stats()["rollbacks_triggered"] == 1

        # Verify the proxy actually rolled back and still forwards legit 443 traffic!
        assert check_proxy_connectivity("127.0.0.1", proxy_port, timeout=0.3) is True
    finally:
        stop_event.set()
        proxy.join(timeout=2.0)
        server.join(timeout=2.0)


def test_end_to_end_proxy_evolution_blocks_attack():
    stop_event = threading.Event()
    labeler = HeuristicLabeler(
        window_seconds=5.0,
        syn_threshold=6,
        subnet_syn_threshold=8,
    )
    buffer = RollingTrafficBuffer(capacity=400, labeler=labeler)

    server = TargetServer(host="127.0.0.1", port=0)
    srv_port = server.start(stop_event)

    proxy = PacketFilterProxy(
        listen_host="127.0.0.1",
        listen_port=0,
        target_host="127.0.0.1",
        target_port=srv_port,
        traffic_buffer=buffer,
    )
    proxy_port = proxy.start(stop_event)

    try:
        applier = RuleApplier(
            proxy=proxy,
            min_generations_between_updates=4,
            health_check_fn=lambda: check_proxy_connectivity(
                "127.0.0.1", proxy_port, timeout=0.3
            ),
            rollback_timeout=1.0,
        )

        # Stream mixed normal + SYN flood traffic into the Proxy socket
        for _ in range(30):
            pkt = make_legit_packet()
            pkt["dst_port"] = 443
            pkt["protocol"] = "TCP"
            pkt["flags"] = "A"
            pkt["_sim_kind"] = "LEGIT"
            _send_udp_packet("127.0.0.1", proxy_port, pkt)

        send_external_attack(
            attack_type="syn-flood",
            count=40,
            host="127.0.0.1",
            port=proxy_port,
            delay=0.0,
        )
        time.sleep(0.25)

        snap = buffer.snapshot(relabel_window=True)
        assert len(snap) >= 50

        engine = GAEngine(
            chromosome_length=6 * BITS_PER_RULE,
            population_size=40,
            generations=20,
            crossover_rate=0.85,
            mutation_rate=0.04,
            elitism_count=2,
            immigrant_rate=0.12,
            fitness_fn=create_firewall_fitness_fn(snap, bits_per_rule=BITS_PER_RULE),
        )
        champ = engine.run(verbose=False)
        rules = decode_chromosome_to_ruleset(champ, bits_per_rule=BITS_PER_RULE)
        score, _ = evaluate_ruleset(rules, snap)

        res = applier.apply_rules(rules, generation=20, fitness=score, force=True)
        assert res["applied"] is True

        # Blast 20 more SYN flood packets + 10 legit packets AFTER rule application
        leaked_before = server.stats()["attack_received"]
        legit_before = server.stats()["legit_received"]

        send_external_attack(
            attack_type="syn-flood",
            count=20,
            host="127.0.0.1",
            port=proxy_port,
            delay=0.0,
        )
        for _ in range(10):
            pkt = make_legit_packet()
            pkt["dst_port"] = 443
            pkt["protocol"] = "TCP"
            pkt["flags"] = "A"
            pkt["_sim_kind"] = "LEGIT"
            _send_udp_packet("127.0.0.1", proxy_port, pkt)
        time.sleep(0.25)

        assert proxy.stats()["dropped_attacks"] >= 15
        assert server.stats()["attack_received"] - leaked_before <= 3
        assert server.stats()["legit_received"] - legit_before >= 8
    finally:
        stop_event.set()
        proxy.join(timeout=2.0)
        server.join(timeout=2.0)
