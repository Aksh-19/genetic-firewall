# 🧬 The Genetic Firewall

A firewall that **evolves** its own packet-filtering rules using a genetic algorithm, adapting to new attacks the way an immune system adapts to new pathogens.

## Progress
- **Phase 0–1**: Repository setup, synthetic traffic generation (`dataset.json`, `dataset.pcap`), and Scapy packet sniffing.
- **Phase 2**: Core Genetic Algorithm engine (tournament selection, crossover, mutation, elitism, random immigrants).
- **Phase 3**: Rule decoder (protocol, source IP CIDR subnet, destination port, TCP flags, action), first-match-wins evaluator, and asymmetric fitness scoring.
- **Phase 4**: Real-time evolution against a thread-safe rolling traffic buffer, behavioral heuristic labeling, rule export (`logs/best_rules.txt`), generation logging (`logs/generations.jsonl`), and a live terminal dashboard.

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
make setup
```

## Running the Firewall

### Live Adaptive Mode (Phase 4)
Start the live simulator stream and continuous GA dashboard in Terminal 1:
```bash
python src/main.py live
```
Optionally trigger an attack burst from a second terminal:
```bash
python src/main.py attack --type syn-flood --count 300
python src/main.py attack --type port-scan --count 250
python src/main.py attack --type udp-flood --count 300
```
*(To capture real interface traffic instead of the live simulator stream, run with `sudo` and `--mode sniffer --iface en0`.)*

### Static Dataset Mode (Phase 3)
```bash
python src/traffic/simulator.py
python src/main.py static
```

## Testing
```bash
make test
```

## Tech Stack
- **Python 3.9+** (`scapy`, `numpy`, `pyyaml`, `rich`, `click`, `matplotlib`)
- **Rust** (Phase 6 packet-filtering hot loop)
