# 🧬 The Genetic Firewall

A firewall that **evolves** its own packet-filtering rules using a genetic algorithm, adapting to new attacks the way an immune system adapts to new pathogens.

## Architecture
This project is split into several phases:
1. **Python Prototyping**: Generating simulated traffic (benign vs malicious) and creating a Genetic Algorithm (GA) to evolve firewall rules that maximize correctly filtered packets.
2. **Rust Optimization**: The packet-evaluation hot loop is written in Rust for performance, interfacing with the Python GA.

## Setup
```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
make setup
```

## Tech Stack
- **Python 3.9+** (Scapy, Numpy, Rich)
- **Rust** (Packet filtering hot-loop engine)
