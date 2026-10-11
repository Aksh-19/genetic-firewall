import random
import json
from scapy.all import IP, TCP, UDP, Ether, wrpcap
from rich.console import Console

console = Console()

def generate_random_ip():
    """Helper function to generate a fake random IP address (e.g., 12.34.56.78)"""
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def create_dataset(num_packets=1000, attack_ratio=0.3):
    """
    Generates a mix of good and bad network packets.
    num_packets: Total number of postcards to create.
    attack_ratio: 0.3 means 30% of them will be bad (attacks).
    """
    packets = []       # This will hold simple dictionary versions for our Genetic Algorithm
    scapy_packets = [] # This will hold real Scapy packets so we can save a .pcap file
    
    num_attack = int(num_packets * attack_ratio)
    num_legit = num_packets - num_attack
    
    # --- 1. GENERATE LEGITIMATE TRAFFIC (Normal people browsing our site) ---
    for _ in range(num_legit):
        src_ip = generate_random_ip()
        dst_ip = "192.168.1.100" # Let's pretend this is our server's IP
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53]) # 80=HTTP, 443=HTTPS, 53=DNS
        
        # Normal traffic has a mix of flags. 'A' is ACK, 'PA' is Push+Ack, 'S' is SYN.
        flags = random.choice(["S", "A", "PA", "FA"]) 
        protocol = "TCP" if dst_port in [80, 443] else "UDP"
        
        # We label this packet as good!
        packet_dict = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "label": "LEGIT"
        }
        packets.append(packet_dict)
        
        # Build the actual Scapy packet (the real envelope)
        if protocol == "TCP":
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)
        else:
            pkt = Ether()/IP(src=src_ip, dst=dst_ip)/UDP(sport=src_port, dport=dst_port)
        scapy_packets.append(pkt)
        
    # --- 2. GENERATE ATTACK TRAFFIC (The Prank Callers / SYN Flood) ---
    for _ in range(num_attack):
        src_ip = generate_random_ip() # Attackers spoof (fake) their IP
        dst_ip = "192.168.1.100" 
        src_port = random.randint(1024, 65535)
        dst_port = 80 # Attackers usually target the main web door
        
        flags = "S" # SYN FLOOD! They only ever say "Hello?" and never reply.
        protocol = "TCP"
        
        # We label this packet as bad!
        packet_dict = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "flags": flags,
            "label": "MALICIOUS" 
        }
        packets.append(packet_dict)
        
        pkt = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags=flags)
        scapy_packets.append(pkt)
        
    # Shuffle the list so the attacks are hidden among the good traffic
    combined = list(zip(packets, scapy_packets))
    random.shuffle(combined)
    packets, scapy_packets = zip(*combined)
    
    return list(packets), list(scapy_packets)

if __name__ == "__main__":
    console.print("[bold cyan]Generating Traffic Dataset...[/bold cyan]")
    
    # Generate 1000 packets, 30% are attacks
    dataset_dicts, dataset_pcap = create_dataset(1000, 0.3)
    
    # Save the simple version to JSON (Our Genetic Algorithm will read this easily later)
    with open("dataset.json", "w") as f:
        json.dump(dataset_dicts, f, indent=4)
        
    # Save the complex version to a .pcap file (Standard format used by cybersecurity tools)
    wrpcap("dataset.pcap", dataset_pcap)
    
    console.print("[bold green]Done! Generated 1000 packets.[/bold green]")
    console.print("Saved to [bold yellow]dataset.json[/bold yellow] and [bold yellow]dataset.pcap[/bold yellow]")
