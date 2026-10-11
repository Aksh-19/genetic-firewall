from scapy.all import sniff, IP, TCP, UDP
from rich.console import Console

console = Console()

def packet_callback(packet):
    """
    This function gets called every time our sniffer catches a postcard.
    It reads the envelope and prints it out nicely.
    """
    # Check if the packet has an IP address layer
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Figure out the protocol (TCP or UDP)
        protocol = "TCP" if TCP in packet else ("UDP" if UDP in packet else "OTHER")
        
        if TCP in packet:
            flags = packet[TCP].flags
            console.print(f"[green]Caught Packet:[/green] {src_ip} -> {dst_ip} | [yellow]{protocol}[/yellow] | Flags: [red]{flags}[/red]")
        else:
            console.print(f"[green]Caught Packet:[/green] {src_ip} -> {dst_ip} | [yellow]{protocol}[/yellow]")

def start_sniffing(packet_count=15):
    """
    Starts listening to the network.
    packet_count: How many postcards to grab before stopping.
    """
    console.print(f"[bold cyan]Starting sniffer... listening for the next {packet_count} packets![/bold cyan]")
    
    # The sniff function is the core of Scapy. It intercepts real traffic.
    # store=False means we don't save them in memory (keeps it fast).
    sniff(prn=packet_callback, count=packet_count, store=False)
    
    console.print("[bold green]Sniffing complete![/bold green]")

if __name__ == "__main__":
    # When you run this file, it will grab 15 packets and then stop.
    start_sniffing(15)
