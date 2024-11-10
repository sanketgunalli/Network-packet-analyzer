from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

def analyze_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for TCP or UDP payloads
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")

        print("-" * 50)

# Main function to start sniffing
def start_sniffer(interface):
    print(f"Starting packet sniffer on interface: {interface}")
    sniff(iface=interface, prn=analyze_packet, store=False)

# Specify the network interface (e.g., 'eth0' for Linux or 'Wi-Fi' for Windows)
interface = input("Enter the network interface to sniff on (e.g., 'eth0', 'Wi-Fi'): ")
start_sniffer(interface)
