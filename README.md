# Prodigy-InfoTech-task-05
 packet sniffer tool requires low-level network programming, and it's essential to emphasize that such tools should only be used for educational purposes or in environments where you have explicit permission to monitor network traffic. Unauthorized use of packet sniffers can violate privacy laws and network security policies.

 import scapy.all as scapy

def sniff_packets(interface, count):
    print(f"\n[*] Sniffing {count} packets on interface {interface}...\n")
    scapy.sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            payload = str(packet[scapy.TCP].payload)
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            payload = str(packet[scapy.UDP].payload)
        else:
            payload = None

        print(f"Source IP: {source_ip} | Destination IP: {destination_ip} | Protocol: {protocol}")

        if payload:
            print("Payload:")
            print(payload)

interface = "eth0"  # Change this to your network interface
packet_count = 10  # Number of packets to sniff

sniff_packets(interface, packet_count)





Before running this code, make sure to install the scapy library (pip install scapy). This program captures packets on the specified network interface, extracts relevant information such as source and destination IP addresses, protocols, and payload data (if available), and prints them to the console.
