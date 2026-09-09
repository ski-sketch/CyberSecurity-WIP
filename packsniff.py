from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, Ether
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")
        print(f"TCP Source Port: {tcp_sport}, TCP Destination Port: {tcp_dport}")
print("Starting packet sniffing...")
print(sniff(count=10, prn=process_packet))