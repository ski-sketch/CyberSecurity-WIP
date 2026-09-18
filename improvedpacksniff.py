from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, Ether
packet = sniff(timeout=1)
packet.show()
print(packet[0].layers())
if packet[0].haslayer(IP):
    print(packet[0].show())
print(len(packet[0]))
print(packet[0][IP].len)
print(packet[0][TCP].dataofs * 4)