from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP,ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
packet = sniff(timeout=10)
lenpacket = len(packet)
for i in range(lenpacket):
    if packet[i].haslayer(Ether):
        if packet[i].haslayer(IP):
            if packet[i].haslayer(TCP):
                print ("TCP Packet")
            elif packet[i].haslayer(UDP):
                print ("UDP Packet")
            elif packet[i].haslayer(ICMP):
                print ("ICMP Packet")
        if packet[i].haslayer(IPv6):
            if packet[i].haslayer(TCP):
                print ("TCP Packet")
            elif packet[i].haslayer(UDP):
                print ("UDP Packet")
            elif packet[i].haslayer(ICMPv6EchoRequest):
                print ("ICMPv6 Echo Request Packet")
            elif packet[i].haslayer(ICMPv6EchoReply):
                print ("ICMPv6 Echo Reply Packet")
    if packet[i].haslayer(ARP):
        print ("ARP Packet")