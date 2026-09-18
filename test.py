from scapy.all import sniff
from scapy.layers.inet import IP,TCP,UDP,ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP
packet = sniff(timeout=2)
lenpacket = len(packet)
for i in range(lenpacket):
    if packet[i].haslayer(Ether):
        if packet[i].haslayer(IP):
            if packet[i].haslayer(TCP):
                print ("TCP Packet")
                print("Source Port: " + str(packet[i][TCP].sport) +
                      "\nSource IP: " + str(packet[i][IP].src) +
                      "\nDestination Port: " + str(packet[i][TCP].dport) +
                      "\nDestination IP: " + str(packet[i][IP].dst) +
                      "\nSequence Number: " + str(packet[i][TCP].seq) +
                      "\nAcknowledgment Number: " + str(packet[i][TCP].ack) +
                      "\nFlags: " + str(packet[i][TCP].flags))
            elif packet[i].haslayer(UDP):
                print ("UDP Packet")
                print("Source Port: " + str(packet[i][UDP].sport) +
                      "\nDestination Port: " + str(packet[i][UDP].dport) +
                      "\nLength: " + str(packet[i][UDP].len) +
                      "\nChecksum: " + str(packet[i][UDP].chksum))
            elif packet[i].haslayer(ICMP):
                print ("ICMP Packet")
                print("Type: " + str(packet[i][ICMP].type) +
                      "\nCode: " + str(packet[i][ICMP].code) +
                      "\nChecksum: " + str(packet[i][ICMP].chksum) +
                      "\nID: " + str(packet[i][ICMP].id) +
                      "\nSequence: " + str(packet[i][ICMP].seq))
        if packet[i].haslayer(IPv6):
            if packet[i].haslayer(TCP):
                print ("TCP Packet")
                print("Source Port: " + str(packet[i][TCP].sport) +
                      "\nSource IP: " + str(packet[i][IPv6].src) +
                      "\nDestination Port: " + str(packet[i][TCP].dport) +
                      "\nDestination IP: " + str(packet[i][IPv6].dst) +
                      "\nSequence Number: " + str(packet[i][TCP].seq) +
                      "\nAcknowledgment Number: " + str(packet[i][TCP].ack) +
                      "\nFlags: " + str(packet[i][TCP].flags))
            elif packet[i].haslayer(UDP):
                print ("UDP Packet")
                print("Source Port: " + str(packet[i][UDP].sport) +
                      "\nDestination Port: " + str(packet[i][UDP].dport) +
                      "\nLength: " + str(packet[i][UDP].len) +
                      "\nChecksum: " + str(packet[i][UDP].chksum))
            elif packet[i].haslayer(ICMPv6EchoRequest):
                print ("ICMPv6 Echo Request Packet")
                print("Type: " + str(packet[i][ICMPv6EchoRequest].type) +
                      "\nCode: " + str(packet[i][ICMPv6EchoRequest].code) +
                      "\nChecksum: " + str(packet[i][ICMPv6EchoRequest].cksum) +
                      "\nID: " + str(packet[i][ICMPv6EchoRequest].id) +
                      "\nSequence: " + str(packet[i][ICMPv6EchoRequest].seq))
            elif packet[i].haslayer(ICMPv6EchoReply):
                print ("ICMPv6 Echo Reply Packet")
                print("Type: " + str(packet[i][ICMPv6EchoReply].type) +
                      "\nCode: " + str(packet[i][ICMPv6EchoReply].code) +
                      "\nChecksum: " + str(packet[i][ICMPv6EchoReply].cksum) +
                      "\nID: " + str(packet[i][ICMPv6EchoReply].id) +
                      "\nSequence: " + str(packet[i][ICMPv6EchoReply].seq))
    if packet[i].haslayer(ARP):
        print ("ARP Packet")
        print("Hardware Type: " + str(packet[i][ARP].hwtype) +
              "\nProtocol Type: " + str(packet[i][ARP].ptype) +
              "\nHardware Size: " + str(packet[i][ARP].hwlen) +
              "\nProtocol Size: " + str(packet[i][ARP].plen) +
              "\nOpcode: " + str(packet[i][ARP].op) +
              "\nSource MAC: " + str(packet[i][ARP].hwsrc) +
              "\nSource IP: " + str(packet[i][ARP].psrc) +
              "\nDestination MAC: " + str(packet[i][ARP].hwdst) +
              "\nDestination IP: " + str(packet[i][ARP].pdst))