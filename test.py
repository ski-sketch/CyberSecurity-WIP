from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
from scapy.layers.l2 import Ether, ARP


def analyze_packet(packet):


    if packet.haslayer(Ether):
        print("\n========== ETHERNET ==========")
        print("Source MAC: " + str(packet[Ether].src))
        print("Destination MAC: " + str(packet[Ether].dst))


    if packet.haslayer(IP):

        print("\n========== IPv4 ==========")
        print("Source IP: " + str(packet[IP].src))
        print("Destination IP: " + str(packet[IP].dst))
        print("TTL: " + str(packet[IP].ttl))


        if packet.haslayer(TCP):
            print("\n---------- TCP ----------")
            print("Source Port: " + str(packet[TCP].sport))
            print("Destination Port: " + str(packet[TCP].dport))
            print("Sequence Number: " + str(packet[TCP].seq))
            print("Acknowledgment Number: " + str(packet[TCP].ack))
            print("Flags: " + str(packet[TCP].flags))


        elif packet.haslayer(UDP):
            print("\n---------- UDP ----------")
            print("Source Port: " + str(packet[UDP].sport))
            print("Destination Port: " + str(packet[UDP].dport))
            print("Length: " + str(packet[UDP].len))
            print("Checksum: " + str(packet[UDP].chksum))


        elif packet.haslayer(ICMP):
            print("\n---------- ICMP ----------")
            print("Type: " + str(packet[ICMP].type))
            print("Code: " + str(packet[ICMP].code))
            print("Checksum: " + str(packet[ICMP].chksum))
            print("ID: " + str(packet[ICMP].id))
            print("Sequence: " + str(packet[ICMP].seq))


    if packet.haslayer(IPv6):

        print("\n========== IPv6 ==========")
        print("Source IP: " + str(packet[IPv6].src))
        print("Destination IP: " + str(packet[IPv6].dst))
        print("Hop Limit: " + str(packet[IPv6].hlim))


        if packet.haslayer(TCP):
            print("\n---------- TCP ----------")
            print("Source Port: " + str(packet[TCP].sport))
            print("Destination Port: " + str(packet[TCP].dport))
            print("Sequence Number: " + str(packet[TCP].seq))
            print("Acknowledgment Number: " + str(packet[TCP].ack))
            print("Flags: " + str(packet[TCP].flags))


        elif packet.haslayer(UDP):
            print("\n---------- UDP ----------")
            print("Source Port: " + str(packet[UDP].sport))
            print("Destination Port: " + str(packet[UDP].dport))
            print("Length: " + str(packet[UDP].len))
            print("Checksum: " + str(packet[UDP].chksum))


        elif packet.haslayer(ICMPv6EchoRequest):
            print("\n---------- ICMPv6 Echo Request ----------")
            print("Type: " + str(packet[ICMPv6EchoRequest].type))
            print("Code: " + str(packet[ICMPv6EchoRequest].code))
            print("Checksum: " + str(packet[ICMPv6EchoRequest].cksum))
            print("ID: " + str(packet[ICMPv6EchoRequest].id))
            print("Sequence: " + str(packet[ICMPv6EchoRequest].seq))


        elif packet.haslayer(ICMPv6EchoReply):
            print("\n---------- ICMPv6 Echo Reply ----------")
            print("Type: " + str(packet[ICMPv6EchoReply].type))
            print("Code: " + str(packet[ICMPv6EchoReply].code))
            print("Checksum: " + str(packet[ICMPv6EchoReply].cksum))
            print("ID: " + str(packet[ICMPv6EchoReply].id))
            print("Sequence: " + str(packet[ICMPv6EchoReply].seq))


    if packet.haslayer(ARP):

        print("\n========== ARP ==========")
        print("Hardware Type: " + str(packet[ARP].hwtype))
        print("Protocol Type: " + str(packet[ARP].ptype))
        print("Hardware Size: " + str(packet[ARP].hwlen))
        print("Protocol Size: " + str(packet[ARP].plen))
        print("Opcode: " + str(packet[ARP].op))
        print("Source MAC: " + str(packet[ARP].hwsrc))
        print("Source IP: " + str(packet[ARP].psrc))
        print("Destination MAC: " + str(packet[ARP].hwdst))
        print("Destination IP: " + str(packet[ARP].pdst))



sniff(prn=analyze_packet, timeout=10)