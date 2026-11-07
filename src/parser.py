from scapy.all import IP, UDP, TCP, Ether, ARP, Dot1Q, IPv6, ICMP, ICMPv6, DNS, HTTP, TLS, DHCP, SSH, FTP

from scapy.all import rdpcap

file_path = "sample_pcaps/dns.cap"

def get_protocols(packet):

    protocols = []

    if (packet.haslayer(UDP)):
        protocols.append("udp")

    if (packet.haslayer(TCP)):
        protocols.append("tcp")

    if (packet.haslayer(Ether)):
        protocols.append("ethernet")

    if (packet.haslayer(ARP)):
        protocols.append("arp")

    if (packet.haslayer(Dot1Q)):
        protocols.append("vlan")

    if (packet.haslayer(IP)):
        protocols.append("ipv4")

    if (packet.haslayer(IPv6)):
        protocols.append("ipv6")

    if (packet.haslayer(ICMP)):
        protocols.append("icmp")

    if (packet.haslayer(ICMPv6)):
        protocols.append("icmpv6")

    if (packet.haslayer(DNS)):
        protocols.append("dns")

    if (packet.haslayer(HTTP)):
        protocols.append("http")

    if (packet.haslayer(TLS)):
        protocols.append("https")

    if (packet.haslayer(DHCP)):
        protocols.append("dhcp")

    if (packet.haslayer(SSH)):
        protocols.append("ssh")

    if (packet.haslayer(FTP)):
        protocols.append("ftp")

    return protocols

network_data = rdpcap(file_path)
print("Number of packets", len(network_data))

for packet in network_data:
    print(f"Packet\nTimestamp: {packet.time}\nSource: {packet[0][1].src}\nDestination: {packet[0][1].dst}\nProtocol: {packet[0][1].proto}\nLength: {len(packet)}\n\n")
    print(f"Protocols: {get_protocols(packet)}\n\n")