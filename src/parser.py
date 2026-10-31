from scapy.all import rdpcap

file_path = "sample_pcaps/dns.cap"

network_data = rdpcap(file_path)
print("Number of packets", len(network_data))

for packet in network_data:
    pass