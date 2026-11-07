
from scapy.all import IP, TCP, UDP


def validate_ip_length(packet):
    """Validate IPv4 header and total packet length."""
    issues = []

    ip = packet[IP]

    # IPv4 header length must be at least 20 bytes (5 words)
    if ip.ihl is not None and ip.ihl < 5:
        issues.append("Invalid IPv4 header length")

    if ip.len is not None:
        header_length = (ip.ihl or 5) * 4

        # Total length cannot be smaller than the IP header
        if ip.len < header_length:
            issues.append("IPv4 total length smaller than header length")

        # Compare declared length against available IP bytes
        if ip.len > len(bytes(ip)):
            issues.append("Truncated IPv4 packet")

    return issues


def validate_tcp_length(packet):
    """Validate TCP header length."""
    issues = []

    tcp = packet[TCP]

    # TCP data offset is measured in 32-bit words.
    # Minimum valid TCP header is 5 words (20 bytes).
    if tcp.dataofs is not None:
        header_length = tcp.dataofs * 4

        if tcp.dataofs < 5:
            issues.append("Invalid TCP header length")

        elif header_length > len(bytes(tcp)):
            issues.append("TCP header exceeds available packet data")

    return issues


def validate_udp_length(packet):
    """Validate UDP length."""
    issues = []

    udp = packet[UDP]

    if udp.len is not None:
        # UDP header has a fixed minimum length of 8 bytes.
        if udp.len < 8:
            issues.append("Invalid UDP length")

        elif udp.len > len(bytes(udp)):
            # A fragmented IP packet may contain only part
            # of the UDP datagram, so don't flag it here.
            fragmented = (
                packet.haslayer(IP)
                and (
                    packet[IP].frag > 0
                    or "MF" in packet[IP].flags
                )
            )

            if not fragmented:
                issues.append("Truncated UDP packet")

    return issues


def validate_capture_truncation(packet):
    """Check whether the captured frame is shorter than its original length."""
    issues = []

    wire_length = getattr(packet, "wirelen", None)

    if wire_length is not None:
        captured_length = len(bytes(packet))

        if wire_length > captured_length:
            issues.append("Capture truncated: original packet was longer")

    return issues


def validate_packet(packet):
    """Run all applicable validation checks."""
    issues = []

    if packet.haslayer(IP):
        issues.extend(validate_ip_length(packet))

    if packet.haslayer(TCP):
        issues.extend(validate_tcp_length(packet))

    if packet.haslayer(UDP):
        issues.extend(validate_udp_length(packet))

    issues.extend(validate_capture_truncation(packet))

    return issues
