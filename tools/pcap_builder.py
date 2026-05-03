from scapy.all import Ether, ARP, IP, ICMP, UDP, TCP, DNS, DNSQR, wrpcap
from pathlib import Path

OUTPUT_DIR = Path("test_pcaps")
OUTPUT_DIR.mkdir(exist_ok=True)


def write_pcap(filename, packets):
    path = OUTPUT_DIR / filename
    wrpcap(str(path), packets)
    print(f"Wrote {path}")


# -------------------------
# ARP request
# -------------------------
arp_request = Ether(
    dst="ff:ff:ff:ff:ff:ff",
    src="aa:bb:cc:dd:ee:01",
    type=0x0806
) / ARP(
    op=1,
    hwsrc="aa:bb:cc:dd:ee:01",
    psrc="192.168.1.10",
    hwdst="00:00:00:00:00:00",
    pdst="192.168.1.1"
)

# -------------------------
# ARP reply
# -------------------------
arp_reply = Ether(
    dst="aa:bb:cc:dd:ee:01",
    src="aa:bb:cc:dd:ee:ff",
    type=0x0806
) / ARP(
    op=2,
    hwsrc="aa:bb:cc:dd:ee:ff",
    psrc="192.168.1.1",
    hwdst="aa:bb:cc:dd:ee:01",
    pdst="192.168.1.10"
)

# -------------------------
# ICMP echo request
# -------------------------
icmp_echo = Ether(
    dst="aa:bb:cc:dd:ee:ff",
    src="aa:bb:cc:dd:ee:01"
) / IP(
    src="192.168.1.10",
    dst="8.8.8.8"
) / ICMP(
    type=8,
    code=0
) / b"hello"

# -------------------------
# UDP DNS query
# -------------------------
udp_dns = Ether(
    dst="aa:bb:cc:dd:ee:ff",
    src="aa:bb:cc:dd:ee:01"
) / IP(
    src="192.168.1.10",
    dst="8.8.8.8"
) / UDP(
    sport=12345,
    dport=53
) / DNS(
    rd=1,
    qd=DNSQR(qname="example.com")
)

# -------------------------
# TCP SYN
# -------------------------
tcp_syn = Ether(
    dst="aa:bb:cc:dd:ee:ff",
    src="aa:bb:cc:dd:ee:01"
) / IP(
    src="192.168.1.10",
    dst="93.184.216.34"
) / TCP(
    sport=54321,
    dport=80,
    flags="S"
)


write_pcap("arp_request.pcap", [arp_request])
write_pcap("arp_reply.pcap", [arp_reply])
write_pcap("icmp_echo.pcap", [icmp_echo])
write_pcap("udp_dns.pcap", [udp_dns])
write_pcap("tcp_syn.pcap", [tcp_syn])

write_pcap("mixed_basic.pcap", [
    arp_request,
    arp_reply,
    icmp_echo,
    udp_dns,
    tcp_syn
])