import struct
from collections import namedtuple
from src.parsers.l2parsers.ethernet import EthernetParser
from src.parsers.l3parsers.ipv4parser import Ipv4Parser
from src.parsers.l3parsers.arpparser import ArpParser
from src.parsers.l4parsers.icmpparser import ICMPParser
from src.parsers.l4parsers.udpparser import UDPParser
from src.parsers.l4parsers.tcpparser import TCPParser


version = "v0.1"
GlobalHeader = namedtuple("GlobalHeader", "ver_maj ver_min gmt_to_local sigfigs snap_len linktype")
PacketHeader = namedtuple("PacketHeader", "ts_sec ts_subsec incl_len orig_len")

LINKTYPES = { # Move to maps later
    1: "Ethernet",
    9: "Point-to-point protocol (PPP)",
    101: "Raw IP",
    105: "802.11 wireless LAN",
    113: "Linux 'cooked' capture encapsulation (SLL)",
    127: "802.11 with radio-tap header"
}

L2PARSERS = { # Maybe add to a registry later??
    1: EthernetParser(),
    9: "PppParser",
    101: "RawIpParser"
}

ETHERTYPES = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x8100: "802.1Q VLAN"
}

L3PARSERS = {
    0x0800: Ipv4Parser(),
    #0x86DD: "ipv6parser",
    0x0806: ArpParser(),
    #0x8100: "802vlanparser"
}

IP_PROTOCOLS = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    43: "IPv6-Route",
    44: "IPv6-Frag",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP"
}

L4PARSERS = {
    1: ICMPParser(),
    6: TCPParser(),
    17: UDPParser(),
}


def check_endian(magic):
    if magic == b"\xd4\xc3\xb2\xa1":
        print("Little-endian | Micro-seconds")
        return "<", "us"
    elif magic == b"\xa1\xb2\xc3\xd4":
        print("Big-endian | Micro-seconds")
        return ">", "us"
    elif magic == b"\x4d\x3c\xb2\xa1":
        print("Little-endian | Nano-seconds")
        return "<", "ns"
    elif magic == b"\xa1\xb2\x3c\x4d":
        print("Big-endian | Nano-seconds")
        return ">", "ns"
    else:
        print("No classic .pcap header format detected. Please make sure to select a .pcap file.")
        raise SystemExit("Program terminated.")

def unpack_network_info(raw_global_header, endian):
    (ver_maj, ver_min, gmt_to_local, sigfigs, snap_len, linktype) = struct.unpack(endian + "HHIIII", raw_global_header)
    print(f"\nSee-ZD PCAP Analyzer {version} | Max packet length: {snap_len} bytes | Linktype: {linktype}\n")
    if (ver_maj, ver_min) != (2, 4):
        print(f"Non-standard .pcap version used.")
    if snap_len <= 60:
        print(f"Packet size small. Packets may be truncated.")
    return GlobalHeader(ver_maj, ver_min, gmt_to_local, sigfigs, snap_len, linktype)

def print_link_layer_type(link_unpacked):
    if link_unpacked in LINKTYPES:
        print(f"Network type: {LINKTYPES[link_unpacked]}")
    else:
        raise SystemExit("Unsupported as of yet. Program terminated.")

def unpack_packet_header(raw_packet_header, endian, packet_number):
    (ts_sec, ts_subsec, incl_len, orig_len) = struct.unpack(endian + "IIII", raw_packet_header)
    print(f"Packet {packet_number} | {incl_len} / {orig_len} bytes.")
    return PacketHeader(ts_sec, ts_subsec, incl_len, orig_len)

def get_l2_parser(link_unpacked):
    parser = L2PARSERS.get(link_unpacked)
    if not parser:
        raise NotImplementedError(f"Unsupported linktype, but soon to be implemented.")
    print(f"Fetching {parser.__class__.__name__}...\n")
    return parser

def run_l2_parser(data, parser):
    l2 = parser.parse(data)
    return l2

def get_l3_parser(l2_ethertype):
    print(f"Ethertype: 0x{l2_ethertype:04X}")
    parser = L3PARSERS.get(l2_ethertype)
    if not parser:
        print("Ethertype not supported\n")
        parser = "skip" #TEMPORARY: FOR TESTING
    else:
        print(f"Fetching {parser.__class__.__name__}...")
    return parser

def run_l3_parser(data, parser):
    l3 = parser.parse(data)
    return l3

def get_l4_parser(l3_protocol):
    print(f"Protocol: {l3_protocol}")
    parser = L4PARSERS.get(l3_protocol)
    if not parser:
        print("Protocol not supported\n")
        parser = "skip"
    else:
        print(f"Fetching {parser.__class__.__name__}...")
    return parser

def run_l4_parser(data, parser):
    l4 = parser.parse(data)
    return l4

class Analyzer:
    def __init__(self, strict=True):
        self.strict = strict

    def analyze(self, file_path):
        with open(file_path, "rb") as packets_file:
            return self._process_file(packets_file)
        
    def _process_file(self, packets_file):
        magic = packets_file.read(4)
        endian, time_precision = check_endian(magic)

        raw_global_header = packets_file.read(20)
        unpacked_global_header = unpack_network_info(raw_global_header, endian)

        print_link_layer_type(unpacked_global_header.linktype)
        l2_parser = get_l2_parser(unpacked_global_header.linktype)

        all_packets = []
        packet_number = 0
        while True:
            packet = {
                "number": None,
                "header": None,
                "l2": None,
                "l3": None,
                "l4": None
            }

            packet_number += 1
            packet["number"] = packet_number
            raw_packet_header = packets_file.read(16)
            if len(raw_packet_header) < 16:
                print(f"Reading completed.\n")
                break
            
            unpacked_packet_header = unpack_packet_header(raw_packet_header, endian, packet_number)
            packet["header"] = unpacked_packet_header

            data = packets_file.read(unpacked_packet_header.incl_len)
            if len(data) < unpacked_packet_header.incl_len:
                print("Packet is truncated.")
                break
            
            l2_info = run_l2_parser(data, l2_parser)
            packet["l2"] = l2_info
            print("Layer 2 complete.")

            ethertype = packet["l2"]["ethertype"]
            l3_parser = get_l3_parser(ethertype)
            if l3_parser == "skip":
                continue
            l3_info = run_l3_parser(packet["l2"]["payload"], l3_parser)
            packet["l3"] = l3_info
            print("Layer 3 complete.")

            protocol = packet["l3"].get("protocol")

            if protocol is not None:
                l4_parser = get_l4_parser(protocol)

                if l4_parser != "skip":
                    l4_info = run_l4_parser(packet["l3"]["payload"], l4_parser)
                    packet["l4"] = l4_info
            print("Layer 4 complete.")

            all_packets.append(packet)
        return all_packets


