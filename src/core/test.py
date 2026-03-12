import struct
from collections import namedtuple
from src.parsers.l2parsers import EthernetParser

version = "v0.1"
GlobalHeader = namedtuple("GlobalHeader", "ver_maj ver_min gmt_to_local sigfigs snap_len linktype")
PacketHeader = namedtuple("PacketHeader", "ts_sec ts_subsec incl_len orig_len")

LINKTYPES = {
    1: "Ethernet",
    9: "Point-to-point protocol (PPP)",
    101: "Raw IP",
    105: "802.11 wireless LAN",
    113: "Linux 'cooked' capture encapsulation (SLL)",
    127: "802.11 with radio-tap header"
}

PARSERS = {
    1: EthernetParser(),
    9: "PppParser",
    101: "RawIpParser"
}

#Logs
all_packets = []
packet = {
    "number": packet_num,
    "header": packet_header,
    "l2": l2,
    "l3": l3,
    "l4": l4
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
    print(f"See-ZD PCAP Analyzer {version} | Max packet length: {snap_len} bytes | Linktype: {linktype}")
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

def get_parser(link_unpacked):
    parser = PARSERS.get(link_unpacked)
    if not parser:
        raise NotImplementedError(f"Unsupported linktype, but soon to be implemented.")
    print(f"Fetching {parser.__class__.__name__}...")
    return parser

def unpack_packet_header(raw_packet_header, endian, packet_number):
    (ts_sec, ts_subsec, incl_len, orig_len) = struct.unpack(endian + "IIII", raw_packet_header)
    print(f"Packet {packet_number} | {incl_len} / {orig_len} bytes.")
    return PacketHeader(ts_sec, ts_subsec, incl_len, orig_len)


def run_parser(data, parser):
    l2 = parser.parse(data)
    return l2
    

with open("test_50.pcap", "rb") as packets_file:
    
    magic = packets_file.read(4)
    endian, time_precision = check_endian(magic)

    raw_global_header = packets_file.read(20)
    unpacked_global_header = unpack_network_info(raw_global_header, endian)

    print_link_layer_type(unpacked_global_header.linktype)
    parser = get_parser(unpacked_global_header.linktype)

    packet_number = 0
    while True:
        packet_number += 1
        packet["number"] = packet_number
        raw_packet_header = packets_file.read(16)
        if len(raw_packet_header) < 16:
            print(f"Reading completed.")
            break
        
        unpacked_packet_header = unpack_packet_header(raw_packet_header, endian, packet_number)
        packet["header"] = unpacked_packet_header

        data = packets_file.read(unpacked_packet_header.incl_len)
        if len(data) < unpacked_packet_header.incl_len:
            print("Packet is truncated.")
            break

        l2_info = run_parser(data, parser)
        packet["l2"] = l2_info

