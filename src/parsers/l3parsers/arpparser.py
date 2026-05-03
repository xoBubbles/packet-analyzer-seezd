from src.utils.formatters import format_ipv4, format_mac

class ArpParser():
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):
        
        if self.strict and len(packet_bytes) < 28:
            raise ValueError("ARP packet too short")
        
        ARP_OPCODES = { # Move to maps/ later
            1: "request",
            2: "reply",
        }

        hardware_type = int.from_bytes(packet_bytes[0:2], "big")
        protocol_type = int.from_bytes(packet_bytes[2:4], "big")
        hardware_size = packet_bytes[4]
        protocol_size = packet_bytes[5]
        opcode = int.from_bytes(packet_bytes[6:8], "big")

        # Addresses
        sender_mac = format_mac(packet_bytes[8:14])
        sender_ip = format_ipv4(packet_bytes[14:18])
        target_mac = format_mac(packet_bytes[18:24])
        target_ip = format_ipv4(packet_bytes[24:28])

        arp_info = {
            "type": "ARP",
            "hardware_type": hardware_type,
            "protocol_type": protocol_type,
            "hardware_size": hardware_size,
            "protocol_size": protocol_size,
            "opcode": opcode,
            "opcode_str": ARP_OPCODES.get(opcode, "unknown"),
            "sender_mac": sender_mac,
            "sender_ip": sender_ip,
            "target_mac": target_mac,
            "target_ip": target_ip,
        }

        return arp_info