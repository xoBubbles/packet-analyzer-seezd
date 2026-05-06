from src.utils.formatters import format_ipv4
from src.maps.ip_protocol_map import get_ip_protocol_name

class Ipv4Parser:
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):

        if len(packet_bytes) < 1:
            if self.strict:
                raise ValueError("Packet too short for IPv4 first byte")
            return None

        first_byte = packet_bytes[0]
        version = first_byte >> 4
        internet_header_len = first_byte & 0x0F # 32-bit words, not in bytes
        header_length_bytes = internet_header_len * 4

        if self.strict:
            if version != 4:
                if self.strict:
                    raise ValueError(f"Expected IPv4, got version {version}")
                return None
            
            if internet_header_len < 5:
                if self.strict:
                    raise ValueError(f"Invalid IHL: {internet_header_len}")
                return None
            
            if len(packet_bytes) < header_length_bytes:
                if self.strict:
                    raise ValueError("Packet shorter than IPv4 header length")
                return None
            
        service_type = packet_bytes[1]
        total_packet_length = int.from_bytes(packet_bytes[2:4], "big")
        identification = int.from_bytes(packet_bytes[4:6], "big")
        flags_frag_offset = int.from_bytes(packet_bytes[6:8], "big")
        time_to_live = packet_bytes[8]
        protocol = packet_bytes[9]
        protocol_name = get_ip_protocol_name(protocol)
        header_checksum = int.from_bytes(packet_bytes[10:12], "big")
        src_ip = format_ipv4(packet_bytes[12:16])
        dst_ip = format_ipv4(packet_bytes[16:20])
        flags = flags_frag_offset >> 13
        fragment_offset = flags_frag_offset & 0x1FFF
        options = packet_bytes[20:header_length_bytes] if header_length_bytes > 20 else b"" # Extract options from header

        payload = packet_bytes[header_length_bytes:total_packet_length]

        return {
            "type": "IPv4",
            "version": version,
            "internet_header_length": internet_header_len,
            "header_length_bytes": header_length_bytes,
            "service_type": service_type,
            "total_length": total_packet_length,
            "identification": identification,
            "flags": flags,
            "fragment_offset": fragment_offset,
            "ttl": time_to_live,
            "protocol": protocol,
            "protocol_name": protocol_name,
            "header_checksum": header_checksum,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "options": options,
            "payload": payload,
        }