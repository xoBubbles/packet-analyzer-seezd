from src.maps.icmp_map import ICMP_TYPES, ICMP_CODES

class ICMPParser:
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):
        if len(packet_bytes) < 4:
            if self.strict:
                raise ValueError("ICMP packet too short for base header")
            return None
        
        icmp_type = packet_bytes[0]
        icmp_code = packet_bytes[1]
        checksum = int.from_bytes(packet_bytes[2:4], "big")

        type_name = ICMP_TYPES.get(icmp_type, "Unknown")
        code_name = ICMP_CODES.get(icmp_type, {}).get(icmp_code, "Unknown")

        parsed_packet = {
            "Protocol": "ICMP",
            "Type": icmp_type,
            "Type Name": type_name,
            "Code": icmp_code,
            "Checksum": checksum,
        }
        if code_name is not None:
            parsed_packet["Code Name"] = code_name

        if icmp_type in (0, 8):
            if len(packet_bytes) < 8:
                if self.strict:
                    raise ValueError("ICMP echo packet too short for identifier/sequence")
                return parsed_packet
            
            identifier = int.from_bytes(packet_bytes[4:6], "big")
            sequence = int.from_bytes(packet_bytes[6:8], "big")
        
            parsed_packet["Identifier"] = identifier
            parsed_packet["Sequence"] = sequence
        
        return parsed_packet

