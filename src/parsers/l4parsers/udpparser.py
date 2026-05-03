from src.maps.port_map import get_port_info

class UDPParser:
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):
        if len(packet_bytes) < 8:
            if self.strict:
                raise ValueError("UDP packet too short")
            return None
        
        udp_header = packet_bytes[:8]
        udp_payload = packet_bytes[8:]

        src_port = int.from_bytes(udp_header[0:2], "big")
        dst_port = int.from_bytes(udp_header[2:4], "big")
        length = int.from_bytes(udp_header[4:6], "big")
        checksum = int.from_bytes(udp_header[6:8], "big")

        parsed_packet = {
            "type": "UDP",
            "src_port": src_port,
            "src_port_name": get_port_info(src_port),
            "dst_port": dst_port,
            "dst_port_name": get_port_info(dst_port),
            "length": length,
            "checksum": checksum,
            "payload_length": len(udp_payload),
            #"Payload": udp_payload, Add payload later; could get noisy without DNS parsing
        }
        return parsed_packet