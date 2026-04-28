from src.maps.port_map import get_port_info

class TCPParser():
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):
        if len(packet_bytes) < 20:
            if self.strict:
                raise ValueError("TCP packet too short")
            return None
        
        src_port = int.from_bytes(packet_bytes[0:2], "big")
        dst_port = int.from_bytes(packet_bytes[2:4], "big")

        seq = int.from_bytes(packet_bytes[4:8], "big")
        ack = int.from_bytes(packet_bytes[8:12], "big")

        data_offset = (packet_bytes[12] >> 4) * 4  # same idea as IPv4 IHL

        if len(packet_bytes) < data_offset:
            if self.strict:
                raise ValueError("TCP packet shorter than header length")
            return None

        flags_byte = packet_bytes[13]

        window = int.from_bytes(packet_bytes[14:16], "big")
        checksum = int.from_bytes(packet_bytes[16:18], "big")
        urgent = int.from_bytes(packet_bytes[18:20], "big")

        # parse flags locally -> Stores a value for each flag
        flags = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }

        flag_list = [name for name, val in flags.items() if val]
        flag_str = ", ".join(flag_list) if flag_list else "None"

        payload = packet_bytes[data_offset:]

        parsed_packet = {
            "Protocol": "TCP",
            "Source Port": src_port,
            "Source Port Name": get_port_info(src_port),
            "Destination Port": dst_port,
            "Destination Port Name": get_port_info(dst_port),
            "Sequence": seq,
            "Acknowledgment": ack,
            "Header Length Bytes": data_offset,
            "Flags": flags,
            "Flags Str": flag_str,
            "Window": window,
            "Checksum": checksum,
            "Urgent Pointer": urgent,
            "Payload Length": len(payload),
            #"Payload": payload, Like udp; could get noisy for now
        }

        return parsed_packet