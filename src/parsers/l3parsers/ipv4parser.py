

class Ipv4Parser:
    def __init__(self, strict=True):
        self.strict = strict

    def parse(self, packet_bytes):
        first_byte = packet_bytes[0]
        version = first_byte >> 4
        internet_header_len = first_byte & 0x0F
        
        service_type = packet_bytes[1:2]
        total_packet_length = packet_bytes[2:4]
        identification = packet_bytes[4:6]
        flags_frag_offset = packet_bytes[6:8]
        time_to_live = packet_bytes[8:9]
        protocol = packet_bytes[9:10]
        header_checksum = packet_bytes[10:12]
        src_ip = packet_bytes[12:16]
        dst_ip = packet_bytes[16:20]
        payload = packet_bytes[20:]
        
