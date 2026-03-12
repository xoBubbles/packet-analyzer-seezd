

class EthernetParser:
    def __init__(self, strict=True):
        self.strict = strict
    
    def parse(self, packet_bytes):
        if len(packet_bytes) < 14:
            return False
        dst_mac_bytes = packet_bytes[0:6]
        src_mac_bytes = packet_bytes[6:12]
        ether_type_bytes = packet_bytes[12:14]
        payload = packet_bytes[14:]
        
        dst_mac = dst_mac_bytes.hex(":")
        src_mac = src_mac_bytes.hex(":")
        ether_type = int.from_bytes(ether_type_bytes, 'big') #Always big endian in ethernet packets | This will be used for l3 parsing

        ether_type_name = {
            0x0800: "IPv4",
            0x86DD: "IPv6",
            0x0806: "ARP",
            0x8100: "802.1Q VLAN"
        }.get(ether_type, "Unknown")
        
        return {
            "l2": "Ethernet",
            "dst_mac": dst_mac,
            "src_mac": src_mac,
            "ethertype": ether_type,
            "ethertype_name": ether_type_name,
            "payload": payload,
        }

        