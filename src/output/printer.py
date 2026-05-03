

def print_packet(packet):
    print(f"Packet #{packet['number']}")

    if packet.get("l2"):
        print_l2(packet["l2"])

    if packet.get("l3"):
        print_l3(packet["l3"])

    if packet.get("l4"):
        print_l4(packet["l4"])

    print()


def print_l2(l2):
    src_mac = l2.get("src_mac", "unknown")
    dst_mac = l2.get("dst_mac", "unknown")
    ethertype = l2.get("ethertype_name", l2.get("ethertype", "unknown"))

    print(f"  L2: {src_mac} -> {dst_mac} | {ethertype}")


def print_l3(l3):
    packet_type = l3.get("type")

    if packet_type == "IPv4":
        src_ip = l3.get("src_ip", "unknown")
        dst_ip = l3.get("dst_ip", "unknown")
        protocol_name = l3.get("protocol_name", "unknown")
        protocol_number = l3.get("protocol", "unknown")

        print(f"  L3: {src_ip} -> {dst_ip} | {protocol_name} ({protocol_number})")

    elif packet_type == "ARP":
        opcode = l3.get("opcode")

        if opcode == 1:
            print(f"  L3: ARP Request | Who has {l3['target_ip']}? Tell {l3['sender_ip']}")
        elif opcode == 2:
            print(f"  L3: ARP Reply | {l3['sender_ip']} is at {l3['sender_mac']}")
        else:
            print(f"  L3: ARP | opcode {opcode}")

    else:
        print(f"  L3: {l3}")


def print_l4(l4):
    packet_type = l4.get("type")

    if packet_type == "TCP":
        print(f"  L4: TCP {l4.get('src_port')} -> {l4.get('dst_port')} | Flags {l4.get('flags')}")

    elif packet_type == "UDP":
        print(f"  L4: UDP {l4.get('src_port')} -> {l4.get('dst_port')}")

    elif packet_type == "ICMP":
        print(f"  L4: ICMP type {l4.get('type')} code {l4.get('code')}")

    else:
        print(f"  L4: {l4}")