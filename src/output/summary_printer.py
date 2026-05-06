from collections import Counter

def print_summary(packets):

    ethertype_counter = Counter()
    protocol_counter = Counter()
    sndr_ips = set()
    trgt_ips = set()
    src_ips = set()
    dst_ips = set()

    print("\n---=== Capture Summary ===---\n")
    print(f"Total packets: {len(packets)} packets.\n")
    for pkt in packets:
        if  pkt["l2"]["ethertype_name"] == "ARP":
            ethertype_counter["ARP"] += 1
            sndr_ips.add(pkt["l3"]["sender_ip"])
            trgt_ips.add(pkt["l3"]["target_ip"])
        elif pkt["l2"]["ethertype_name"] == "IPv4":
            ethertype_counter["IPv4"] += 1
            src_ips.add(pkt["l3"]["src_ip"])
            dst_ips.add(pkt["l3"]["dst_ip"])
            if pkt["l3"]["protocol_name"] == "ICMP":
               protocol_counter["ICMP"] += 1
            elif pkt["l3"]["protocol_name"] == "UDP": 
                protocol_counter["UDP"] += 1
            elif pkt["l3"]["protocol_name"] == "TCP": 
                protocol_counter["TCP"] += 1
    
    print(f"IPv4: {ethertype_counter['IPv4']} packets.")
    print(f"     ICMP: {protocol_counter['ICMP']} packets.")
    print(f"     UDP: {protocol_counter['UDP']} packets.")
    print(f"     TCP: {protocol_counter['TCP']} packets.\n")
    print(f"    Unique source IPs: {len(src_ips)}")
    print(f"    Unique destination IPs: {len(dst_ips)}\n")
    print(f"ARP: {ethertype_counter['ARP']} packets.")
    print(f"    Unique sender IPs: {len(sndr_ips)}")
    print(f"    Unique target IPs: {len(trgt_ips)}\n")


