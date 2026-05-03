def format_ipv4(ip_bytes):
    return ".".join(str(byte) for byte in ip_bytes)

def format_mac(mac_bytes):
    return ":".join(f"{byte:02x}" for byte in mac_bytes)