ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Mask Request",
    18: "Mask Reply",
}

ICMP_CODES = {
    3: {    # Destination Unreachable
        0: "Network Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation needed and DF set",
        5: "Source route failed"
    },
    5: {    # Redirect
        0: "Redirect datagrams for the network",
        1: "Redirect datagrams for the host",
        2: "Redirect for type of service and network",
        3: "Redirect for type of service and host"
    },
    11: {   # Time Exceeded
        0: "TTL Expired",
        1: "Fragment Reassembly Time Exceeded"
    },
    12: {   # Parameter Problem
        0: "Pointer indicates the error",
        1: "Missing required option",
        2: "Bad length"
    }
}