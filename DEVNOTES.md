## Project mental model

/parsers = turn raw bytes into fields
/maps = turn protocol numbers into names
/core = reads pcap and chooses which parser runs next
/parsers = parser folders for each layer
/output = Printer helper/display
/utils = Shared helper functions - Currently only holds the address formatter
/tools = Dedicated to outside tools for testing - Not imported by main app

Flow:
PCAP global header
- packet header
- Ethernet parser
- IPv4 parser
- L4 parser based on IPv4 protocol
- Parsed packet storing
- Basic printing

Currently supported:
- Ethernet
- IPv4
- ARP
- ICMP
- UDP
- TCP

Next:
- Need to add a registry and put protocols there so L3 can reference protocols in its part of the resulting packet
- TCP flow tracking
- DNS parsing
- Maybe a refactor before things get too messy