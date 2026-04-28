## Project mental model

/parsers = turn raw bytes into fields
/maps = turn protocol numbers into names
/core = reads pcap and chooses which parser runs next
/parsers = parser folders for each layer

Flow:
PCAP global header
- packet header
- Ethernet parser
- IPv4 parser
- L4 parser based on IPv4 protocol
- Parsed packet storing
- Basic printing (This needs a rework)

Currently supported:
- Ethernet
- IPv4
- ICMP
- UDP
- TCP

Next:
- add ARP
- TCP flow tracking
- DNS parsing
- Maybe a refactor before things get too messy