# Packet Analyzer

A lightweight Python-based packet analyzer for parsing and inspecting `.pcap` network captures.

This project is focused on learning low-level networking, protocol analysis, and packet inspection by building a modular analyzer from scratch without external packet parsing libraries.

---

# Features

## Current Features

- Read and parse `.pcap` files
- Ethernet frame parsing
- ARP parsing
- IPv4 parsing
- ICMP parsing
- UDP parsing
- TCP parsing
- Layered L2 / L3 / L4 architecture
- Debug logging system
- Verbose packet inspection mode
- Capture summary statistics
- CLI flag support through `argparse`

## Planned Features

- DNS parsing
- TCP flow tracking
- Packet filtering
- Live packet capture
- IPv6 support
- PCAP export support
- GUI interface

---

# CLI Usage

    python cli.py <pcap_file>

    python cli.py test.pcap --verbose
    python cli.py test.pcap --summary
    python cli.py test.pcap --no-debug

--- 

# Example Outputs

## Normal Mode

    [1] ARP
    [2] ARP
    [3] IPv4
    [4] IPv4
    [5] IPv4

## Verbose Mode

    Packet #5

    L2: aa:bb:cc:dd:ee:01 -> aa:bb:cc:dd:ee:ff | IPv4
    L3: 192.168.1.10 -> 93.184.216.34 | TCP (6)
    L4: TCP 54321 -> 80 | Flags {'SYN': True}

---

# Project Structure

    src/
    ├── core/
    ├── parsers/
    │   ├── l2parsers/
    │   ├── l3parsers/
    │   └── l4parsers/
    ├── maps/
    ├── output/
    └── utils/

---

# Goals

The objective of this project is to deepen understanding of:

- Network protocols
- Packet structures
- Layered network analysis
- Protocol parsing
- Network tooling architecture
- Cybersecurity-related traffic inspection
