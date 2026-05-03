import sys
from src.core.analyzer import Analyzer
from src.output.printer import print_packet

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <pcap_file>")
        return

    file_path = sys.argv[1]

    analyzer = Analyzer()
    packets = analyzer.analyze(file_path)

    for pkt in packets:
        print_packet(pkt)


if __name__ == "__main__":
    main()