import argparse
from src.core.analyzer import Analyzer
from src.output.printer import print_packet
from src.output.summary_printer import print_summary


def main():

    parser = argparse.ArgumentParser(
        description = """
  ____                ____  _____
 / ___|  ___   ___   |__  || | \ \\
 \\___   / __\ / __\    / / | | | |
  ___)\ ||__/ ||__/   / /_ | |_| |
 |____/ \___/ \___/  /____||____/

 Packet Analyzer v0.2
 """, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument(
        "pcap_file",
        help = "Path to the .pcap file"
    )

    parser.add_argument(
        "--verbose",
        action = "store_true",
        help = "Display additional packet details"
    )

    parser.add_argument(
        "--summary",
        action = "store_true",
        help = "Display capture summary"
    )

    parser.add_argument(
        "--no-debug",
        action = "store_true",
        help = "Disable debug/error messages"
    )

    args = parser.parse_args()

    analyzer = Analyzer(debug = not args.no_debug)

    packets = analyzer.analyze(args.pcap_file)

    for pkt in packets:
        print_packet(pkt, verbose = args.verbose)
    
    if args.summary:
        print_summary(packets)
        return


if __name__ == "__main__":
    main()