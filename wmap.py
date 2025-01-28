#!/usr/bin/env python3
import argparse
import os
import subprocess
import logging
from utils import wpa_sec, scapy_parser, init_db
from config.config import CONFIG, DEFAULT_DB_PATH, setup_logging

def main():
    # Initialize Files/Directories/Database and Logging
    init_db.ensure_directories_and_database()
    setup_logging()
    logger = logging.getLogger("wmap")

    parser = argparse.ArgumentParser(description='Wireless capturing, parsing, and analyzing.')

    # Adding arguments
    parser.add_argument("--active", action="store_true", help="Enable active scanning mode")
    parser.add_argument("--passive", action="store_true", help="Enable passive scanning mode")
    parser.add_argument("interface", nargs="?",
                        help="Name of the wireless interface (optional if parsing existing file)")
    parser.add_argument("-u", "--upload", nargs="?", const=CONFIG["capture_dir"],
                        help="Upload a specific PCAP file or all unmarked files in the capture directory.")
    parser.add_argument("-d", "--download", nargs="?", const=os.path.join(CONFIG["capture_dir"], "wpa-sec.potfile"),
                        help="Download potfile from WPA-SEC (default path if no path provided).")
    parser.add_argument("--set-key", type=str, help="Set the WPA-SEC key in the database.")
    parser.add_argument("--get-key", action="store_true", help="Get the WPA-SEC key from the database.")
    parser.add_argument("--no-webserver", action="store_true", help="Disable web server and run CLI-only operations.")
    parser.add_argument("--parse-existing", type=str,
                        help="Parse an existing capture file (e.g., /path/to/file.pcap).")

    args = parser.parse_args()

    # Ensure capture directory exists
    os.makedirs(CONFIG["capture_dir"], exist_ok=True)
    capture_file = os.path.join(CONFIG["capture_dir"], 'wmap.pcapng')

    # Handle WPA-SEC related actions
    if wpa_sec.handle_wpa_sec_actions(args, DEFAULT_DB_PATH):
        return

    # Handle parsing of existing capture files
    if args.parse_existing:
        device_dict = {}
        oui_mapping = scapy_parser.parse_oui_file()

        packets = scapy_parser.rdpcap(args.parse_existing)
        for packet in packets:
            packet_info = scapy_parser.parse_packet(packet)
            if packet_info:
                scapy_parser.update_device_dict(device_dict, packet_info, oui_mapping)

        scapy_parser.store_results_in_db(device_dict)
        print("Parsing and storing complete.")
        return

    # If neither active nor passive scanning is enabled, exit
    if not args.active and not args.passive:
        parser.error("Either --active or --passive must be specified if not parsing an existing file.")

    # Ensure interface is provided for scanning modes
    if not args.interface:
        parser.error("An interface must be specified for active or passive scanning modes.")

    # Handle active/passive scanning
    if args.active:
        command = f"hcxdumptool -i {args.interface} -o {capture_file}"
        subprocess.run(command, shell=True)
    elif args.passive:
        command = f"hcxdumptool -i {args.interface} -w {capture_file} --disable_deauthentication --disable_proberequest --disable_association --disable_reassociation --disable_beacon"
        subprocess.run(command, shell=True)

    if not args.no_webserver:
        # Insert logic to start the web server if needed
        pass

    # Start live scan if active or passive options are used
    if args.active or args.passive:
        scapy_parser.live_scan(args.interface)


if __name__ == "__main__":
    main()
