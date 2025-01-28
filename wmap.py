#!/usr/bin/env python3
import argparse
import os
import subprocess
import logging
from utils import wpa_sec, scapy_parser, init_wmap
from config.config import CONFIG, DEFAULT_DB_PATH, setup_logging

def main():
    # Initialize Files/Directories/Database and Logging
    init_wmap.ensure_directories_and_database()
    setup_logging()
    logger = logging.getLogger("wmap")
    logger.info("Starting wmap application.")

    logger.info("Directories and database ensured.")

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
    parser.add_argument("--parse-existing", type=str, help="Parse an existing capture file (e.g., /path/to/file.pcap).")

    args = parser.parse_args()
    logger.debug(f"Parsed arguments: {args}")

    # Ensure capture directory exists
    os.makedirs(CONFIG["capture_dir"], exist_ok=True)
    logger.info(f"Capture directory ensured: {CONFIG['capture_dir']}")

    capture_file = os.path.join(CONFIG["capture_dir"], 'wmap.pcapng')
    logger.debug(f"Capture file path set to: {capture_file}")

    # Handle WPA-SEC related actions
    if wpa_sec.handle_wpa_sec_actions(args, DEFAULT_DB_PATH):
        logger.info("Handled WPA-SEC related action. Exiting.")
        return

    # Handle parsing of existing capture files
    if args.parse_existing:
        logger.info(f"Parsing existing file: {args.parse_existing}")
        scapy_parser.process_pcap(args.parse_existing)
        logger.info("Parsing and storing complete.")
        return

    # If neither active nor passive scanning is enabled, exit
    if not args.active and not args.passive:
        logger.error("Either --active or --passive must be specified if not parsing an existing file.")
        parser.error("Either --active or --passive must be specified if not parsing an existing file.")

    # Ensure interface is provided for scanning modes
    if not args.interface:
        logger.error("An interface must be specified for active or passive scanning modes.")
        parser.error("An interface must be specified for active or passive scanning modes.")

    # Handle active/passive scanning
    if args.active:
        command = f"hcxdumptool -i {args.interface} -o {capture_file}"
        logger.info(f"Starting active scan with command: {command}")
        subprocess.run(command, shell=True)
    elif args.passive:
        command = f"hcxdumptool -i {args.interface} -w {capture_file} --disable_deauthentication --disable_proberequest --disable_association --disable_reassociation --disable_beacon"
        logger.info(f"Starting passive scan with command: {command}")
        subprocess.run(command, shell=True)

    if not args.no_webserver:
        logger.info("Starting web server.")
        # Insert logic to start the web server if needed
        pass

    # Start live scan if active or passive options are used
    if args.active or args.passive:
        logger.info(f"Starting live scan on interface: {args.interface}")
        scapy_parser.live_scan(args.interface)

    logger.info("wmap application finished.")


if __name__ == "__main__":
    main()