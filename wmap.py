#!/usr/bin/env python3
import argparse
import os
import subprocess
import logging
from tools import scapy_parser
from utils import wpa_sec
from config.config import CONFIG, ensure_directories_and_database, DEFAULT_DB_PATH

# Ensure necessary directories and database are initialized
ensure_directories_and_database()

# Configure logging
log_file = os.path.join(CONFIG['log_dir'], "wmap.log")
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def handle_wpa_sec_actions(args, db_path):
    """Handle WPA-SEC related actions: upload, download, set key, and get key."""
    try:
        if args.set_key:
            wpa_sec.set_wpasec_key("wpa_sec_key", args.set_key, db_path)
            logging.info("WPA-SEC key set successfully.")
            return True

        if args.get_key:
            key = wpa_sec.get_wpasec_key("wpa_sec_key", db_path)
            if key:
                print(f"WPA-SEC key: {key}")
            else:
                print("WPA-SEC key: null")
            logging.info("WPA-SEC key retrieved.")
            return True

        if args.upload:
            if args.upload == CONFIG["capture_dir"]:
                wpa_sec.upload_all_pcaps(db_path)
            else:
                wpa_sec.upload_pcap(args.upload, db_path)
            logging.info("WPA-SEC upload completed.")
            return True

        if args.download:
            wpa_sec.download_potfile(args.download, db_path)
            logging.info("WPA-SEC download completed.")
            return True
    except Exception as e:
        logging.error(f"Error handling WPA-SEC actions: {e}")
    return False

def main():
    parser = argparse.ArgumentParser(description='Wireless capturing, parsing, and analyzing.')

    # Adding arguments
    parser.add_argument("--active", action="store_true", help="Enable active scanning mode")
    parser.add_argument("--passive", action="store_true", help="Enable passive scanning mode")
    parser.add_argument("interface", help="Name of the wireless interface")
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

    interface = args.interface

    # Ensure capture directory exists
    os.makedirs(CONFIG["capture_dir"], exist_ok=True)
    capture_file = os.path.join(CONFIG["capture_dir"], 'wmap.pcapng')

    # Handle WPA-SEC related actions
    if handle_wpa_sec_actions(args, DEFAULT_DB_PATH):
        return

    # Handle active/passive scanning
    if args.active:
        command = f"hcxdumptool -i {interface} -o {capture_file}"
        subprocess.run(command, shell=True)
    elif args.passive:
        command = f"hcxdumptool -i {interface} -w {capture_file} --disable_deauthentication --disable_proberequest --disable_association --disable_reassociation --disable_beacon"
        subprocess.run(command, shell=True)

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

    if not args.no_webserver:
        # Insert logic to start the web server if needed
        pass

    # Start live scan if active or passive options are used
    if args.active or args.passive:
        scapy_parser.live_scan(interface)

if __name__ == "__main__":
    main()