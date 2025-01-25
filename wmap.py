#!/usr/bin/env python3
import os
import argparse
from config.config import CONFIG, ensure_directories_and_database, DEFAULT_DB_PATH
from utils.parsing import parse_capture_file, get_latest_capture_file
from utils.wpa_sec import download_potfile, upload_pcap, upload_all_pcaps, set_wpasec_key
from tools.scapy_parser import parse_scapy_live


def handle_wpa_sec_actions(args, db_path):
    """Handle WPA-SEC related actions: upload, download, or set key."""
    if args.set_key:
        set_wpasec_key("wpa_sec_key", args.set_key, db_path)
        return True

    if args.upload:
        if args.upload == CONFIG["capture_dir"]:
            upload_all_pcaps(db_path)
        else:
            upload_pcap(args.upload, db_path)
        return True

    if args.download:
        download_potfile(args.download, db_path)
        return True

    return False


def parse_previous_captures(db_path):
    """Parse all .pcap files in the capture directory into the database."""
    capture_dir = CONFIG["capture_dir"]
    files = [
        os.path.join(capture_dir, f)
        for f in os.listdir(capture_dir)
        if f.endswith(".pcap") or f.endswith(".pcapng")
    ]

    if not files:
        print("No capture files found to parse.")
        return

    for file in files:
        print(f"Parsing {file} into the database...")
        parse_capture_file("scapy", file, db_path)
    print("All previous captures have been parsed.")


def main():
    ensure_directories_and_database()

    parser = argparse.ArgumentParser(description="Wi-Fi packet capture and parsing tool.")
    parser.add_argument("-t", "--tool", type=str, required=True,
                        choices=["hcxdumptool", "tshark", "airodump-ng", "tcpdump", "dumpcap"],
                        help="Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).")
    parser.add_argument("-u", "--upload", nargs="?", const=CONFIG["capture_dir"],
                        help="Upload a specific PCAP file or all unmarked files in the capture directory.")
    parser.add_argument("-d", "--download", nargs="?", const=os.path.join(CONFIG["capture_dir"], "wpa-sec.potfile"),
                        help="Download potfile from WPA-SEC (default path if no path provided).")
    parser.add_argument("--set-key", type=str, help="Set the WPA-SEC key in the database.")
    parser.add_argument("--no-webserver", action="store_true", help="Disable web server and run CLI-only operations.")
    parser.add_argument("--parse-prev", action="store_true", help="Parse all previously captured .pcap files.")
    parser.add_argument("tool_args", nargs=argparse.REMAINDER,
                        help="All additional arguments for the tool (e.g., interface, output options).")

    args = parser.parse_args()

    db_path = DEFAULT_DB_PATH

    # Handle WPA-SEC actions
    if handle_wpa_sec_actions(args, db_path):
        return

    # Parse previous captures
    if args.parse_prev:
        parse_previous_captures(db_path)
        return

    # Ensure tool-specific arguments are provided
    if not args.tool_args:
        parser.error(f"Tool '{args.tool}' requires additional arguments (e.g., interface and output options).")

    # Determine the capture file for live parsing
    capture_dir = CONFIG["capture_dir"]
    latest_capture_file = get_latest_capture_file(capture_dir)

    # Run live parsing with Scapy
    if args.tool and latest_capture_file:
        print(f"Starting live parsing for {latest_capture_file}...")
        parse_scapy_live(latest_capture_file, db_path)

    # Launch Flask web server if not disabled
    if not args.no_webserver:
        from web.app import app
        host = CONFIG.get("web_server_host", "0.0.0.0")
        port = CONFIG.get("web_server_port", 8080)
        print(f"Starting web server on {host}:{port}...")
        app.run(host=host, port=port)


if __name__ == "__main__":
    main()