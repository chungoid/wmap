#!/usr/bin/env python3
import os
import argparse
from config.config import CONFIG, ensure_directories_and_database, DEFAULT_DB_PATH
from utils.capture import capture_packets
from utils.wpa_sec import download_potfile, upload_pcap, upload_all_pcaps, set_wpasec_key
from tools.scapy_parser import parse_scapy_to_db
from tools.tshark_parser import parse_tshark_live_to_db


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
    parser.add_argument("tool_args", nargs=argparse.REMAINDER,
                        help="All additional arguments for the tool (e.g., interface, output options).")

    args = parser.parse_args()

    db_path = DEFAULT_DB_PATH

    # Handle WPA-SEC actions
    if handle_wpa_sec_actions(args, db_path):
        return

    # Ensure tool-specific arguments are provided
    if not args.tool_args:
        parser.error(f"Tool '{args.tool}' requires additional arguments (e.g., interface and output options).")

    # Rewrite output path if specified in the arguments
    capture_dir = CONFIG["capture_dir"]
    os.makedirs(capture_dir, exist_ok=True)

    output_path = None
    additional_args = args.tool_args
    for i, arg in enumerate(additional_args):
        if arg in ["-o", "--write", "-w"]:  # Arguments specifying output
            if i + 1 < len(additional_args):
                original_output = additional_args[i + 1]
                filename = os.path.basename(original_output)
                output_path = os.path.join(capture_dir, filename)
                additional_args[i + 1] = output_path

    # Handle live parsing for TShark
    if args.tool == "tshark":
        interface = next((arg for i, arg in enumerate(additional_args) if additional_args[i - 1] in ["-i", "--interface"]), None)
        if interface:
            print(f"Starting live parsing with TShark on interface '{interface}'...")
            parse_tshark_live_to_db(interface, db_path)
            return

    # Run packet capture via the wrapper
    print(f"Starting capture with {args.tool}...")
    capture_packets(args.tool, additional_args, live_parser=lambda: parse_scapy_to_db(output_path, db_path) if output_path else None)

    # Parse packets into the database post-capture if output is provided and no live parsing
    if output_path and args.tool != "tshark":
        print(f"Parsing capture file '{output_path}' into the database...")
        parse_scapy_to_db(output_path, db_path)

    # Launch Flask web server if not disabled
    if not args.no_webserver:
        from web.app import app
        host = CONFIG.get("web_server_host", "0.0.0.0")
        port = CONFIG.get("web_server_port", 8080)
        print(f"Starting web server on {host}:{port}...")
        app.run(host=host, port=port)


if __name__ == "__main__":
    main()