#!/usr/bin/env python3
import os
import argparse
from config.config import CONFIG, ensure_directories_and_database, DEFAULT_DB_PATH
from tools.init_db import initialize_database
from utils.capture import prepare_output_directory, capture_packets, determine_tool_args
from utils.parsing import parse_capture_file
from utils.wpa_sec import download_potfile, upload_pcap, upload_all_pcaps, set_wpasec_key


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


def validate_capture_arguments(args, parser):
    """Ensure required arguments for capture and parsing are provided."""
    if not args.interface or not args.tool:
        parser.error("interface and -t/--tool are required for capture.")

    if args.tool in ["tshark", "airodump-ng", "tcpdump", "dumpcap"] and not args.output:
        parser.error(f"Tool '{args.tool}' requires an output file specified with -o/--output.")


def main():
    ensure_directories_and_database()

    parser = argparse.ArgumentParser(description="Wi-Fi packet capture and parsing tool.")
    parser.add_argument("interface", type=str, nargs="?", help="Wireless interface to use (e.g., wlan0mon).")
    parser.add_argument("-t", "--tool", type=str,
                        choices=["hcxdumptool", "tshark", "airodump-ng", "tcpdump", "dumpcap"],
                        help="Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).")
    parser.add_argument("-o", "--output", type=str, help="Output file or directory for the capture (if required).")
    parser.add_argument("--parser", type=str, choices=["scapy", "tshark"], default="scapy",
                        help="Parser to use for processing the capture (default: scapy).")
    parser.add_argument("--args", nargs=argparse.REMAINDER, help="Additional arguments for the capture tool.")
    parser.add_argument("-u", "--upload", nargs="?", const=CONFIG["capture_dir"],
                        help="Upload a specific PCAP file or all unmarked files in the capture directory.")
    parser.add_argument("-d", "--download", nargs="?", const=os.path.join(CONFIG["capture_dir"], "wpa-sec.potfile"),
                        help="Download potfile from WPA-SEC (default path if no path provided).")
    parser.add_argument("--set-key", type=str, help="Set the WPA-SEC key in the database.")
    parser.add_argument("--no-webserver", action="store_true", help="Disable web server and run CLI-only operations.")

    args = parser.parse_args()

    db_path = DEFAULT_DB_PATH

    # Handle WPA-SEC actions
    if handle_wpa_sec_actions(args, db_path):
        return

    # Validate capture-related arguments
    if not args.no_webserver:
        validate_capture_arguments(args, parser)

    # Prepare output directory if needed
    if args.output:
        prepare_output_directory(args.output)

    # Capture and parse packets if web server is not disabled
    if not args.no_webserver:
        additional_args = args.args if args.args else []
        if args.output and args.tool in ["tshark", "airodump-ng", "tcpdump", "dumpcap"]:
            additional_args = determine_tool_args(args.tool, args.output, additional_args)

        # Run packet capture
        capture_packets(args.tool, args.interface, additional_args)

        # Parse packets into the database if --output is specified
        if args.output:
            parse_capture_file(args.parser, args.output, db_path)

        print("Capture and parsing completed successfully.")

    # Launch Flask web server if not disabled
    if not args.no_webserver:
        from web.app import app
        host = CONFIG.get("web_server_host", "0.0.0.0")
        port = CONFIG.get("web_server_port", 8080)
        print(f"Starting web server on {host}:{port}...")
        app.run(host=host, port=port)


if __name__ == "__main__":
    main()