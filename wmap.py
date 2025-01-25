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
    parser.add_argument("-t", "--tool", type=str, required=True,
                        choices=["hcxdumptool", "tshark", "airodump-ng", "tcpdump", "dumpcap"],
                        help="Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).")
    parser.add_argument("--args", nargs=argparse.REMAINDER, required=True,
                        help="Additional arguments for the capture tool, including interface and output.")
    parser.add_argument("--parser", type=str, choices=["scapy", "tshark"], default="scapy",
                        help="Parser to use for processing the capture (default: scapy).")
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

    # Build capture command and ensure output redirection to `capture/`
    additional_args = args.args
    capture_dir = CONFIG["capture_dir"]
    os.makedirs(capture_dir, exist_ok=True)

    # Check if the tool specifies an output argument and rewrite it to the capture directory
    output_path = None
    for i, arg in enumerate(additional_args):
        if arg in ["-o", "--write", "-w"]:  # Arguments that specify output
            if i + 1 < len(additional_args):
                original_output = additional_args[i + 1]
                filename = os.path.basename(original_output)
                output_path = os.path.join(capture_dir, filename)
                additional_args[i + 1] = output_path

    # Validate that output was provided if required by the tool
    if not output_path and args.tool in ["tshark", "airodump-ng", "tcpdump", "dumpcap"]:
        print(f"Error: The tool '{args.tool}' requires an output file specified in its arguments.")
        return

    # Run packet capture
    print(f"Starting capture with {args.tool}...")
    capture_packets(args.tool, additional_args)

    # Parse packets into the database
    if output_path:
        print(f"Parsing capture file '{output_path}' into the database...")
        parse_capture_file(args.parser, output_path, db_path)

    # Launch Flask web server if not disabled
    if not args.no_webserver:
        from web.app import app
        host = CONFIG.get("web_server_host", "0.0.0.0")
        port = CONFIG.get("web_server_port", 8080)
        print(f"Starting web server on {host}:{port}...")
        app.run(host=host, port=port)


if __name__ == "__main__":
    main()