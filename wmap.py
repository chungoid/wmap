#!/usr/bin/env python3
import os
import subprocess
import argparse
import requests

from config.config import CONFIG, ensure_directories
from tools.init_db import initialize_database
from tools.scapy_parser import parse_scapy_to_db
from tools.tshark_parser import parse_tshark_to_db


def initialize_database_if_needed(db_path):
    """Ensure the database is initialized."""
    if not os.path.exists(db_path):
        print(f"Initializing database at {db_path}...")
        initialize_database(db_path)
    else:
        print(f"Database already exists at {db_path}.")


def prepare_output_directory(output_path):
    """Ensure the output directory exists."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)


def determine_tool_args(tool, output, additional_args):
    """Adjust arguments for the specific capture tool."""
    if tool == "hcxdumptool":
        additional_args += ["-o", output]
    elif tool == "tshark":
        additional_args += ["-w", output]
    elif tool == "airodump-ng":
        additional_args += ["--write", os.path.splitext(output)[0]]
    elif tool == "tcpdump":
        additional_args += ["-w", output]
    elif tool == "dumpcap":
        additional_args += ["-w", output]
    return additional_args


def capture_packets(tool, interface, output, additional_args):
    """Run the specified capture tool."""
    print(f"Starting capture with {tool} on {interface}...")
    command = [tool, "-i", interface] + additional_args
    try:
        subprocess.run(command, check=True)
        print(f"Capture completed with {tool}.")
    except subprocess.CalledProcessError as e:
        print(f"Error during capture with {tool}: {e}")
        if e.stderr:
            print(f"Tool output:\n{e.stderr.decode('utf-8')}")
        exit(1)


def parse_capture_file(parser, output, db_path):
    """Parse the capture file into the database."""
    print(f"Parsing capture file '{output}' into database using {parser} parser...")
    if parser == "scapy":
        parse_scapy_to_db(output, db_path)
    elif parser == "tshark":
        parse_tshark_to_db(output, db_path)
    print("Parsing completed successfully.")


def download_potfile(output_file):
    """Download the potfile from WPA-SEC."""
    key = CONFIG.get("wpa_sec_key")
    if not key:
        print("Error: WPA-SEC key not configured in config.py.")
        return

    url = "https://wpa-sec.stanev.org/?api&dl=1"
    headers = {"Cookie": f"key={key}"}

    try:
        print("Downloading potfile from WPA-SEC...")
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        with open(output_file, "wb") as f:
            f.write(response.content)

        print(f"Potfile downloaded successfully and saved to {output_file}.")
    except requests.RequestException as e:
        print(f"Error downloading potfile: {e}")


def upload_pcap(pcap_file):
    """Upload a PCAP file to WPA-SEC."""
    key = CONFIG.get("wpa_sec_key")
    if not key:
        print("Error: WPA-SEC key not configured in config.py.")
        return

    url = "https://wpa-sec.stanev.org/?api&upload"
    headers = {"Cookie": f"key={key}"}
    files = {"file": open(pcap_file, "rb")}

    try:
        print(f"Uploading {pcap_file} to WPA-SEC...")
        response = requests.post(url, headers=headers, files=files)
        response.raise_for_status()

        print(f"Upload successful: {response.text}")
    except requests.RequestException as e:
        print(f"Error uploading PCAP file: {e}")


def main():
    ensure_directories()

    parser = argparse.ArgumentParser(description="Wi-Fi packet capture and parsing tool.")
    parser.add_argument("interface", type=str, help="Wireless interface to use (e.g., wlan0mon).")
    parser.add_argument("-t", "--tool", type=str, required=True,
                        choices=["hcxdumptool", "tshark", "airodump-ng", "tcpdump", "dumpcap"],
                        help="Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).")
    parser.add_argument("-o", "--output", type=str, required=True, help="Output file or directory for the capture.")
    parser.add_argument("--parser", type=str, choices=["scapy", "tshark"], default="scapy",
                        help="Parser to use for processing the capture (default: scapy).")
    parser.add_argument("--args", nargs=argparse.REMAINDER, help="Additional arguments for the capture tool.")
    parser.add_argument("-u", "--upload", type=str, help="Upload a PCAP file to WPA-SEC.")
    parser.add_argument("-d", "--download", nargs="?", const=os.path.join(CONFIG["capture_dir"], "wpa-sec.potfile"),
                        help="Download potfile from WPA-SEC (default path if no path provided).")

    args = parser.parse_args()

    # Initialize database and directories
    db_path = os.path.join(CONFIG["db_dir"], "wmap.db")
    initialize_database_if_needed(db_path)
    prepare_output_directory(args.output)

    # Handle WPA-SEC arguments
    if args.upload:
        upload_pcap(args.upload)
        return  # Skip other actions if upload is performed

    if args.download:
        download_potfile(args.download)
        return  # Skip other actions if download is performed

    # Run packet capture
    additional_args = args.args if args.args else []
    additional_args = determine_tool_args(args.tool, args.output, additional_args)
    capture_packets(args.tool, args.interface, args.output, additional_args)

    # Parse packets into the database
    parse_capture_file(args.parser, args.output, db_path)

    print("Capture and parsing completed successfully.")


if __name__ == "__main__":
    main()