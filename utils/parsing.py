from tools.scapy_parser import parse_scapy_to_db
from tools.tshark_parser import parse_tshark_to_db


def parse_capture_file(parser, file_path, db_path):
    """
    Parse a capture file into the database.
    :param parser: Parser type ('scapy' or 'tshark').
    :param file_path: Path to the capture file.
    :param db_path: Path to the database.
    """
    print(f"Parsing {file_path} using {parser} parser...")
    if parser == "scapy":
        parse_scapy_to_db(file_path, db_path)
    elif parser == "tshark":
        parse_tshark_to_db(file_path, db_path)
    else:
        print(f"Unsupported parser: {parser}")


import os

def get_latest_capture_file(capture_dir):
    """
    Find the most recently created or modified .pcap file in the capture directory.

    :param capture_dir: Directory to search for .pcap files.
    :return: Path to the latest .pcap file, or None if no .pcap file exists.
    """
    try:
        pcap_files = [
            os.path.join(capture_dir, f)
            for f in os.listdir(capture_dir)
            if f.endswith(".pcap") or f.endswith(".pcapng")
        ]
        if not pcap_files:
            return None
        latest_file = max(pcap_files, key=os.path.getmtime)
        return latest_file
    except Exception as e:
        print(f"Error finding latest capture file: {e}")
        return None