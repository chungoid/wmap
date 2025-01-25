from tools.scapy_parser import parse_scapy_to_db
from tools.tshark_parser import parse_tshark_to_db


def parse_capture_file(parser, output, db_path):
    """Parse the capture file into the database."""
    print(f"Parsing capture file '{output}' into database using {parser} parser...")
    if parser == "scapy":
        parse_scapy_to_db(output, db_path)
    elif parser == "tshark":
        parse_tshark_to_db(output, db_path)
    print("Parsing completed successfully.")
