import sqlite3
import argparse
import logging
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
from scapy.utils import PcapReader

# Configure logging
LOG_FILE = "scapy_parser.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def parse_scapy_to_db(pcap_file, db_path="wmap.db"):
    """Parse a pcap file using Scapy in chunks and populate the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        logging.info(f"Starting to parse pcap file: {pcap_file}")
        with PcapReader(pcap_file) as packets:
            for idx, packet in enumerate(packets):
                try:
                    # Common metadata
                    ts_sec = int(packet.time)
                    ts_usec = int((packet.time - ts_sec) * 1_000_000)
                    source_mac = packet.addr2 if packet.haslayer(Dot11) else None
                    dest_mac = packet.addr1 if packet.haslayer(Dot11) else None
                    trans_mac = packet.addr3 if packet.haslayer(Dot11) else None
                    packet_len = len(packet)

                    # Radiotap signal data (if present)
                    signal = getattr(packet, 'dBm_AntSignal', None)
                    signal = int(signal) if signal is not None else None

                    # Default values for specific layers
                    phyname = "802.11"
                    freq = getattr(packet, 'ChannelFrequency', None)
                    channel = None
                    dlt = "802.11"
                    tags = None
                    datarate = None

                    # Layer-specific processing
                    if packet.haslayer(Dot11Beacon):
                        ssid = packet.info.decode("utf-8") if getattr(packet, "info", None) else "Hidden"
                        cursor.execute("""
                        INSERT INTO beacons (id, ssid, encryption, capabilities, beacon_interval)
                        VALUES (NULL, ?, ?, ?, ?)
                        """, (ssid, "WPA2-PSK", "HT20", 100))

                    elif packet.haslayer(Dot11ProbeReq):
                        ssid = packet.info.decode("utf-8") if getattr(packet, "info", None) else "Wildcard"
                        cursor.execute("""
                        INSERT INTO probes (id, ssid, is_response)
                        VALUES (NULL, ?, 0)
                        """, (ssid,))

                    elif packet.haslayer(Dot11Deauth):
                        reason_code = getattr(packet, "reason_code", None)
                        cursor.execute("""
                        INSERT INTO deauth_frames (id, reason_code)
                        VALUES (NULL, ?)
                        """, (reason_code,))

                    # Insert into the packets table
                    cursor.execute("""
                    INSERT INTO packets (
                        ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
                        freq, channel, packet_len, signal, dlt, tags, datarate
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac, freq,
                          channel, packet_len, signal, dlt, tags, datarate))

                    logging.debug(
                        f"Packet {idx + 1}: Inserted with ts_sec={ts_sec}, source_mac={source_mac}, signal={signal}")

                except sqlite3.IntegrityError as e:
                    logging.error(f"Integrity error on packet {idx + 1}: {e}")
                except Exception as e:
                    logging.error(f"Error processing packet {idx + 1}: {e}")

                # Commit every 100 packets to avoid locking
                if (idx + 1) % 100 == 0:
                    conn.commit()
                    logging.info(f"Committed 100 packets to the database (processed {idx + 1} packets so far).")

    except Exception as e:
        logging.error(f"Error reading pcap file '{pcap_file}': {e}")
    finally:
        conn.commit()
        conn.close()
        logging.info(f"Parsing completed for {pcap_file}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse a pcap file and load data into the database.")
    parser.add_argument("pcap_file", type=str, help="Path to the pcap or pcapng file.")
    parser.add_argument("-d", "--db_path", type=str, default="wmap.db", help="Path to the SQLite database.")
    args = parser.parse_args()

    parse_scapy_to_db(args.pcap_file, args.db_path)