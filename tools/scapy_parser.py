import sqlite3
import logging
import os
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
from scapy.utils import PcapReader
from config.config import LOG_FILES, DEFAULT_DB_PATH

LOG_FILE = LOG_FILES["scapy_parser"]
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def parse_scapy_to_db(pcap_file, db_path=DEFAULT_DB_PATH):
    """Parse a pcap file using Scapy in chunks and populate the database."""
    if not os.path.exists(pcap_file):
        logging.error(f"PCAP file '{pcap_file}' not found.")
        raise FileNotFoundError(f"PCAP file '{pcap_file}' does not exist.")

    if not os.path.exists(db_path):
        logging.error(f"Database file '{db_path}' not found.")
        raise FileNotFoundError(f"Database file '{db_path}' does not exist.")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        logging.info(f"Starting to parse pcap file: {pcap_file}")
        with PcapReader(pcap_file) as packets:
            for idx, packet in enumerate(packets):
                try:
                    # metadata
                    ts_sec = int(packet.time)
                    ts_usec = int((packet.time - ts_sec) * 1_000_000)
                    source_mac = packet.addr2 if packet.haslayer(Dot11) else None
                    dest_mac = packet.addr1 if packet.haslayer(Dot11) else None
                    trans_mac = packet.addr3 if packet.haslayer(Dot11) else None
                    packet_len = len(packet)

                    # radiotap
                    signal = getattr(packet, 'dBm_AntSignal', None)
                    signal = int(signal) if signal is not None else None

                    # default
                    phyname = "802.11"
                    freq = getattr(packet, 'ChannelFrequency', None)
                    channel = None
                    dlt = "802.11"
                    tags = None
                    datarate = None

                    # layer specific
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

                    # packets table in db
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

                if (idx + 1) % 100 == 0:
                    conn.commit()
                    logging.info(f"Committed 100 packets to the database (processed {idx + 1} packets so far).")

    except Exception as e:
        logging.error(f"Error reading pcap file '{pcap_file}': {e}")
        raise
    finally:
        conn.commit()
        conn.close()
        logging.info(f"Parsing completed for {pcap_file}.")