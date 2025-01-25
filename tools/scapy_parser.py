import sqlite3
import logging
import os
import time
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
from scapy.utils import RawPcapReader
from config.config import LOG_FILES, DEFAULT_DB_PATH

# Setup logging
LOG_FILE = LOG_FILES["scapy_parser"]
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def parse_scapy_live(file_path, db_path=DEFAULT_DB_PATH, check_interval=1):
    """
    Parse packets live from a file that's actively being written to
    and insert them into the database.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        logging.info(f"Starting live parsing of packets from file: {file_path}")
        processed_packets = 0  # Track how many packets have been processed

        # Wait until the file exists
        while not os.path.exists(file_path):
            logging.info(f"Waiting for capture file '{file_path}' to be created...")
            time.sleep(check_interval)

        while True:
            try:
                with RawPcapReader(file_path) as pcap_reader:
                    for idx, (raw_packet, _) in enumerate(pcap_reader):
                        if idx < processed_packets:
                            continue  # Skip already processed packets

                        try:
                            # Parse the raw bytes into a Scapy packet
                            packet = Dot11(raw_packet)
                            if not validate_packet(packet):
                                logging.warning(f"Skipping invalid packet at index {idx}.")
                                continue

                            process_packet(packet, cursor)
                            processed_packets += 1

                            # Commit every 100 packets
                            if processed_packets % 100 == 0:
                                conn.commit()
                                logging.info(f"Committed 100 packets (processed {processed_packets} total).")
                        except Exception as e:
                            logging.error(f"Error processing packet at index {idx}: {e}")
                            logging.debug(f"Raw packet data: {raw_packet}")

            except EOFError:
                # File is being written; wait before attempting to read again
                logging.debug("Reached end of file; waiting for more data...")
                time.sleep(check_interval)
            except Exception as e:
                logging.error(f"Unexpected error during live parsing: {e}")

            # Check if capture is still ongoing
            if not is_capture_active(file_path):
                logging.info("Capture appears to have stopped.")
                break

    except Exception as e:
        logging.error(f"Error during live parsing: {e}")
    finally:
        conn.commit()
        conn.close()
        logging.info(f"Live parsing completed for file: {file_path}")


def validate_packet(packet):
    """Ensure the packet meets basic requirements before processing."""
    try:
        # Example validations
        if not hasattr(packet, "time"):
            raise ValueError("Packet has no 'time' attribute.")
        if not packet.haslayer(Dot11):
            raise ValueError("Packet is not a valid 802.11 frame.")
        return True
    except Exception as e:
        logging.error(f"Packet validation failed: {e}")
        return False


def is_capture_active(file_path):
    """
    Check if the capture process is still active by monitoring the file's size or timestamp.
    """
    try:
        initial_size = os.path.getsize(file_path)
        time.sleep(1)  # Check file size after a short delay
        current_size = os.path.getsize(file_path)
        is_active = initial_size != current_size
        logging.debug(f"File '{file_path}' size changed: {initial_size} -> {current_size}. Active: {is_active}")
        return is_active
    except Exception as e:
        logging.error(f"Error monitoring file '{file_path}': {e}")
        return False


def process_packet(packet, cursor):
    """Process a single packet and insert data into the database."""
    try:
        # Metadata
        ts_sec = int(packet.time)
        ts_usec = int((packet.time - ts_sec) * 1_000_000)
        source_mac = packet.addr2 if packet.haslayer(Dot11) else None
        dest_mac = packet.addr1 if packet.haslayer(Dot11) else None
        trans_mac = packet.addr3 if packet.haslayer(Dot11) else None
        packet_len = len(packet)

        # Radiotap fields
        signal = getattr(packet, 'dBm_AntSignal', None)
        signal = int(signal) if signal is not None else None

        # Default fields
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

        # Insert into packets table
        cursor.execute("""
        INSERT INTO packets (
            ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
            freq, channel, packet_len, signal, dlt, tags, datarate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac, freq,
              channel, packet_len, signal, dlt, tags, datarate))

        logging.debug(f"Inserted packet with ts_sec={ts_sec}, source_mac={source_mac}, signal={signal}")

    except sqlite3.IntegrityError as e:
        logging.error(f"Integrity error while inserting packet: {e}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")