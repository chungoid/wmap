import sqlite3
import logging
import os
import time
from multiprocessing import Pool, cpu_count
from scapy.utils import RawPcapReader
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Deauth
from config.config import LOG_FILES, DEFAULT_DB_PATH

# Setup logging
LOG_FILE = LOG_FILES["scapy_parser"]
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

CHUNK_SIZE = 10000  # Number of packets per chunk

def parse_scapy_to_db(pcap_file, db_path=DEFAULT_DB_PATH):
    """Parse a PCAP file using Scapy in chunks and populate the database."""
    if not os.path.exists(pcap_file):
        logging.error(f"PCAP file '{pcap_file}' not found.")
        raise FileNotFoundError(f"PCAP file '{pcap_file}' does not exist.")

    if not os.path.exists(db_path):
        logging.error(f"Database file '{db_path}' not found.")
        raise FileNotFoundError(f"Database file '{db_path}' does not exist.")

    logging.info(f"Parsing PCAP file: {pcap_file}")
    try:
        pcap_reader = RawPcapReader(pcap_file)
        chunk = []
        chunk_index = 0

        with Pool(processes=cpu_count()) as pool:
            results = []
            for idx, (raw_packet, _) in enumerate(pcap_reader):
                chunk.append(raw_packet)
                if len(chunk) >= CHUNK_SIZE:
                    logging.info(f"Submitting chunk {chunk_index + 1} for processing...")
                    results.append(pool.apply_async(process_chunk, (chunk, db_path)))
                    chunk = []
                    chunk_index += 1

            if chunk:
                logging.info(f"Submitting final chunk {chunk_index + 1} for processing...")
                results.append(pool.apply_async(process_chunk, (chunk, db_path)))

            for result in results:
                processed_packets = result.get()
                logging.info(f"Processed {processed_packets} packets in a chunk.")

        pcap_reader.close()
    except Exception as e:
        logging.error(f"Error reading PCAP file '{pcap_file}': {e}")
        raise
    finally:
        logging.info(f"Parsing completed for {pcap_file}.")


def parse_scapy_live(file_path, db_path=DEFAULT_DB_PATH, check_interval=1):
    """Parse packets live from a file and insert them into the database in chunks."""
    if not os.path.exists(db_path):
        logging.error(f"Database file '{db_path}' not found.")
        raise FileNotFoundError(f"Database file '{db_path}' does not exist.")

    logging.info(f"Starting live parsing of packets from file: {file_path}")
    processed_packets = 0

    try:
        while not os.path.exists(file_path):
            logging.info(f"Waiting for capture file '{file_path}' to be created...")
            time.sleep(check_interval)

        while True:
            chunk = []
            try:
                with RawPcapReader(file_path) as pcap_reader:
                    for idx, (raw_packet, _) in enumerate(pcap_reader):
                        if idx < processed_packets:
                            continue

                        chunk.append(raw_packet)
                        processed_packets += 1

                        if len(chunk) >= CHUNK_SIZE:
                            logging.info(f"Processing chunk of size {len(chunk)}...")
                            process_chunk(chunk, db_path)
                            chunk = []

                if chunk:
                    logging.info(f"Processing final chunk of size {len(chunk)}...")
                    process_chunk(chunk, db_path)

            except EOFError:
                logging.debug("Reached end of file; waiting for more data...")
                time.sleep(check_interval)
            except Exception as e:
                logging.error(f"Unexpected error during live parsing: {e}")

            if not is_capture_active(file_path):
                logging.info("Capture appears to have stopped.")
                break
    except Exception as e:
        logging.error(f"Error during live parsing: {e}")
    finally:
        logging.info(f"Live parsing completed for file: {file_path}")


def process_chunk(chunk, db_path, max_retries=5, retry_delay=0.1):
    """Process a single chunk of packets and insert them into the database."""
    processed_packets = 0

    for attempt in range(max_retries):
        try:
            conn = sqlite3.connect(db_path, timeout=10)
            cursor = conn.cursor()
            break
        except sqlite3.OperationalError as e:
            logging.warning(f"Database connection attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                logging.error("Max retries reached. Aborting chunk processing.")
                return processed_packets
            time.sleep(retry_delay)

    try:
        for raw_packet in chunk:
            try:
                packet = Dot11(raw_packet)
                if not validate_packet(packet):
                    continue

                process_packet(packet, cursor)
                processed_packets += 1
            except Exception as e:
                logging.error(f"Error processing packet in the chunk: {e}")

        conn.commit()
        logging.info(f"Processed and committed {processed_packets} packets from the chunk.")
    except sqlite3.OperationalError as e:
        logging.error(f"Database locked during chunk processing: {e}")
    except Exception as e:
        logging.error(f"Error processing chunk: {e}")
    finally:
        conn.close()

    return processed_packets


def validate_packet(packet):
    """Ensure the packet meets basic requirements before processing."""
    try:
        if not hasattr(packet, "time"):
            raise ValueError("Packet has no 'time' attribute.")
        if not packet.haslayer(Dot11):
            raise ValueError("Packet is not a valid 802.11 frame.")
        return True
    except Exception as e:
        logging.error(f"Packet validation failed: {e}")
        return False


def is_capture_active(file_path):
    """Check if the capture process is still active."""
    try:
        initial_size = os.path.getsize(file_path)
        time.sleep(1)
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
        ts_sec = int(packet.time)
        ts_usec = int((packet.time - ts_sec) * 1_000_000)
        source_mac = packet.addr2 if packet.haslayer(Dot11) else None
        dest_mac = packet.addr1 if packet.haslayer(Dot11) else None
        trans_mac = packet.addr3 if packet.haslayer(Dot11) else None
        packet_len = len(packet)

        signal = getattr(packet, 'dBm_AntSignal', None)
        signal = int(signal) if signal is not None else None

        phyname = "802.11"
        freq = getattr(packet, 'ChannelFrequency', None)
        channel = None
        dlt = "802.11"
        tags = None
        datarate = None

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

        cursor.execute("""
        INSERT INTO packets (
            ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
            freq, channel, packet_len, signal, dlt, tags, datarate
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac, freq,
              channel, packet_len, signal, dlt, tags, datarate))

        logging.debug(f"Inserted packet with ts_sec={ts_sec}, source_mac={source_mac}, signal={signal}")

    except Exception as e:
        logging.error(f"Error inserting packet into database: {e}")