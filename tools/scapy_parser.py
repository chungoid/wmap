import sqlite3
import logging
import os
import time
from multiprocessing import Pool
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


def parse_scapy_to_db(pcap_file, db_path=DEFAULT_DB_PATH, num_workers=4):
    """Parse a pcap file using Scapy with multiprocessing and populate the database."""
    if not os.path.exists(pcap_file):
        logging.error(f"PCAP file '{pcap_file}' not found.")
        raise FileNotFoundError(f"PCAP file '{pcap_file}' does not exist.")

    if not os.path.exists(db_path):
        logging.error(f"Database file '{db_path}' not found.")
        raise FileNotFoundError(f"Database file '{db_path}' does not exist.")

    logging.info(f"Starting multiprocessing parse of {pcap_file} with {num_workers} workers.")

    # Divide the PCAP file into chunks for parallel processing
    chunk_size = 10000  # Number of packets per chunk
    chunks = []
    with RawPcapReader(pcap_file) as reader:
        current_chunk = []
        for idx, (raw_packet, _) in enumerate(reader):
            current_chunk.append(raw_packet)
            if len(current_chunk) >= chunk_size:
                chunks.append(current_chunk)
                current_chunk = []
        if current_chunk:
            chunks.append(current_chunk)

    logging.info(f"Divided {len(chunks)} chunks for multiprocessing.")

    # Use multiprocessing to process chunks in parallel
    with Pool(processes=num_workers) as pool:
        results = pool.starmap(process_chunk, [(chunk, db_path) for chunk in chunks])

    logging.info(f"Completed parsing of {pcap_file}. Processed {sum(results)} packets.")


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

            except EOFError:
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


def process_chunk(chunk, db_path):
    """Process a single chunk of packets and insert into the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    processed_packets = 0

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