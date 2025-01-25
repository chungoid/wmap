import sqlite3
import json
import subprocess
import logging
import os
from config.config import LOG_FILES, DEFAULT_DB_PATH

# Setup logging
LOG_FILE = LOG_FILES["tshark_parser"]
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)


def extract_field(fields, key, default=None):
    """Extract a field from TShark output with proper handling for lists."""
    value = fields.get(key, default)
    if isinstance(value, list):
        return value[0] if value else default
    return value


def parse_tshark_to_db(pcap_file, db_path=DEFAULT_DB_PATH):
    """Parse packets from a pcap file using TShark and insert them into the database."""
    if not os.path.exists(pcap_file):
        logging.error(f"PCAP file '{pcap_file}' not found.")
        raise FileNotFoundError(f"PCAP file '{pcap_file}' does not exist.")

    if not os.path.exists(db_path):
        logging.error(f"Database file '{db_path}' not found.")
        raise FileNotFoundError(f"Database file '{db_path}' does not exist.")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        logging.info(f"Running TShark on {pcap_file}...")
        result = subprocess.run([
            "tshark", "-r", pcap_file, "-T", "json",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "radiotap.dbm_antsignal",
            "-e", "wlan.ssid",
            "-e", "wlan.fc.type_subtype"
        ], capture_output=True, text=True, check=True)

        packets = json.loads(result.stdout)
        logging.info(f"Successfully parsed {len(packets)} packets from {pcap_file}.")

    except subprocess.CalledProcessError as e:
        logging.error(f"TShark failed with error: {e}")
        return
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse JSON output from TShark: {e}")
        return

    for packet in packets:
        try:
            fields = packet.get("_source", {}).get("layers", {})

            # Extract fields
            ts_sec = extract_field(fields, "frame.time_epoch", 0)
            ts_sec = int(float(ts_sec)) if ts_sec else None

            source_mac = extract_field(fields, "wlan.sa")
            dest_mac = extract_field(fields, "wlan.da")
            signal = extract_field(fields, "radiotap.dbm_antsignal", -100)
            signal = int(signal) if signal is not None else None
            ssid = extract_field(fields, "wlan.ssid")
            packet_type = extract_field(fields, "wlan.fc.type_subtype")

            # Insert into packets table
            cursor.execute("""
            INSERT INTO packets (
                ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
                freq, channel, packet_len, signal, dlt, tags, datarate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts_sec, 0, "802.11", source_mac, dest_mac, None, None, None, None, signal, "802.11", None, None))

            # Insert into beacons table
            if packet_type == "0x08":  # Beacon frame
                cursor.execute("""
                INSERT INTO beacons (id, ssid, encryption, capabilities, beacon_interval)
                VALUES (NULL, ?, ?, ?, ?)
                """, (ssid, "WPA2-PSK", "HT20", 100))

            # Insert into probes table
            if packet_type == "0x04":  # Probe request
                cursor.execute("""
                INSERT INTO probes (id, ssid, is_response)
                VALUES (NULL, ?, 0)
                """, (ssid,))

            logging.debug(
                f"Inserted packet: ts_sec={ts_sec}, source_mac={source_mac}, dest_mac={dest_mac}, signal={signal}")

        except Exception as e:
            logging.error(f"Error inserting packet: {e}. Packet data: {packet}")

    conn.commit()
    conn.close()
    logging.info(f"Parsing and database insertion completed for {pcap_file}.")


def parse_tshark_live_to_db(interface, db_path=DEFAULT_DB_PATH):
    """Parse packets live using TShark and insert them into the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        logging.info(f"Starting live parsing on interface {interface} using TShark...")
        process = subprocess.Popen([
            "tshark", "-i", interface, "-T", "json",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "radiotap.dbm_antsignal",
            "-e", "wlan.ssid",
            "-e", "wlan.fc.type_subtype"
        ], stdout=subprocess.PIPE, text=True)

        buffer = ""
        for line in process.stdout:
            buffer += line
            try:
                packets = json.loads(buffer)
                for packet in packets:
                    try:
                        fields = packet.get("_source", {}).get("layers", {})
                        ts_sec = extract_field(fields, "frame.time_epoch", 0)
                        ts_sec = int(float(ts_sec)) if ts_sec else None

                        source_mac = extract_field(fields, "wlan.sa")
                        dest_mac = extract_field(fields, "wlan.da")
                        signal = extract_field(fields, "radiotap.dbm_antsignal", -100)
                        signal = int(signal) if signal is not None else None
                        ssid = extract_field(fields, "wlan.ssid")
                        packet_type = extract_field(fields, "wlan.fc.type_subtype")

                        cursor.execute("""
                        INSERT INTO packets (
                            ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
                            freq, channel, packet_len, signal, dlt, tags, datarate
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (ts_sec, 0, "802.11", source_mac, dest_mac, None, None, None, None, signal, "802.11", None,
                              None))

                        conn.commit()

                    except Exception as e:
                        logging.error(f"Error processing live packet: {e}")
                buffer = ""
            except json.JSONDecodeError:
                pass

    except Exception as e:
        logging.error(f"Error during live TShark parsing: {e}")
    finally:
        conn.close()
        logging.info("Live parsing completed.")
