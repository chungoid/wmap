import sqlite3
import json
import subprocess
import logging


LOG_FILE = "tshark_parser.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def parse_tshark_to_db(pcap_file, db_path="wmap.db"):
    """Parse packets from a pcap file using TShark and insert them into the database."""
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
            ts_sec = fields.get("frame.time_epoch", [0])[0] if isinstance(fields.get("frame.time_epoch"), list) else fields.get("frame.time_epoch", 0)
            ts_sec = int(float(ts_sec))  # Convert to integer seconds

            source_mac = fields.get("wlan.sa", [None])[0] if isinstance(fields.get("wlan.sa"), list) else fields.get("wlan.sa")
            dest_mac = fields.get("wlan.da", [None])[0] if isinstance(fields.get("wlan.da"), list) else fields.get("wlan.da")
            signal = fields.get("radiotap.dbm_antsignal", [-100])[0] if isinstance(fields.get("radiotap.dbm_antsignal"), list) else fields.get("radiotap.dbm_antsignal")
            signal = int(signal) if signal is not None else None
            ssid = fields.get("wlan.ssid", [None])[0] if isinstance(fields.get("wlan.ssid"), list) else fields.get("wlan.ssid")
            packet_type = fields.get("wlan.fc.type_subtype", [None])[0] if isinstance(fields.get("wlan.fc.type_subtype"), list) else fields.get("wlan.fc.type_subtype")

            # packets table
            cursor.execute("""
            INSERT INTO packets (
                ts_sec, ts_usec, phyname, source_mac, dest_mac, trans_mac,
                freq, channel, packet_len, signal, dlt, tags, datarate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts_sec, 0, "802.11", source_mac, dest_mac, None, None, None, None, signal, "802.11", None, None))

            # beacons table
            if packet_type == "0x08":  # Beacon frame
                cursor.execute("""
                INSERT INTO beacons (id, ssid, encryption, capabilities, beacon_interval)
                VALUES (NULL, ?, ?, ?, ?)
                """, (ssid, "WPA2-PSK", "HT20", 100))

            # probes table
            if packet_type == "0x04":  # Probe request
                cursor.execute("""
                INSERT INTO probes (id, ssid, is_response)
                VALUES (NULL, ?, 0)
                """, (ssid,))

            logging.debug(f"Inserted packet: ts_sec={ts_sec}, source_mac={source_mac}, dest_mac={dest_mac}, signal={signal}")

        except Exception as e:
            logging.error(f"Error inserting packet: {e}. Packet data: {packet}")

    conn.commit()
    conn.close()
    logging.info(f"Parsing and database insertion completed for {pcap_file}.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Parse a pcap file and load data into the database using TShark.")
    parser.add_argument("pcap_file", type=str, help="Path to the pcap or pcapng file.")
    parser.add_argument("-d", "--db_path", type=str, default="wmap.db", help="Path to the SQLite database.")
    args = parser.parse_args()

    parse_tshark_to_db(args.pcap_file, args.db_path)