import logging
import os
import sqlite3
import subprocess
import signal
import time

from datetime import datetime
from scapy.fields import FlagValue
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11ProbeResp, RadioTap, Dot11Deauth
)
from scapy.utils import PcapReader, PcapNgReader

from config.config import DEFAULT_OUI_PATH, CONFIG

logger = logging.getLogger("scapy_parser")
oui_file = DEFAULT_OUI_PATH


# Check file existence
if not os.path.exists(oui_file):
    print(f"OUI file not found at {oui_file}")
else:
    print(f"OUI file found at {oui_file}")

def update_device_dict(device_dict, packet_info, oui_mapping):
    try:
        mac = packet_info['Dot11Beacon'].get('bssid', '').lower()  # Ensure lowercase
        if not isinstance(mac, str):
            logger.error("Invalid BSSID. Skipping entry.")
            return

        ssid = packet_info['Dot11Beacon'].get('essid', '')
        manufacturer = get_manufacturer(mac, oui_mapping)  # Match OUI mapping
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        device_dict[mac] = {
            'mac': mac,
            'ssid': ssid,
            'encryption': packet_info['Dot11Beacon'].get('crypto', 'Unknown'),
            'last_seen': timestamp,
            'manufacturer': manufacturer,
            'signal_strength': packet_info['Dot11Beacon'].get('dbm_signal'),
            'channel': packet_info['Dot11Beacon'].get('channel'),
            'extended_capabilities': packet_info['Dot11Beacon'].get('extended_capabilities'),
        }
        logger.info(f"AP added to device dict: {device_dict[mac]}")
    except Exception as e:
        logger.error(f"Error updating device dict: {e}")


def parse_flag_value(value):
    try:
        if isinstance(value, FlagValue):
            return int(value)
        return value
    except Exception as e:
        logger.error(f"Failed to parse FlagValue: {e}")
        return None

def convert_to_serializable(obj):
    if isinstance(obj, FlagValue):
        return int(obj)
    elif isinstance(obj, set):
        return list(obj)
    elif hasattr(obj, "__dict__"):
        return vars(obj)
    elif isinstance(obj, bytes):
        return obj.decode('utf-8', 'ignore')
    return obj

def bytes_to_hex_string(byte_seq):
    return byte_seq.hex() if byte_seq else None

def parse_oui_file():
    """
    Parse the OUI file to create a mapping of OUI prefixes to manufacturers.
    Returns:
        dict: A dictionary mapping OUI prefixes to manufacturer names.
    """

    logger.info(f"Attempting to parse OUI file at: {oui_file}")

    oui_mapping = {}
    try:
        with open(oui_file, 'r') as file:
            for line in file:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    oui = parts[0].strip().replace('-', ':').lower()
                    manufacturer = parts[1].strip().strip("'")
                    oui_mapping[oui] = manufacturer
        logger.info("OUI file parsed successfully.")
    except FileNotFoundError:
        logger.error(f"OUI file not found at {oui_file}. Please ensure the file exists.")
    except Exception as e:
        logger.error(f"Error parsing OUI file: {e}")
    return oui_mapping

def get_manufacturer(mac, oui_mapping):
    """
    Get the manufacturer from the OUI mapping based on the MAC address.

    Args:
        mac (str): The MAC address to look up.
        oui_mapping (dict): The OUI-to-manufacturer mapping.

    Returns:
        str: The manufacturer name or "Unknown" if not found.
    """
    try:
        oui = mac[:8].lower()  # Extract OUI and keep it lowercase
        return oui_mapping.get(oui, "Unknown")
    except Exception as e:
        logger.error(f"Error determining manufacturer for MAC {mac}: {e}")
        return "Unknown"


def decode_extended_capabilities(data):
    if not isinstance(data, str):
        logger.debug("Extended capabilities data is invalid or not a string.")
        return "No Extended Capabilities"
    try:
        capabilities = int(data, 16)
        logger.debug(f"Decoded extended capabilities: {capabilities}")
        features = []
        if capabilities & (1 << 0):
            features.append("Extended Channel Switching")
        if capabilities & (1 << 1):
            features.append("WNM Sleep Mode")
        if capabilities & (1 << 2):
            features.append("TIM Broadcast")
        return ", ".join(features) if features else "No Extended Capabilities"
    except Exception as e:
        logger.error(f"Failed to decode extended capabilities: {data} - {e}")
        return "No Extended Capabilities"


def parse_packet(packet, device_dict, oui_mapping, db_conn):
    """
    Parse a packet and extract information about access points and clients.
    Also tracks frame types and total data usage.

    - device_dict: Stores detected devices.
    - oui_mapping: OUI to manufacturer mapping.
    - db_conn: SQLite database connection.
    """
    try:
        # Get packet length (in bytes)
        packet_length = len(packet) if packet else 0
        frame_type = None  # Initialize frame type

        if packet.haslayer(Dot11Beacon):
            logger.debug(f"Parsing Dot11Beacon layer.")
            frame_type = "beacon"
            bssid = getattr(packet[Dot11], 'addr2', '').lower()
            if not bssid:
                logger.error("BSSID missing from packet.")
                return

            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            dbm_signal = getattr(packet, 'dBm_AntSignal', None)
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')
            manufacturer = get_manufacturer(bssid, oui_mapping)

            extended_capabilities = bytes_to_hex_string(
                getattr(packet.getlayer(Dot11Elt, ID=127), 'info', None)
            )

            logger.debug(f"BSSID: {bssid}, ESSID: {essid}, Signal: {dbm_signal}, "
                         f"Channel: {channel}, Crypto: {crypto}")

            device_dict[bssid] = {
                'mac': bssid,
                'ssid': essid,
                'encryption': crypto,
                'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'manufacturer': manufacturer,
                'signal_strength': dbm_signal,
                'channel': channel,
                'extended_capabilities': decode_extended_capabilities(extended_capabilities),
                'clients': []
            }
            logger.info(f"AP added to device dict: {device_dict[bssid]}")

        elif packet.haslayer(Dot11ProbeReq):
            logger.debug(f"Parsing Dot11ProbeReq layer.")
            frame_type = "probe_req"
            client_mac = getattr(packet[Dot11], 'addr2', '').lower()
            associated_ap = getattr(packet[Dot11], 'addr1', '').lower()
            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            dbm_signal = getattr(packet, 'dBm_AntSignal', None)

            if not client_mac:
                logger.error("Client MAC is missing. Skipping packet.")
                return

            if associated_ap in device_dict:
                client_info = {
                    'mac': client_mac,
                    'ssid': essid,
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': get_manufacturer(client_mac, oui_mapping),
                    'signal_strength': dbm_signal,
                }
                device_dict[associated_ap].setdefault('clients', []).append(client_info)
                logger.info(f"Client added to AP {associated_ap}: {client_info}")
            else:
                logger.warning(f"Associated AP {associated_ap} not found in device_dict for client {client_mac}.")

        elif packet.haslayer(Dot11ProbeResp):
            logger.debug(f"Parsing Dot11ProbeResp layer.")
            frame_type = "probe_resp"

        elif packet.haslayer(Dot11Auth):
            logger.debug(f"Parsing Dot11Auth layer.")
            frame_type = "auth"

        elif packet.haslayer(Dot11Deauth):
            logger.debug(f"Parsing Dot11Deauth layer.")
            frame_type = "deauth"

        elif packet.haslayer(Dot11AssoReq):
            logger.debug(f"Parsing Dot11AssoReq layer.")
            frame_type = "assoc_req"

        # **Update Database for Frame Counts & Data Usage**
        if frame_type:
            device_mac = getattr(packet[Dot11], 'addr2', '').lower()
            update_frame_count(device_mac, frame_type, db_conn)
            update_total_data(device_mac, packet_length, db_conn)

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")


def update_frame_count(device_mac, frame_type, db_conn):
    """Update frame count for a device in the database."""
    try:
        cursor = db_conn.cursor()

        logger.debug(f"Updating frame count for {device_mac}: {frame_type}")

        # Increment frame count or insert if missing
        cursor.execute("""
            INSERT INTO frame_counts (mac, frame_type, count) 
            VALUES (?, ?, 1) 
            ON CONFLICT(mac, frame_type) 
            DO UPDATE SET count = count + 1;
        """, (device_mac, frame_type))

        db_conn.commit()
        logger.info(f"Updated frame count for {device_mac}: {frame_type}")

    except sqlite3.Error as e:
        logger.error(f"Database error updating frame count for {device_mac}: {e}")

    except Exception as e:
        logger.error(f"Unexpected error updating frame count for {device_mac}: {e}")


def update_total_data(device_mac, packet_length, db_conn):
    """Update the total data usage for a device in the database."""
    try:
        cursor = db_conn.cursor()

        logger.debug(f"Fetching total data for {device_mac}. Packet size: {packet_length} bytes.")

        # Retrieve existing data usage
        cursor.execute("SELECT total_data FROM access_points WHERE mac = ?", (device_mac,))
        result = cursor.fetchone()

        if not result:
            logger.warning(f"No existing record for {device_mac}. Data usage will not be updated.")
            return

        total_data = result[0] if result[0] else 0
        total_data += packet_length  # Add new packet size to total

        cursor.execute(
            "UPDATE access_points SET total_data = ? WHERE mac = ?",
            (total_data, device_mac)
        )
        db_conn.commit()

        logger.info(f"Updated total data for {device_mac}: {total_data} bytes.")

    except sqlite3.Error as e:
        logger.error(f"Database error updating total data for {device_mac}: {e}")

    except Exception as e:
        logger.error(f"Unexpected error updating total data for {device_mac}: {e}")


def store_results_in_db(device_dict, db_conn):
    """Store parsed results into the database."""
    logger.debug("Storing results in the database...")
    try:
        cursor = db_conn.cursor()
        for ap_mac, ap_info in device_dict.items():
            try:
                # Convert set to comma-separated string
                encryption = ",".join(ap_info['encryption']) if isinstance(ap_info['encryption'], set) else ap_info['encryption']

                cursor.execute("""
                INSERT OR REPLACE INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ap_info['mac'], ap_info['ssid'], encryption,
                    ap_info['last_seen'], ap_info['manufacturer'], ap_info['signal_strength'],
                    ap_info['channel'], ap_info['extended_capabilities']
                ))
                logger.info(f"Inserted AP into database: {ap_info}")

                # Insert associated clients
                for client in ap_info.get('clients', []):
                    cursor.execute("""
                    INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        client['mac'], client['ssid'], client['last_seen'],
                        client['manufacturer'], client['signal_strength'], ap_info['mac']
                    ))
                    logger.info(f"Inserted client into database: {client}")

            except Exception as e:
                logger.error(f"Error inserting AP {ap_info['mac']} into database: {e}")

        db_conn.commit()
    except Exception as e:
        logger.error(f"Error storing results in the database: {e}")


def process_pcap(pcap_file, db_conn):
    """
    Process a PCAP file and parse its packets.

    Args:
        pcap_file: Path to the PCAP file to process.
        db_conn: SQLite database connection.
    """
    device_dict = {}  # Initialize the device dictionary
    oui_mapping = parse_oui_file()  # Load OUI file

    try:
        packet_count = 0
        logger.info(f"Processing PCAP file: {pcap_file}")

        # Use PcapNgReader as an iterator (no len())
        with PcapNgReader(pcap_file) as packets:
            for packet in packets:
                packet_count += 1
                parse_packet(packet, device_dict, oui_mapping, db_conn)  # Pass db_conn here

        logger.info(f"Finished processing {packet_count} packets from {pcap_file}")
        store_results_in_db(device_dict, db_conn)  # Use db_conn instead of db_path
        logger.info("PCAP processing complete.")

    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")


def live_scan(interface, db_conn):
    """
    Starts hcxdumptool in live mode and parses the generated PCAP file in real-time.

    - interface: The network interface to capture packets on.
    - db_conn: The active SQLite database connection.
    """
    capture_file = os.path.join(CONFIG["capture_dir"], "wmap.pcapng")

    command = f"hcxdumptool -i {interface} -o {capture_file}"
    logger.info(f"Starting live capture with hcxdumptool: {command}")

    # Start hcxdumptool as a subprocess
    process = subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)  # Give hcxdumptool time to start

    logger.info("hcxdumptool started. Parsing packets in real-time... Press Ctrl+C to stop.")

    try:
        # Open the capture file for live reading
        with PcapReader(capture_file) as pcap:
            while process.poll() is None:  # Check if hcxdumptool is still running
                try:
                    packet = next(pcap)  # Read packets as they arrive
                    parse_packet(packet, device_dict={}, oui_mapping=parse_oui_file(), db_conn=db_conn)
                except StopIteration:
                    time.sleep(0.5)  # No new packets, wait a bit and retry
                    continue

    except KeyboardInterrupt:
        logger.warning("Ctrl+C detected. Stopping hcxdumptool and finishing packet parsing...")
        process.terminate()  # Stop hcxdumptool
        process.wait()  # Wait for the process to fully exit

        # Ensure all packets are processed before exiting
        logger.info("Processing any remaining packets before exiting...")
        with PcapReader(capture_file) as pcap:
            for packet in pcap:
                parse_packet(packet, device_dict={}, oui_mapping=parse_oui_file(), db_conn=db_conn)

        logger.info("Live scan completed. Exiting.")

    except Exception as e:
        logger.error(f"Error during live scanning: {e}")

    finally:
        logger.info("Closing database connection.")
        db_conn.close()  # Ensure db_conn is properly closed