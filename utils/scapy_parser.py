import logging
import os
import signal
import sqlite3
import json
import subprocess
import time

from datetime import datetime

from scapy.error import Scapy_Exception
from scapy.fields import FlagValue
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11ProbeResp, RadioTap, Dot11Deauth
)
from scapy.utils import PcapReader

from config.config import DEFAULT_OUI_PATH

logger = logging.getLogger("scapy_parser")
oui_file = DEFAULT_OUI_PATH

if not os.path.exists(oui_file):
    print(f"OUI file not found at {oui_file}")
else:
    print(f"OUI file found at {oui_file}")

def update_device_dict(device_dict, packet_info, oui_mapping):
    try:
        mac = packet_info['Dot11Beacon'].get('bssid', '').lower()
        if not isinstance(mac, str):
            logger.error("Invalid BSSID. Skipping entry.")
            return

        ssid = packet_info['Dot11Beacon'].get('essid', '')
        manufacturer = get_manufacturer(mac, oui_mapping)
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

def decode_extended_capabilities(data):
    """Decode extended capabilities from packets."""
    if not isinstance(data, str):
        logger.debug("Extended capabilities data is invalid or not a string.")
        return "No Extended Capabilities"
    try:
        capabilities = int(data, 16)
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


def parse_oui_file():
    """Parse the OUI file to create a mapping of OUI prefixes to manufacturers."""
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
        oui = mac[:8].lower()
        return oui_mapping.get(oui, "Unknown")
    except Exception as e:
        logger.error(f"Error determining manufacturer for MAC {mac}: {e}")
        return "Unknown"

def parse_packet(packet, device_dict, oui_mapping, db_conn):
    """Parse a packet and extract information about access points and clients."""
    try:
        packet_length = len(packet) if packet else 0
        frame_type = None
        dbm_signal = getattr(packet[RadioTap], 'dBm_AntSignal', None) if packet.haslayer(RadioTap) else None

        if packet.haslayer(Dot11Beacon):
            logger.debug("Parsing Dot11Beacon layer.")
            frame_type = "beacon"
            bssid = getattr(packet[Dot11], 'addr2', '').lower()
            if not bssid:
                logger.error("BSSID missing from packet.")
                return
            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')
            manufacturer = get_manufacturer(bssid, oui_mapping)
            extended_capabilities = decode_extended_capabilities(
                bytes_to_hex_string(getattr(packet.getlayer(Dot11Elt, ID=127), 'info', None))
            )

            if bssid in device_dict:
                device_dict[bssid]['total_data'] += packet_length
            else:
                device_dict[bssid] = {
                    'mac': bssid, 'ssid': essid, 'encryption': crypto, 'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal, 'channel': channel,
                    'extended_capabilities': extended_capabilities, 'clients': [], 'total_data': packet_length
                }

            logger.info(f"AP updated: {device_dict[bssid]}")

        elif packet.haslayer(Dot11ProbeReq):
            logger.debug("Parsing Dot11ProbeReq layer.")
            frame_type = "probe_req"
            client_mac = getattr(packet[Dot11], 'addr2', '').lower()
            associated_ap = getattr(packet[Dot11], 'addr1', '').lower()
            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''

            if not client_mac:
                logger.error("Client MAC is missing. Skipping packet.")
                return

            client_info = {
                'mac': client_mac,
                'ssid': essid,
                'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'manufacturer': get_manufacturer(client_mac, oui_mapping),
                'signal_strength': dbm_signal,
                'total_data': packet_length
            }

            if associated_ap in device_dict:
                existing_clients = device_dict[associated_ap].get('clients', [])
                if not any(c['mac'] == client_mac for c in existing_clients):
                    device_dict[associated_ap].setdefault('clients', []).append(client_info)
                    logger.info(f"Client added to AP {associated_ap}: {client_info}")

            else:
                # **New Fix**: Store probe request clients properly
                device_dict[client_mac] = {
                    'mac': client_mac,
                    'ssid': essid if essid else "Unknown",
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': get_manufacturer(client_mac, oui_mapping),
                    'signal_strength': dbm_signal,
                    'clients': [],
                    'total_data': packet_length
                }
                logger.info(f"Standalone client detected: {client_info}")

        elif packet.haslayer(Dot11ProbeResp):
            logger.debug("Parsing Dot11ProbeResp layer.")
            frame_type = "probe_resp"
            bssid = getattr(packet[Dot11], 'addr2', '').lower()
            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''

            if not bssid:
                logger.error("Probe Response missing BSSID. Skipping packet.")
                return

            if bssid in device_dict:
                device_dict[bssid]['total_data'] += packet_length
            else:
                # **New Fix**: Store probe responses as APs
                device_dict[bssid] = {
                    'mac': bssid, 'ssid': essid, 'encryption': "Unknown", 'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': get_manufacturer(bssid, oui_mapping), 'signal_strength': dbm_signal, 'channel': None,
                    'extended_capabilities': "No Extended Capabilities", 'clients': [], 'total_data': packet_length
                }
                logger.info(f"Probe Response detected, stored as AP: {device_dict[bssid]}")

        elif packet.haslayer(Dot11Auth):
            frame_type = "auth"
        elif packet.haslayer(Dot11Deauth):
            frame_type = "deauth"
        elif packet.haslayer(Dot11AssoReq):
            frame_type = "assoc_req"

        if frame_type:
            device_mac = getattr(packet[Dot11], 'addr2', '').lower()
            update_frame_count(device_mac, frame_type, db_conn)
            update_total_data(device_mac, packet_length, db_conn)

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")


def update_frame_count(mac, frame_type, db_conn):
    """
    Update frame type counts inside the `access_points` table as JSON.
    """
    try:
        cursor = db_conn.cursor()

        # Retrieve current frame counts
        cursor.execute("SELECT frame_counts FROM access_points WHERE mac = ?", (mac,))
        result = cursor.fetchone()

        if result is None:
            logger.warning(f"MAC {mac} not found in access_points. Skipping frame count update.")
            return

        # Convert from JSON or initialize empty dict
        frame_counts = json.loads(result[0]) if result[0] else {}

        # Increment frame count
        frame_counts[frame_type] = frame_counts.get(frame_type, 0) + 1

        # Update database
        cursor.execute("UPDATE access_points SET frame_counts = ? WHERE mac = ?",
                       (json.dumps(frame_counts), mac))
        db_conn.commit()

        logger.debug(f"Updated frame_counts for {mac}: {frame_counts}")

    except Exception as e:
        logger.error(f"Error updating frame count for {mac}: {e}")


def update_total_data(mac, packet_length, db_conn):
    """Update total data usage for a MAC address in the database."""
    try:
        logger.debug(f"Updating total data for {mac}: +{packet_length} bytes")

        cursor = db_conn.cursor()

        cursor.execute("SELECT total_data FROM access_points WHERE mac = ?", (mac,))
        result = cursor.fetchone()

        if result is None:
            logger.warning(f"MAC {mac} not found in access_points table. Inserting new entry.")
            cursor.execute("""
                INSERT INTO access_points (mac, total_data)
                VALUES (?, ?)
            """, (mac, packet_length))
        else:
            updated_total = result[0] + packet_length
            cursor.execute("""
                UPDATE access_points
                SET total_data = ?
                WHERE mac = ?
            """, (updated_total, mac))
            logger.debug(f"Updated total_data for {mac}: {updated_total}")

        db_conn.commit()
    except Exception as e:
        logger.error(f"Error updating total data for {mac}: {e}")


def store_results_in_db(device_dict, db_conn):
    """Store parsed results into the database."""
    try:
        cursor = db_conn.cursor()
        for ap_mac, ap_info in device_dict.items():
            try:
                encryption = ",".join(ap_info['encryption']) if isinstance(ap_info['encryption'], set) else ap_info['encryption']
                if not ap_info['ssid'] and not ap_info['encryption']:
                    logger.warning(f"AP with MAC {ap_mac} has missing details: SSID={ap_info['ssid']}, Encryption={ap_info['encryption']}")
                    continue

                cursor.execute("""
                INSERT OR REPLACE INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (ap_info['mac'], ap_info['ssid'], encryption, ap_info['last_seen'], ap_info['manufacturer'],
                      ap_info['signal_strength'], ap_info['channel'], ap_info['extended_capabilities'], ap_info.get('total_data', 0)))

                for client in ap_info.get('clients', []):
                    cursor.execute("""
                    INSERT OR REPLACE INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (client['mac'], client['ssid'], client['last_seen'], client['manufacturer'], client['signal_strength'], ap_info['mac'], client.get('total_data', 0)))
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
        logger.info(f"Processing PCAP file: {pcap_file}")

        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                try:
                    parse_packet(packet, device_dict, oui_mapping, db_conn)
                except Scapy_Exception as e:
                    logger.warning(f"Skipped corrupted packet: {e}")
                    continue  # **Skip invalid packets instead of stopping**

        logger.debug(f"Device dictionary after processing: {device_dict}")
        store_results_in_db(device_dict, db_conn)  # Use db_conn instead of db_path
        logger.info("PCAP processing complete.")

    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")


def live_scan(interface, db_conn, capture_file, process):
    """Live scan parsing with real-time packet processing and enhanced error handling."""
    logger.info(f"Starting live parsing on: {capture_file}")

    try:
        # **Ensure capture file exists before proceeding**
        while not os.path.exists(capture_file):
            logger.info(f"Waiting for capture file: {capture_file}")
            time.sleep(3)

        logger.info("hcxdumptool started. Parsing packets in real-time... Press Ctrl+C to stop.")

        # **Open the capture file for live reading**
        with PcapReader(capture_file) as pcap_reader:
            for packet in pcap_reader:
                try:
                    # **Attempt to parse each packet**
                    parse_packet(packet, device_dict={}, oui_mapping=parse_oui_file(), db_conn=db_conn)

                except OSError as e:
                    if "Invalid Block body length" in str(e):
                        logger.warning(f"Handling invalid block: {e}. Attempting to recover.")

                        # **Attempt to skip only the problematic packet**
                        continue  # Skip the packet instead of stopping

                    else:
                        logger.error(f"Unexpected OS error: {e}")
                        continue  # Ensure the loop continues

                except Scapy_Exception as e:
                    logger.warning(f"Skipped corrupted packet: {e}")
                    continue  # Skip corrupted packets

                except ValueError as e:
                    logger.warning(f"Malformed packet skipped: {e}")
                    continue  # Skip malformed packets

                except Exception as e:
                    logger.error(f"Unexpected parsing error: {e}")
                    continue  # Skip unknown errors instead of stopping

                # **Check if hcxdumptool is still running**
                if process.poll() is not None:
                    logger.warning("hcxdumptool stopped unexpectedly. Restarting...")
                    process = subprocess.Popen(
                        f"hcxdumptool -i {interface} -o {capture_file}",
                        shell=True, preexec_fn=os.setsid
                    )

    except KeyboardInterrupt:
        logger.info("Stopping live scan. Terminating hcxdumptool...")
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)  # **Terminate hcxdumptool properly**

    except Exception as e:
        logger.error(f"Unexpected error during live scanning: {e}")

    finally:
        logger.info("Closing database connection after live scanning.")
