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
        cursor = db_conn.cursor()

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

            # **Update or Insert AP into database**
            cursor.execute("""
                INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                total_data=access_points.total_data + excluded.total_data
            """, (bssid, essid, crypto, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), manufacturer, dbm_signal, channel, extended_capabilities, packet_length))

            db_conn.commit()
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

            # **Log client even if not associated with an AP**
            cursor.execute("""
                INSERT OR IGNORE INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (client_mac, essid if essid else "Unknown", datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  get_manufacturer(client_mac, oui_mapping), dbm_signal, associated_ap if associated_ap else None, packet_length))

            db_conn.commit()
            logger.info(f"Client recorded in database: {client_mac}, Associated AP: {associated_ap if associated_ap else 'None'}")

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
                device_dict[bssid] = {
                    'mac': bssid, 'ssid': essid, 'encryption': "Unknown", 'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': get_manufacturer(bssid, oui_mapping), 'signal_strength': dbm_signal, 'channel': None,
                    'extended_capabilities': "No Extended Capabilities", 'clients': [], 'total_data': packet_length
                }

            # **Store Probe Response AP in Database**
            cursor.execute("""
                INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                total_data=access_points.total_data + excluded.total_data
            """, (bssid, essid, "Unknown", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), get_manufacturer(bssid, oui_mapping),
                  dbm_signal, None, "No Extended Capabilities", packet_length))

            db_conn.commit()
            logger.info(f"Probe Response detected, stored as AP: {device_dict[bssid]}")

        elif packet.haslayer(Dot11Auth) or packet.haslayer(Dot11AssoReq):
            frame_type = "auth" if packet.haslayer(Dot11Auth) else "assoc_req"
            client_mac = getattr(packet[Dot11], 'addr2', '').lower()
            ap_mac = getattr(packet[Dot11], 'addr1', '').lower()

            if client_mac and ap_mac:
                logger.info(f"Client {client_mac} attempting {frame_type} with AP {ap_mac}")

                cursor.execute("""
                    INSERT OR IGNORE INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (client_mac, "", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), get_manufacturer(client_mac, oui_mapping),
                      dbm_signal, ap_mac, packet_length))

                db_conn.commit()

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


def live_scan(capture_file, db_conn, process):
    """Live scan parsing that continuously reads from the capture file."""
    logger.info(f"Starting live parsing on: {capture_file}")

    device_dict = {}  # **Ensure persistent tracking of detected devices**

    try:
        # **Wait until the capture file is created**
        while not os.path.exists(capture_file):
            logger.info(f"Waiting for capture file: {capture_file}")
            time.sleep(3)

        logger.info("hcxdumptool started. Parsing packets in real-time... Press Ctrl+C to stop.")

        while process.poll() is None:  # **Ensure hcxdumptool is still running**
            try:
                with PcapReader(capture_file) as pcap_reader:
                    packet_count = 0
                    for packet in pcap_reader:
                        try:
                            parse_packet(packet, device_dict, oui_mapping=parse_oui_file(), db_conn=db_conn)
                            packet_count += 1

                            # **Commit to DB every 50 packets**
                            if packet_count % 50 == 0:
                                store_results_in_db(device_dict, db_conn)
                                db_conn.commit()

                        except Scapy_Exception as e:
                            logger.warning(f"Skipped corrupted packet: {e}")
                            continue
                        except ValueError as e:
                            logger.warning(f"Malformed packet skipped: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Unexpected parsing error: {e}")
                            continue

                time.sleep(1)  # **Allow time for new packets before reopening the file**

            except FileNotFoundError:
                logger.warning(f"Capture file {capture_file} not found. Waiting...")
                time.sleep(2)
            except Exception as e:
                logger.error(f"Unexpected error during live scanning: {e}")

    except KeyboardInterrupt:
        logger.info("Stopping live scan. Terminating hcxdumptool...")
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    finally:
        # **Final DB Commit to ensure latest results are saved**
        store_results_in_db(device_dict, db_conn)
        db_conn.commit()
        logger.info("Closing database connection after live scanning.")

