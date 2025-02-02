import logging
import os
import signal
import json
import time

from datetime import datetime
from scapy.error import Scapy_Exception
from scapy.fields import FlagValue
from scapy.utils import PcapReader
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11ProbeResp, RadioTap, Dot11Deauth, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11Disas
)

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
    """Parse a packet and extract information about access points and clients, including frame counts."""
    try:
        packet_length = len(packet) if packet else 0
        frame_type = None
        dbm_signal = getattr(packet[RadioTap], 'dBm_AntSignal', None) if packet.haslayer(RadioTap) else None
        cursor = db_conn.cursor()

        mac = getattr(packet[Dot11], 'addr2', '').lower()
        if not mac:
            return  # Skip if MAC is missing

        # **Check if MAC exists in access_points (AP list)**
        cursor.execute("SELECT mac FROM access_points WHERE mac = ?", (mac,))
        ap_entry = cursor.fetchone()

        # **Check if MAC exists in clients (Client list)**
        cursor.execute("SELECT mac FROM clients WHERE mac = ?", (mac,))
        client_entry = cursor.fetchone()

        if ap_entry and client_entry:
            logger.error(f"Conflict: {mac} is classified as both AP and Client!")
            return

        # **Process APs**
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            frame_type = "beacon" if packet.haslayer(Dot11Beacon) else "probe_resp"

            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')
            manufacturer = get_manufacturer(mac, oui_mapping)
            extended_capabilities = "No Extended Capabilities"

            if mac not in device_dict:
                device_dict[mac] = {
                    'mac': mac, 'ssid': ssid, 'encryption': crypto,
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal, 'channel': channel,
                    'extended_capabilities': extended_capabilities, 'clients': [], 'total_data': packet_length,
                    'frame_counts': {}
                }

            # **Ensure AP has frame_counts stored**
            cursor.execute("SELECT frame_counts FROM access_points WHERE mac = ?", (mac,))
            existing_frame_counts = cursor.fetchone()
            existing_frame_counts = json.loads(existing_frame_counts[0]) if existing_frame_counts and existing_frame_counts[0] else {}

            existing_frame_counts[frame_type] = existing_frame_counts.get(frame_type, 0) + 1
            frame_counts_json = json.dumps(existing_frame_counts)

            cursor.execute("""
                INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data, frame_counts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                total_data=access_points.total_data + excluded.total_data,
                frame_counts=excluded.frame_counts
            """, (mac, ssid, crypto, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), manufacturer, dbm_signal, channel,
                  extended_capabilities, packet_length, frame_counts_json))

            db_conn.commit()
            logger.info(f"AP updated: {device_dict[mac]}")

        # **Process Clients**
        elif any(packet.haslayer(layer) for layer in [
            Dot11ProbeReq, Dot11Auth, Dot11AssoReq, Dot11AssoResp,
            Dot11ReassoReq, Dot11ReassoResp, Dot11Deauth, Dot11Disas
        ]):
            if packet.haslayer(Dot11ProbeReq):
                frame_type = "probe_req"
            elif packet.haslayer(Dot11Auth):
                frame_type = "auth"
            elif packet.haslayer(Dot11AssoReq):
                frame_type = "assoc_req"
            elif packet.haslayer(Dot11AssoResp):
                frame_type = "assoc_resp"
            elif packet.haslayer(Dot11ReassoReq):
                frame_type = "reassoc_req"
            elif packet.haslayer(Dot11ReassoResp):
                frame_type = "reassoc_resp"
            elif packet.haslayer(Dot11Deauth):
                frame_type = "deauth"
            elif packet.haslayer(Dot11Disas):
                frame_type = "disas"

            associated_ap = getattr(packet[Dot11], 'addr1', '').lower()
            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            manufacturer = get_manufacturer(mac, oui_mapping)

            cursor.execute("""
                INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data, frame_counts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                ssid=excluded.ssid, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                signal_strength=excluded.signal_strength, associated_ap=excluded.associated_ap,
                total_data=clients.total_data + excluded.total_data,
                frame_counts=excluded.frame_counts
            """, (mac, ssid if ssid else "Unknown", datetime.now().strftime("%Y-%m-%d %H:%M:%S"), manufacturer, dbm_signal,
                  associated_ap if associated_ap else None, packet_length, '{}'))

            db_conn.commit()
            logger.info(f"Client recorded in database: {mac}, Associated AP: {associated_ap if associated_ap else 'None'}")

        # **Frame Count Updates for APs and Clients**
        if frame_type:
            target_table = "access_points" if ap_entry else "clients"

            cursor.execute(f"SELECT frame_counts FROM {target_table} WHERE mac = ?", (mac,))
            frame_counts = cursor.fetchone()
            frame_counts = json.loads(frame_counts[0]) if frame_counts and frame_counts[0] else {}
            frame_counts[frame_type] = frame_counts.get(frame_type, 0) + 1

            cursor.execute(f"UPDATE {target_table} SET frame_counts = ? WHERE mac = ?",
                           (json.dumps(frame_counts), mac))
            db_conn.commit()

            logger.debug(f"Updated frame_counts for {mac} in {target_table}: {frame_counts}")

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")



def store_results_in_db(device_dict, db_conn):
    """Store parsed results into the database and retain frame_counts for APs and Clients."""
    try:
        cursor = db_conn.cursor()

        for mac, info in device_dict.items():
            try:
                encryption = ",".join(info['encryption']) if isinstance(info['encryption'], set) else info['encryption']

                # **Retrieve existing frame_counts before updating (For APs & Clients)**
                cursor.execute("SELECT frame_counts FROM access_points WHERE mac = ?", (mac,))
                ap_result = cursor.fetchone()
                cursor.execute("SELECT frame_counts FROM clients WHERE mac = ?", (mac,))
                client_result = cursor.fetchone()

                # **Load frame counts from DB (or reset to empty dict if missing)**
                existing_ap_frame_counts = json.loads(ap_result[0]) if ap_result and ap_result[0] else {}
                existing_client_frame_counts = json.loads(client_result[0]) if client_result and client_result[0] else {}

                # **Ensure valid dictionary format**
                if not isinstance(existing_ap_frame_counts, dict):
                    existing_ap_frame_counts = {}
                if not isinstance(existing_client_frame_counts, dict):
                    existing_client_frame_counts = {}

                # **Merge new frame counts**
                new_frame_counts = info.get("frame_counts", {})
                for frame_type, count in new_frame_counts.items():
                    if info.get("clients"):  # If it's a client, update client frame counts
                        existing_client_frame_counts[frame_type] = existing_client_frame_counts.get(frame_type, 0) + count
                    else:  # Otherwise, update AP frame counts
                        existing_ap_frame_counts[frame_type] = existing_ap_frame_counts.get(frame_type, 0) + count

                # **Convert frame_counts back to JSON**
                ap_frame_counts_json = json.dumps(existing_ap_frame_counts)
                client_frame_counts_json = json.dumps(existing_client_frame_counts)

                # **Insert or update AP, preserving frame_counts**
                cursor.execute("""
                INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data, frame_counts)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                total_data=access_points.total_data + excluded.total_data,
                frame_counts=excluded.frame_counts
                """, (info['mac'], info['ssid'], encryption, info['last_seen'], info['manufacturer'],
                      info['signal_strength'], info['channel'], info['extended_capabilities'], info.get('total_data', 0), ap_frame_counts_json))

                # **Insert clients into the database, preserving frame_counts**
                for client in info.get('clients', []):
                    cursor.execute("""
                    INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data, frame_counts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                    ssid=excluded.ssid, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                    signal_strength=excluded.signal_strength, associated_ap=excluded.associated_ap,
                    total_data=clients.total_data + excluded.total_data,
                    frame_counts=excluded.frame_counts
                    """, (client['mac'], client['ssid'], client['last_seen'], client['manufacturer'], client['signal_strength'], info['mac'], client.get('total_data', 0), client_frame_counts_json))

                    logger.info(f"Inserted client into database: {client}")

            except Exception as e:
                logger.error(f"Error inserting {mac} into database: {e}")

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

