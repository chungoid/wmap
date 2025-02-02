import logging
import os
import signal
import json
import time

from datetime import datetime
from scapy.error import Scapy_Exception
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


def decode_extended_capabilities(data):
    """Decode extended capabilities from packets."""
    if isinstance(data, bytes):
        data = data.hex()  # Convert bytes to hex string

    if not isinstance(data, str) or len(data) < 2:
        logger.debug("Extended capabilities data is invalid or too short.")
        return "No Extended Capabilities"

    try:
        features = []
        capabilities_bytes = bytes.fromhex(data)  # Convert hex string to bytes

        # Iterate over each byte and check bit flags
        for index, byte in enumerate(capabilities_bytes):
            if byte & (1 << 0):
                features.append(f"Extended Channel Switching (Byte {index})")
            if byte & (1 << 1):
                features.append(f"WNM Sleep Mode (Byte {index})")
            if byte & (1 << 2):
                features.append(f"TIM Broadcast (Byte {index})")
            if byte & (1 << 3):
                features.append(f"Support for Spectrum Management (Byte {index})")
            if byte & (1 << 4):
                features.append(f"Support for QOS Traffic Capability (Byte {index})")
            if byte & (1 << 5):
                features.append(f"Support for Emergency Services (Byte {index})")

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
        if not packet.haslayer(Dot11):
            return  # Skip non-802.11 packets

        frame_type = None
        packet_length = len(packet)
        dbm_signal = getattr(packet[RadioTap], 'dBm_AntSignal', None) if packet.haslayer(RadioTap) else None
        cursor = db_conn.cursor()

        mac = getattr(packet[Dot11], 'addr2', '').lower()
        if not mac:
            return  # Skip if MAC is missing

        # Determine the frame subtype
        if packet.haslayer(Dot11Beacon):
            frame_type = "beacon"
        elif packet.haslayer(Dot11ProbeResp):
            frame_type = "probe_resp"
        elif packet.haslayer(Dot11ProbeReq):
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
        elif packet.haslayer(Dot11Disas):
            frame_type = "disas"
        elif packet.haslayer(Dot11Deauth):
            frame_type = "deauth"

        # **1. Check if MAC is already classified as a client**
        cursor.execute("SELECT mac FROM clients WHERE mac = ?", (mac,))
        client_entry = cursor.fetchone()
        if client_entry:
            logger.warning(f"Skipping AP insertion for {mac}, it is already classified as a client.")
            return

        # **2. Process Access Points**
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            logger.debug("Processing AP frame (Beacon or Probe Response).")

            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')
            manufacturer = get_manufacturer(mac, oui_mapping)
            extended_capabilities = "No Extended Capabilities"  # Default
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 127:  # Extended Capabilities Tag
                        try:
                            hex_data = elt.info.hex()
                            logger.debug(f"Raw Extended Capabilities Data for {mac}: {hex_data}")
                            if len(hex_data) > 2:  # Ensure it's a valid short hex string
                                extended_capabilities = decode_extended_capabilities(hex_data)
                        except Exception as e:
                            logger.error(f"Failed to process extended capabilities: {e}")
                            extended_capabilities = "No Extended Capabilities"  # Fallback
                        break
                    elt = elt.payload  # Move to the next Information Element (IE)

            # **Ensure AP exists in device_dict**
            if mac not in device_dict:
                device_dict[mac] = {
                    'mac': mac, 'ssid': ssid, 'encryption': crypto,
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal, 'channel': channel,
                    'extended_capabilities': extended_capabilities, 'clients': [], 'total_data': packet_length,
                    'frame_counts': {}  # Initialize frame_counts
                }

            # **Update frame counts for AP**
            device_dict[mac]['frame_counts'][frame_type] = device_dict[mac]['frame_counts'].get(frame_type, 0) + 1

        # **3. Process Clients**
        elif frame_type in ["probe_req", "auth", "assoc_req", "assoc_resp", "reassoc_req", "reassoc_resp", "disas", "deauth"]:
            logger.debug("Processing Client frame.")

            associated_ap = getattr(packet[Dot11], 'addr1', '').lower()
            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            manufacturer = get_manufacturer(mac, oui_mapping)

            # **Insert or update client data**
            if mac not in device_dict:
                device_dict[mac] = {
                    'mac': mac, 'ssid': ssid, 'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal, 'associated_ap': associated_ap,
                    'total_data': packet_length, 'frame_counts': {}
                }

            # **Update frame counts for clients**
            device_dict[mac]['frame_counts'][frame_type] = device_dict[mac]['frame_counts'].get(frame_type, 0) + 1

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")


def store_results_in_db(device_dict, db_conn):
    """Store parsed results into the database and retain frame_counts."""
    try:
        cursor = db_conn.cursor()

        for mac, device_info in device_dict.items():
            try:
                # **Retrieve existing frame_counts before updating**
                cursor.execute("SELECT frame_counts FROM access_points WHERE mac = ?", (mac,))
                result = cursor.fetchone()
                if result:
                    try:
                        existing_frame_counts = json.loads(result[0]) if result[0] else {}
                    except json.JSONDecodeError:
                        existing_frame_counts = {}
                else:
                    existing_frame_counts = {}

                # **Merge new frame counts**
                for frame_type, count in device_info.get("frame_counts", {}).items():
                    existing_frame_counts[frame_type] = existing_frame_counts.get(frame_type, 0) + count

                frame_counts_json = json.dumps(existing_frame_counts)

                if "associated_ap" in device_info:  # Client
                    cursor.execute("""
                    INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap, total_data, frame_counts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                    ssid=excluded.ssid, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                    signal_strength=excluded.signal_strength, associated_ap=excluded.associated_ap,
                    total_data=clients.total_data + excluded.total_data,
                    frame_counts=excluded.frame_counts
                    """, (device_info['mac'], device_info['ssid'], device_info['last_seen'], device_info['manufacturer'],
                          device_info['signal_strength'], device_info['associated_ap'], device_info.get('total_data', 0), frame_counts_json))

                else:  # Access Point
                    encryption = ",".join(device_info['encryption']) if isinstance(device_info.get('encryption', ''), set) else device_info.get('encryption', '')

                    # **Log Extended Capabilities for Debugging**
                    logger.debug(f"Storing Extended Capabilities for {mac}: {device_info['extended_capabilities']}")

                    cursor.execute("""
                    INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel, extended_capabilities, total_data, frame_counts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(mac) DO UPDATE SET
                    ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                    signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                    total_data=access_points.total_data + excluded.total_data,
                    frame_counts=excluded.frame_counts
                    """, (device_info['mac'], device_info['ssid'], encryption, device_info['last_seen'],
                          device_info['manufacturer'], device_info['signal_strength'], device_info['channel'],
                          device_info['extended_capabilities'], device_info.get('total_data', 0), frame_counts_json))

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

