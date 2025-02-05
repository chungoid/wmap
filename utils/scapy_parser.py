import logging
import os
import signal
import time
import datetime
import re
import json

from datetime import datetime
from scapy.error import Scapy_Exception
from scapy.utils import PcapReader
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11ProbeResp, RadioTap, Dot11Deauth, Dot11AssoResp, Dot11ReassoReq, Dot11ReassoResp, Dot11Disas
)

from config.config import DEFAULT_OUI_PATH

logger = logging.getLogger("wmap")
oui_file = DEFAULT_OUI_PATH

def live_scan(capture_file, db_conn, process, gps_file=None):
    """Live scan parsing that continuously reads from the capture file."""
    logger.info(f"Starting live parsing on: {capture_file}")

    device_dict = {}  # Ensure persistent tracking of detected devices**
    oui_mapping = parse_oui_file()  # Load OUI mapping once at the start

    gps_data = None  # Initialize GPS data

    try:
        # Wait until the capture file is created
        while not os.path.exists(capture_file):
            logger.info(f"Waiting for capture file: {capture_file}")
            time.sleep(3)

        logger.info("hcxdumptool started. Parsing packets in real-time... Press Ctrl+C to stop.")

        while process.poll() is None:  # Ensure hcxdumptool is still running
            try:
                # Update GPS data if GPS file exists
                if gps_file and os.path.exists(gps_file):
                    gps_data = process_nmea(gps_file)  # Continuously update GPS data

                with PcapReader(capture_file) as pcap_reader:
                    packet_count = 0
                    for packet in pcap_reader:
                        try:
                            # Pass `oui_mapping` and `gps_data` to `parse_packet()`
                            parse_packet(packet, device_dict, oui_mapping, db_conn, gps_data=gps_data)
                            packet_count += 1

                            # Commit to DB every 50 packets
                            if packet_count % 50 == 0:
                                store_results_in_db(device_dict, db_conn)
                                db_conn.commit()

                        except (Scapy_Exception, ValueError) as e:
                            logger.warning(f"Skipped corrupted packet: {e}")
                            continue
                        except Exception as e:
                            logger.error(f"Unexpected parsing error: {e}")
                            continue

                time.sleep(1)  # Allow time for new packets before reopening the file

            except FileNotFoundError:
                logger.warning(f"Capture file {capture_file} not found. Waiting...")
                time.sleep(2)
            except Exception as e:
                logger.error(f"Unexpected error during live scanning: {e}")

    except KeyboardInterrupt:
        logger.info("Stopping live scan. Terminating hcxdumptool...")
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)

    finally:
        # Final DB Commit
        store_results_in_db(device_dict, db_conn)
        db_conn.commit()
        logger.info("Closing database connection after live scanning.")


def process_pcapng(pcap_file, db_conn, gps_data=None):
    """
    Process a PCAP file and parse its packets.

    Args:
        pcap_file (str): Path to the PCAP file to process.
        db_conn: SQLite database connection.
        gps_data (dict, optional): GPS timestamp-to-coordinates mapping from NMEA.

    """
    device_dict = {}  # Initialize a dictionary to track detected devices
    oui_mapping = parse_oui_file()  # Load OUI file for MAC-to-manufacturer mapping

    try:
        logger.info(f"Processing PCAP file: {pcap_file}")

        with PcapReader(pcap_file) as pcap_reader:
            for packet in pcap_reader:
                try:
                    parse_packet(packet, device_dict, oui_mapping, db_conn, gps_data=gps_data)
                except Scapy_Exception as e:
                    logger.warning(f"Skipped corrupted packet: {e}")
                    continue  # Skip invalid packets

        # **Store final results in the database**
        logger.debug(f"Device dictionary after processing: {device_dict}")
        store_results_in_db(device_dict, db_conn)
        logger.info("PCAP processing complete.")

    except FileNotFoundError:
        logger.error(f"PCAP file not found: {pcap_file}")
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")


def parse_packet(packet, device_dict, oui_mapping, db_conn, gps_data=None):
    """Parse a packet and extract APs, clients, and optionally GPS latitude/longitude, with WPS & Extended Capabilities."""
    try:
        if not packet.haslayer(Dot11):
            return  # Skip non-802.11 packets

        frame_type = None
        packet_length = len(packet)
        dbm_signal = getattr(packet[RadioTap], 'dBm_AntSignal', None) if packet.haslayer(RadioTap) else None

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

        # Process Access Points
        if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
            logger.debug(f"Processing AP frame (Beacon or Probe Response) for {mac}.")

            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            stats = packet[Dot11Beacon].network_stats() if packet.haslayer(Dot11Beacon) else {}
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')

            # Ensure encryption is stored as a string instead of a set
            if isinstance(crypto, set):
                crypto = ", ".join(crypto)  # Convert set to string

            manufacturer = get_manufacturer(mac, oui_mapping)

            # Detect WPS Before Parsing Extended Capabilities
            wps_info = None
            extended_capabilities = "No Extended Capabilities"

            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 221:  # Vendor-Specific IE (0xDD) - Check for WPS
                        vendor_data = elt.info
                        if vendor_data[:3] == b'\x00\x50\xF2' and vendor_data[3] == 0x04:  # WPS OUI + Type 0x04
                            try:
                                wps_config_methods = int.from_bytes(vendor_data[8:10], 'big') if len(vendor_data) > 9 else None
                                config_methods = []
                                if wps_config_methods:
                                    if wps_config_methods & 0x0100:
                                        config_methods.append("PIN Mode (Pixie Dust Vulnerable)")
                                    if wps_config_methods & 0x0800:
                                        config_methods.append("Virtual Display")
                                if config_methods:
                                    wps_info = ", ".join(config_methods)
                            except Exception as e:
                                logger.error(f"Failed to extract WPS details for {mac}: {e}")

                    elif elt.ID == 127:  # Extended Capabilities Tag
                        try:
                            hex_data = elt.info.hex()
                            if len(hex_data) > 2:
                                extended_capabilities = decode_extended_capabilities(hex_data)
                        except Exception as e:
                            logger.error(f"Failed to process extended capabilities for {mac}: {e}")
                            extended_capabilities = "No Extended Capabilities"
                    elt = elt.payload

            if wps_info:
                extended_capabilities = (
                    f"{extended_capabilities}, {wps_info}" if extended_capabilities != "No Extended Capabilities" else wps_info
                )

            # Ensure AP exists in device_dict
            if mac not in device_dict:
                device_dict[mac] = {
                    'mac': mac, 'ssid': ssid, 'encryption': crypto,
                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal, 'channel': channel,
                    'extended_capabilities': extended_capabilities, 'clients': [], 'total_data': packet_length,
                    'frame_counts': {}
                }

            # Update frame counts for AP
            device_dict[mac]['frame_counts'][frame_type] = device_dict[mac]['frame_counts'].get(frame_type, 0) + 1

        # Process Clients
        elif frame_type in ["probe_req", "auth", "assoc_req", "reassoc_req"]:
            logger.debug(f"Processing Client frame for {mac}. Frame Type: {frame_type}")

            # Extract the AP's MAC address properly
            associated_ap = None
            if frame_type in ["auth", "assoc_req", "reassoc_req"]:
                associated_ap = getattr(packet[Dot11], 'addr1', '').lower()  # AP's MAC should be in addr1

            ssid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            manufacturer = get_manufacturer(mac, oui_mapping)

            # Log valid associations for debugging
            if associated_ap and associated_ap != "ff:ff:ff:ff:ff:ff":
                logger.debug(f"Client {mac} associated with AP {associated_ap}")

            # Insert or update client data
            if mac not in device_dict:
                device_dict[mac] = {
                    'mac': mac, 'ssid': ssid, 'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'manufacturer': manufacturer, 'signal_strength': dbm_signal,
                    'associated_ap': associated_ap,  # No defaults to ff:ff:ff:ff:ff:ff
                    'total_data': packet_length, 'frame_counts': {}
                }
            else:
                # Only update associated_ap if it's a valid MAC (not None, not ff:ff:ff:ff:ff:ff)
                if associated_ap and associated_ap != "ff:ff:ff:ff:ff:ff":
                    device_dict[mac]['associated_ap'] = associated_ap

            # Update frame counts
            device_dict[mac]['frame_counts'][frame_type] = device_dict[mac]['frame_counts'].get(frame_type, 0) + 1

        # GPS Data Matching (if Available)
        if gps_data and len(gps_data) > 0:
            timestamp = packet.time  # Extract timestamp from packet

            # Find the closest timestamp safely
            if gps_data:
                valid_timestamps = [t for t in gps_data.keys() if t is not None]
                if valid_timestamps:
                    closest_timestamp = min(valid_timestamps, key=lambda t: abs(t - timestamp))
                    latitude, longitude = gps_data.get(closest_timestamp, (None, None))
                else:
                    latitude, longitude = None, None
            else:
                latitude, longitude = None, None

            # Assign GPS coordinates to the device entry
            device_dict[mac]['latitude'] = latitude
            device_dict[mac]['longitude'] = longitude

        # Debugging Device Dictionary Before Storing
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Device Dictionary Before Storing:\n{json.dumps(device_dict, indent=4)}")

        # Pass Device Dictionary to Database Storage
        store_results_in_db(device_dict, db_conn)

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")


def store_results_in_db(device_dict, db_conn):
    """Store parsed results into the database and retain frame_counts."""

    logger.debug(f"Parsed Device Dictionary Before DB Insert:\n{json.dumps(device_dict, indent=4)}")

    try:
        cursor = db_conn.cursor()

        for mac, device_info in device_dict.items():
            try:
                # Ensure latitude and longitude are stored as None or proper float values
                latitude = device_info.get("latitude", None)
                longitude = device_info.get("longitude", None)

                # Ensure they're converted to NULL in SQL if None
                if latitude is None or longitude is None:
                    latitude, longitude = None, None  # Explicitly set to None for proper DB handling

                if "associated_ap" in device_info:  # Client Table
                    cursor.execute("""
                        INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap,
                                            total_data, frame_counts, latitude, longitude)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac) DO UPDATE SET
                        ssid=excluded.ssid, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                        signal_strength=excluded.signal_strength, associated_ap=excluded.associated_ap,
                        total_data=clients.total_data + excluded.total_data,
                        frame_counts=excluded.frame_counts,
                        latitude=excluded.latitude,
                        longitude=excluded.longitude
                    """, (device_info['mac'], device_info.get('ssid', ''), device_info['last_seen'],
                          device_info['manufacturer'], device_info['signal_strength'],
                          device_info.get('associated_ap', 'Unknown'), device_info.get('total_data', 0),
                          json.dumps(device_info.get("frame_counts", {})), latitude, longitude))

                    logger.debug(
                        f"Client inserted into database: {mac} -> Associated AP: {device_info.get('associated_ap', 'Unknown')}")

                else:  # Access Point Entry
                    encryption = device_info.get('encryption', 'None')

                    # Convert encryption from set to string if necessary
                    if isinstance(encryption, set):
                        encryption = ", ".join(encryption)
                    elif not isinstance(encryption, str):
                        encryption = str(encryption)

                    logger.debug(f"Inserting AP into DB: {device_info}")

                    cursor.execute("""
                        INSERT INTO access_points (mac, ssid, encryption, last_seen, manufacturer, signal_strength, channel,
                                                   extended_capabilities, total_data, frame_counts, latitude, longitude)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac) DO UPDATE SET
                        ssid=excluded.ssid, encryption=excluded.encryption, last_seen=excluded.last_seen, manufacturer=excluded.manufacturer,
                        signal_strength=excluded.signal_strength, channel=excluded.channel, extended_capabilities=excluded.extended_capabilities,
                        total_data=access_points.total_data + excluded.total_data,
                        frame_counts=excluded.frame_counts,
                        latitude=excluded.latitude,
                        longitude=excluded.longitude
                    """, (device_info['mac'], device_info.get('ssid', ''), encryption, device_info['last_seen'],
                          device_info['manufacturer'], device_info['signal_strength'], device_info['channel'],
                          device_info.get('extended_capabilities', 'None'), device_info.get('total_data', 0),
                          json.dumps(device_info.get("frame_counts", {})), latitude, longitude))

                    logger.debug(f"Access Point inserted into database: {mac}")

            except Exception as e:
                logger.error(f"Error inserting {mac} into database: {e}")

        db_conn.commit()
        logger.debug("Database commit successful.")

    except Exception as e:
        logger.error(f"Error storing results in the database: {e}")


def decode_extended_capabilities(data):
    """Decode security-relevant Extended Capabilities from packets."""
    if not isinstance(data, str):
        logger.debug("Extended capabilities data is invalid or not a string.")
        return "No Extended Capabilities"

    try:
        capabilities_bytes = bytes.fromhex(data)
        features = []

        # ** Management Frame Protection (MFP) - Byte 1, Bit 2**
        if len(capabilities_bytes) > 1 and not (capabilities_bytes[1] & (1 << 2)):
            features.append("No Management Frame Protection")

        # ** BSS Transition (802.11v) - Byte 0, Bit 6**
        if len(capabilities_bytes) > 0 and (capabilities_bytes[0] & (1 << 6)):
            features.append("BSS Transition Enabled")

        # ** TDLS Support - Byte 3, Bits 0-2**
        if len(capabilities_bytes) > 3:
            if capabilities_bytes[3] & (1 << 0):
                features.append("TDLS Supported")
            if capabilities_bytes[3] & (1 << 1):
                features.append("TDLS Prohibited Not Set")
            if capabilities_bytes[3] & (1 << 2):
                features.append("TDLS Channel Switching Allowed")

        # ** Opportunistic Key Caching (OKC) - Byte 4, Bit 0**
        if len(capabilities_bytes) > 4 and (capabilities_bytes[4] & (1 << 0)):
            features.append("Opportunistic Key Caching Enabled")

        # ** Extended Channel Switching - Byte 0, Bit 0**
        if len(capabilities_bytes) > 0 and (capabilities_bytes[0] & (1 << 0)):
            features.append("Extended Channel Switching Enabled")

        # ** Wi-Fi Protected Setup (WPS) Detection**
        if "WPS" in data:
            features.append("WPS Enabled")

        if not features:
            return "No Extended Capabilities"

        formatted_features = ", ".join(features)
        logger.debug(f"Parsed Extended Capabilities: {formatted_features}")

        return formatted_features

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


def process_nmea(nmea_file):
    """Process an NMEA file and extract timestamped GPS coordinates."""
    gps_data = {}

    try:
        with open(nmea_file, "r") as file:
            for line in file:
                match = re.match(r"\$(GPGGA|GPRMC),([^*]+)", line)
                if not match:
                    continue

                sentence_type, data = match.groups()
                fields = data.split(",")

                if sentence_type == "GPGGA" and len(fields) >= 6:
                    time_raw, lat_raw, lat_dir, lon_raw, lon_dir = fields[:5]
                elif sentence_type == "GPRMC" and len(fields) >= 7:
                    time_raw, lat_raw, lat_dir, lon_raw, lon_dir = fields[1:6]
                else:
                    continue

                timestamp = convert_nmea_time(time_raw)
                latitude = convert_nmea_coordinates(lat_raw, lat_dir)
                longitude = convert_nmea_coordinates(lon_raw, lon_dir)

                if timestamp is not None and latitude is not None and longitude is not None:
                    gps_data[timestamp] = (latitude, longitude)

    except FileNotFoundError:
        logger.warning(f"NMEA file not found: {nmea_file}")
    except Exception as e:
        logger.error(f"Error processing NMEA file: {e}")

    logger.debug(f"Processed GPS Data: {gps_data}")
    return gps_data if gps_data else {}


def convert_nmea_time(nmea_time):
    """
    Convert NMEA time (HHMMSS) into a Unix timestamp.

    Args:
        nmea_time (str): Time from NMEA sentence (e.g., '123456' for 12:34:56 UTC).

    Returns:
        float: Unix timestamp.
    """
    try:
        # Extract HH, MM, SS from NMEA format
        hours, minutes, seconds = int(nmea_time[:2]), int(nmea_time[2:4]), int(nmea_time[4:6])

        # Get current UTC date
        now = time.gmtime()  # Get current UTC time struct
        timestamp = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, hours, minutes, seconds, 0, 0, 0))

        return timestamp
    except ValueError:
        return None  # Return None if time conversion fails


def convert_nmea_coordinates(value, direction):
    """
    Convert NMEA latitude/longitude format to decimal degrees.

    Args:
        value (str): Latitude or longitude value from NMEA (e.g., '4807.038' for 48°07.038').
        direction (str): Direction ('N', 'S', 'E', 'W').

    Returns:
        float: Decimal degrees.
    """
    try:
        if not value:
            return None

        # Split degrees and minutes
        if "." in value:
            degrees = int(value[:-7])  # Extract degrees (first part)
            minutes = float(value[-7:])  # Extract minutes (remaining)
        else:
            return None  # Invalid format

        # Convert to decimal degrees
        decimal_degrees = degrees + (minutes / 60)

        # Apply direction
        if direction in ["S", "W"]:
            decimal_degrees = -decimal_degrees

        return decimal_degrees
    except ValueError:
        return None  # Return None if conversion fails


def parse_nmea_sentence(nmea_sentence):
    """
    Parse an NMEA sentence to extract timestamp, latitude, and longitude.

    Args:
        nmea_sentence (str): A raw NMEA sentence (e.g., $GPGGA or $GPRMC).

    Returns:
        tuple: (timestamp, latitude, longitude) or (None, None, None) if parsing fails.
    """
    try:
        # Match NMEA sentence types
        match = re.match(r"\$(GPGGA|GPRMC),([^*]+)", nmea_sentence)
        if not match:
            return None, None, None  # Invalid sentence

        sentence_type, data = match.groups()
        fields = data.split(",")

        if sentence_type == "GPGGA" and len(fields) >= 6:
            time_raw, lat_raw, lat_dir, lon_raw, lon_dir = fields[:5]
        elif sentence_type == "GPRMC" and len(fields) >= 7:
            time_raw, lat_raw, lat_dir, lon_raw, lon_dir = fields[1:6]
        else:
            return None, None, None  # Skip malformed data

        # Convert NMEA time to Unix timestamp
        timestamp = convert_nmea_time(time_raw)

        # Convert latitude and longitude to decimal degrees
        latitude = convert_nmea_coordinates(lat_raw, lat_dir)
        longitude = convert_nmea_coordinates(lon_raw, lon_dir)

        if latitude is not None and longitude is not None:
            return timestamp, latitude, longitude

    except Exception as e:
        logger.error(f"Failed to parse NMEA sentence: {nmea_sentence} - {e}")

    return None, None, None  # Return empty values if parsing fails
