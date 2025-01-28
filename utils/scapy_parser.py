import sqlite3
import logging
import json
import os
from scapy.all import rdpcap, sniff
from datetime import datetime
from scapy.fields import FlagValue
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11EltRates, Dot11ProbeResp, RadioTap
)

from config.config import DEFAULT_DB_PATH, DEFAULT_OUI_PATH
from utils import setup_work
from utils.setup_work import get_db_connection

logger = logging.getLogger("scapy_parser")
setup_work.initialize_db(DEFAULT_DB_PATH)

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

def parse_oui_file(oui_file=DEFAULT_OUI_PATH):
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
    except Exception as e:
        logger.error(f"Error parsing OUI file: {e}")
    return oui_mapping

def get_manufacturer(mac, oui_mapping):
    oui_prefix = mac[:8].lower()
    return oui_mapping.get(oui_prefix, 'Unknown')

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

def parse_packet(packet):
    packet_info = {}
    try:
        if packet.haslayer(Dot11Beacon):
            logger.debug(f"Parsing Dot11Beacon layer.")
            bssid = getattr(packet[Dot11], 'addr2', None)
            if bssid:
                bssid = bssid.upper()
            else:
                logger.error("BSSID missing from packet.")
                return {}

            essid = packet[Dot11Elt].info.decode(errors='ignore') if packet.haslayer(Dot11Elt) else ''
            dbm_signal = getattr(packet, 'dBm_AntSignal', None)
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get('channel', 0)
            crypto = stats.get('crypto', 'None')

            logger.debug(f"BSSID: {bssid}, ESSID: {essid}, Signal: {dbm_signal}, Channel: {channel}, Crypto: {crypto}")

            extended_capabilities = bytes_to_hex_string(
                getattr(packet.getlayer(Dot11Elt, ID=127), 'info', None))
            logger.debug(f"Extended Capabilities Raw: {extended_capabilities}")

            packet_info['Dot11Beacon'] = {
                'bssid': bssid,
                'essid': essid,
                'dbm_signal': dbm_signal,
                'channel': channel,
                'crypto': crypto,
                'extended_capabilities': decode_extended_capabilities(extended_capabilities),
            }
            packet_info['type'] = 'AP'
    except Exception as e:
        logger.error(f"Error parsing packet: {e}")
    return packet_info

def update_device_dict(device_dict, packet_info, oui_mapping):
    try:
        mac = packet_info['Dot11Beacon'].get('bssid', '')
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


def store_results_in_db(device_dict, db_path=DEFAULT_DB_PATH):
    """Store parsed results into the database."""
    logger.debug(f"Database path used for insertion: {db_path}")
    try:
        with get_db_connection(db_path) as conn:
            cursor = conn.cursor()
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
                except Exception as e:
                    logger.error(f"Error inserting AP {ap_info['mac']} into database: {e}")

            # Verify data after commit
            conn.commit()
            cursor.execute("SELECT * FROM access_points;")
            rows = cursor.fetchall()
            logger.debug(f"Rows in access_points table after insertion: {rows}")
    except Exception as e:
        logger.error(f"Error storing results in the database: {e}")


def process_pcap(pcap_file, oui_file=DEFAULT_OUI_PATH, db_path=DEFAULT_DB_PATH):
    """Process a PCAP file and store results in the database."""
    try:
        packets = rdpcap(pcap_file)
        device_dict = {}
        oui_mapping = parse_oui_file(oui_file)

        for packet in packets:
            packet_info = parse_packet(packet)
            if packet_info:
                update_device_dict(device_dict, packet_info, oui_mapping)

        store_results_in_db(device_dict, db_path=db_path)
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")

    logger.info("PCAP processing complete.")

