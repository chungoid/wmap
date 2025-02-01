import logging
import os
from scapy.all import rdpcap, sniff
from datetime import datetime
from scapy.fields import FlagValue
from scapy.layers.dot11 import (
    Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq,
    Dot11EltRates, Dot11ProbeResp, RadioTap
)

from config.config import DEFAULT_DB_PATH, DEFAULT_OUI_PATH, BASE_DIR
from utils import setup_work
from utils.setup_work import get_db_connection

logger = logging.getLogger("scapy_parser")
setup_work.initialize_db(DEFAULT_DB_PATH)


# Debug current working directory and file paths
print(f"Current working directory: {os.getcwd()}")
print(f"BASE_DIR: {BASE_DIR}")
print(f"DEFAULT_OUI_PATH: {DEFAULT_OUI_PATH}")
print(f"ABS PATH OUI: {os.path.abspath(DEFAULT_OUI_PATH)}")

oui_file = DEFAULT_OUI_PATH

# Check file existence
if not os.path.exists(DEFAULT_OUI_PATH):
    print(f"OUI file not found at {DEFAULT_OUI_PATH}")
else:
    print(f"OUI file found at {DEFAULT_OUI_PATH}")

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

def parse_oui_file(DEFAULT_OUI_PATH):
    """
    Parse the OUI file to create a mapping of OUI prefixes to manufacturers.

    Args:
        oui_file (str): Path to the OUI file. Defaults to DEFAULT_OUI_PATH.

    Returns:
        dict: A dictionary mapping OUI prefixes to manufacturer names.
    """

    logger.info(f"Attempting to parse OUI file at: {DEFAULT_OUI_PATH}")

    oui_mapping = {}
    try:
        with open(DEFAULT_OUI_PATH, 'r') as file:
            for line in file:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    oui = parts[0].strip().replace('-', ':').lower()
                    manufacturer = parts[1].strip().strip("'")
                    oui_mapping[oui] = manufacturer
        logger.info("OUI file parsed successfully.")
    except FileNotFoundError:
        logger.error(f"OUI file not found at {DEFAULT_OUI_PATH}. Please ensure the file exists.")
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


def parse_packet(packet, device_dict, oui_mapping):
    """
    Parse a packet and extract information about access points and clients.
    """
    try:
        if packet.haslayer(Dot11Beacon):
            logger.debug(f"Parsing Dot11Beacon layer.")
            bssid = getattr(packet[Dot11], 'addr2', None)
            if bssid:
                bssid = bssid.lower()  # Ensure lowercase
            else:
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
                'clients': []  # Initialize clients list
            }
            logger.info(f"AP added to device dict: {device_dict[bssid]}")

        elif packet.haslayer(Dot11ProbeReq):
            logger.debug(f"Parsing Dot11ProbeReq layer.")
            client_mac = getattr(packet[Dot11], 'addr2', '').lower()  # Ensure lowercase
            associated_ap = getattr(packet[Dot11], 'addr1', '').lower()  # Ensure lowercase
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

    except Exception as e:
        logger.error(f"Error parsing packet: {e}")

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

            conn.commit()
    except Exception as e:
        logger.error(f"Error storing results in the database: {e}")


def process_pcap(pcap_file):
    """
    Process a PCAP file and parse its packets.

    Args:
        pcap_file: Path to the PCAP file to process.
    """
    device_dict = {}  # Initialize the device dictionary
    oui_mapping = parse_oui_file(DEFAULT_OUI_PATH)  # Load OUI file

    try:
        packets = rdpcap(pcap_file)
        logger.info(f"Processing PCAP file: {pcap_file} with {len(packets)} packets.")

        for packet in packets:
            parse_packet(packet, device_dict, oui_mapping)

        logger.debug(f"Device dictionary after processing: {device_dict}")
        store_results_in_db(device_dict)  # Save parsed data to the database
        logger.info("PCAP processing complete.")
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")