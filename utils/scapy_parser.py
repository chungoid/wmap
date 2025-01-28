import sqlite3
from scapy.all import *
from datetime import datetime
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Auth, Dot11Elt, Dot11ProbeReq, Dot11AssoReq, Dot11EltRates, \
    Dot11ProbeResp, RadioTap

from config.config import DEFAULT_DB_PATH, DEFAULT_OUI_PATH, LOG_FILES, setup_logging

logger = logging.getLogger("scapy_parser")

def parse_flag_value(value):
    try:
        if isinstance(value, FlagValue):
            return int(value)
        return value
    except Exception as e:
        logging.error(f"Failed to parse FlagValue: {e}")
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
    oui_mapping = {}
    try:
        with open(DEFAULT_OUI_PATH, 'r') as file:
            for line in file:
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    oui = parts[0].strip().replace('-', ':').lower()
                    manufacturer = parts[1].strip().strip("'")
                    oui_mapping[oui] = manufacturer
    except Exception as e:
        logging.error(f"Error parsing OUI file: {e}")
    return oui_mapping


def get_manufacturer(mac, oui_mapping):
    oui_prefix = mac[:8].lower()
    return oui_mapping.get(oui_prefix, 'Unknown')


# Decoding functions for capabilities fields
def decode_extended_capabilities(data):
    if not data:
        return "No Extended Capabilities"
    capabilities = int(data, 16)
    features = []
    if capabilities & (1 << 0):
        features.append("Extended Channel Switching")
    if capabilities & (1 << 1):
        features.append("WNM Sleep Mode")
    if capabilities & (1 << 2):
        features.append("TIM Broadcast")
    # Add more features based on the IEEE 802.11 standard
    return ", ".join(features) if features else "No Extended Capabilities"


def decode_ht_capabilities(data):
    if not data:
        return "No HT Capabilities"
    capabilities = bytes.fromhex(data)
    features = []
    if capabilities[0] & (1 << 0):
        features.append("LDPC Coding Capability")
    if capabilities[1] & (1 << 1):
        features.append("Channel Width 40 MHz")
    if capabilities[1] & (1 << 2):
        features.append("Greenfield Mode")
    # Add more features based on the IEEE 802.11n standard
    return ", ".join(features) if features else "No HT Capabilities"


def decode_vht_capabilities(data):
    if not data:
        return "No VHT Capabilities"
    capabilities = bytes.fromhex(data)
    features = []
    if capabilities[0] & (1 << 0):
        features.append("Max MPDU Length")
    if capabilities[1] & (1 << 2):
        features.append("Supported Channel Width")
    if capabilities[2] & (1 << 0):
        features.append("Rx LDPC")
    # Add more features based on the IEEE 802.11ac standard
    return ", ".join(features) if features else "No VHT Capabilities"


def parse_packet(packet_id):
    packet_info = {}
    try:
        # Radiotap Layer
        if packet_id.haslayer(RadioTap):
            packet_info['RadioTap'] = {field: convert_to_serializable(getattr(packet_id[RadioTap], field))
                                       for field in packet_id[RadioTap].fields}

        # 802.11 (WiFi) Layer
        if packet_id.haslayer(Dot11):
            packet_info['Dot11'] = {field: convert_to_serializable(getattr(packet_id[Dot11], field))
                                    for field in packet_id[Dot11].fields}

        # 802.11 Beacon Layer (AP)
        if packet_id.haslayer(Dot11Beacon):
            bssid = packet_id[Dot11].addr2.upper()
            essid = packet_id[Dot11Elt].info.decode() if packet_id.haslayer(Dot11Elt) else ''
            try:
                dbm_signal = packet_id.dBm_AntSignal
            except:
                dbm_signal = None
            stats = packet_id[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            crypto = stats.get("crypto")
            timestamp = packet_id[Dot11Beacon].timestamp
            lastseen = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            extended_capabilities = bytes_to_hex_string(getattr(packet_id.getlayer(Dot11Elt, ID=127), 'info', None))
            ht_capabilities = bytes_to_hex_string(getattr(packet_id.getlayer(Dot11Elt, ID=45), 'info', None))
            vht_capabilities = bytes_to_hex_string(getattr(packet_id.getlayer(Dot11Elt, ID=191), 'info', None))

            packet_info['Dot11Beacon'] = {
                'bssid': bssid,
                'essid': essid,
                'dbm_signal': dbm_signal,
                'channel': channel,
                'crypto': crypto,
                'timestamp': timestamp,
                'lastseen': lastseen,
                'extended_capabilities': decode_extended_capabilities(extended_capabilities),
                'ht_capabilities': decode_ht_capabilities(ht_capabilities),
                'vht_capabilities': decode_vht_capabilities(vht_capabilities)
            }

            packet_info['Signal_strength'] = dbm_signal
            packet_info['Channel'] = channel
            packet_info['Rates'] = packet_id[Dot11EltRates].rates if packet_id.haslayer(Dot11EltRates) else None
            packet_info['Extended_Capabilities'] = decode_extended_capabilities(extended_capabilities)
            packet_info['HT_Capabilities'] = decode_ht_capabilities(ht_capabilities)
            packet_info['VHT_Capabilities'] = decode_vht_capabilities(vht_capabilities)

            packet_info['type'] = 'AP'

        # 802.11 Probe Request Layer (Client)
        if packet_id.haslayer(Dot11ProbeReq):
            packet_info['Dot11ProbeReq'] = {
                'info': convert_to_serializable(packet_id[Dot11ProbeReq].info)
            }
            packet_info['type'] = 'Client'

        # 802.11 Probe Response Layer (AP)
        if packet_id.haslayer(Dot11ProbeResp):
            packet_info['Dot11ProbeResp'] = {
                'timestamp': packet_id[Dot11ProbeResp].timestamp,
                'beacon_interval': packet_id[Dot11ProbeResp].beacon_interval,
                'cap': parse_flag_value(packet_id[Dot11ProbeResp].cap)
            }
            packet_info['type'] = 'AP'

        # 802.11 Authentication Layer
        if packet_id.haslayer(Dot11Auth):
            packet_info['Dot11Auth'] = {field: convert_to_serializable(getattr(packet_id[Dot11Auth], field))
                                        for field in packet_id[Dot11Auth].fields}

        # 802.11 Association Request Layer
        if packet_id.haslayer(Dot11AssoReq):
            packet_info['Dot11AssoReq'] = {field: convert_to_serializable(getattr(packet_id[Dot11AssoReq], field))
                                           for field in packet_id[Dot11AssoReq].fields}
            packet_info['type'] = 'Client'

        # Update type based on new information
        if 'type' not in packet_info:
            if packet_id.haslayer(Dot11Beacon) or packet_id.haslayer(Dot11ProbeResp):
                packet_info['type'] = 'AP'
            elif packet_id.haslayer(Dot11ProbeReq) or packet_id.haslayer(Dot11AssoReq):
                packet_info['type'] = 'Client'
    except Exception as e:
        logging.error(f"Error parsing packet: {e}")

    return packet_info


def update_device_dict(device_dict, packet_info, oui_mapping):
    mac = packet_info['Dot11'].get('addr2', '').upper()
    ssid = packet_info.get('Dot11Beacon', {}).get('essid', '') or \
           packet_info.get('Dot11ProbeReq', {}).get('info', '')
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    manufacturer = get_manufacturer(mac, oui_mapping)

    if packet_info.get('type') == 'AP':
        encryption = packet_info.get('Dot11Beacon', {}).get('crypto', 'Unknown')
        if mac not in device_dict:
            device_dict[mac] = {
                'mac': mac,
                'ssid': ssid,
                'encryption': encryption,
                'last_seen': timestamp,
                'manufacturer': manufacturer,
                'signal_strength': packet_info.get('Signal_strength'),
                'channel': packet_info.get('Channel'),
                'rates': packet_info.get('Rates'),
                'extended_capabilities': packet_info.get('Extended_Capabilities'),
                'ht_capabilities': packet_info.get('HT_Capabilities'),
                'vht_capabilities': packet_info.get('VHT_Capabilities'),
                'clients': []
            }
        else:
            device_dict[mac]['last_seen'] = timestamp
            device_dict[mac]['signal_strength'] = packet_info.get('Signal_strength')
            device_dict[mac]['channel'] = packet_info.get('Channel')
            device_dict[mac]['rates'] = packet_info.get('Rates')
            device_dict[mac]['extended_capabilities'] = packet_info.get('Extended_Capabilities')
            device_dict[mac]['ht_capabilities'] = packet_info.get('HT_Capabilities')
            device_dict[mac]['vht_capabilities'] = packet_info.get('VHT_Capabilities')
    elif packet_info.get('type') == 'Client':
        ap_mac = packet_info['Dot11'].get('addr1', '').upper()
        client_info = {
            'mac': mac,
            'ssid': ssid,
            'last_seen': timestamp,
            'manufacturer': manufacturer,
            'signal_strength': packet_info.get('Signal_strength')
        }
        if not client_info['ssid']:
            if ap_mac in device_dict:
                ap_ssid = device_dict[ap_mac].get('ssid', '')
                client_info['ssid'] = ap_ssid if ap_ssid else ap_mac
            else:
                client_info['ssid'] = ap_mac

        if ap_mac in device_dict:
            device_dict[ap_mac]['clients'].append(client_info)
        else:
            device_dict[mac] = client_info


def store_results_in_db(device_dict):
    """Store the device dictionary results in the SQLite database."""
    conn = None
    try:
        conn = sqlite3.connect(DEFAULT_DB_PATH)
        cursor = conn.cursor()

        for ap_mac, ap_info in device_dict.items():
            if ap_info.get('device_type') == 'AP':
                cursor.execute("""
                INSERT OR REPLACE INTO devices (mac, ssid, encryption, device_type, last_seen, manufacturer, signal_strength, channel, rates, extended_capabilities, ht_capabilities, vht_capabilities)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ap_info['mac'], ap_info['ssid'], ap_info['encryption'], 'AP', ap_info['last_seen'],
                    ap_info['manufacturer'],
                    ap_info['signal_strength'], ap_info['channel'], json.dumps(ap_info['rates']),
                    ap_info['extended_capabilities'],
                    ap_info['ht_capabilities'], ap_info['vht_capabilities']
                ))
                for client in ap_info['clients']:
                    cursor.execute("""
                    INSERT INTO clients (mac, ssid, last_seen, manufacturer, signal_strength, associated_ap)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        client['mac'], client['ssid'], client['last_seen'], client['manufacturer'],
                        client['signal_strength'], ap_mac
                    ))

        conn.commit()
        logging.info("Results stored in the database successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error storing results in the database: {e}")
    finally:
        if conn:
            conn.close()


def live_scan(interface):
    """Perform live scan, parsing packets continually and updating the database."""
    device_dict = {}
    oui_mapping = parse_oui_file()

    def packet_handler(packet_id):
        packet_info = parse_packet(packet_id)
        if packet_info:
            update_device_dict(device_dict, packet_info, oui_mapping)
            store_results_in_db(device_dict)

    sniff(iface=interface, prn=packet_handler, store=0)