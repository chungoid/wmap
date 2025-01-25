# WMAP: Wi-Fi Monitoring and Analysis Platform

WMAP is a modular tool for capturing, parsing, and analyzing Wireless Traffic.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/wmap.git
   cd wmap
   ```

2. **Install Dependencies:**: 
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt 
   ```

## Configuration

Edit the config/config.py file to set up default directories and your WPA-SEC key:
```
wpasec_stanev_org_key = "your_wpa_sec_key" # optional value
```

## Usage
Capture Packets and Parse

To capture packets and parse them into the database:
```
./wmap.py wlan0 -t hcxdumptool -o capture.pcap --parser scapy
```

WPA-SEC Integration & Capture File Handling:
```
./wmap.py -u # upload all captures (default: wmap/capture/)

./wmap.py -u /path/to/capture.pcap 

./wmap .py -d # download wpa-sec (default: wmap/capture/)

./wmap.py -d /path/to/save/potfile.pot 
```

Customize Database Queries via queries.yaml in /config/
```
  - id: "20"
    description: "Open Networks with High Traffic"
    query: >
      SELECT ssid, source_mac AS ap_mac, COUNT(*) AS packet_count
      FROM beacons
      JOIN packets ON beacons.id = packets.id
      WHERE encryption IS NULL OR encryption = 'Open'
      GROUP BY ssid, source_mac
      ORDER BY packet_count DESC;
```

## Features
```
    Supports multiple capture tools: hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap.
    Parses captured data using Scapy (default) or TShark.
    Stores parsed data using a SQLite database.
    Uploads and downloads data with WPA-SEC integration.
    Modular and extensible SQLite queries maintained in wmap/config/queries.yaml
````
## Directory Structure

    config/: Configuration files for the project.
    database/: Contains the SQLite database for parsed data.
    capture/: Stores captured PCAP files.
    logs/: Logs for various components.
    tools/: Scripts for database initialization and parsing.
    utils/: Utility modules for handling captures, parsing, and WPA-SEC integration.

License

This project is licensed under the MIT License. See the LICENSE file for details.

## Attribution

This project makes use of the following third-party tools and libraries:

- **Scapy** (BSD License): Used for parsing network traffic. [Scapy License](https://github.com/secdev/scapy/blob/master/LICENSE)
- **TShark** (LGPL): Used as an optional parser and capture tool. [Wireshark License](https://www.wireshark.org/docs/wsug_html_chunked/ChIntroLegal.html)
- **hcxdumptool** (GPL): Used for capturing WPA handshakes. [hcxdumptool License](https://github.com/ZerBea/hcxdumptool/blob/master/LICENSE)
- **aircrack-ng suite** (GPL): Includes `airodump-ng` for packet capture. [Aircrack License](https://github.com/aircrack-ng/aircrack-ng/blob/master/LICENSE)