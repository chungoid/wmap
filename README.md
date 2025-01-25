# WMAP: Wi-Fi Monitoring and Analysis Platform

WMAP is a modular tool for capturing, parsing, and analyzing Wi-Fi traffic, with support for WPA-SEC integration and live traffic monitoring.

## Installation

### Clone the Repository:

```bash
git clone https://github.com/your-repo/wmap.git
cd wmap
```
### Install Dependencies:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configuration

Edit the config/config.py file to set up default directories and configure your WPA-SEC key:
```
wpasec_stanev_org_key = "your_wpa_sec_key"  # Set your optional WPA-SEC key here
```
The default directory structure is defined in the CONFIG dictionary and can be customized.

Usage
```
usage: wmap.py [-h] [-t {hcxdumptool,tshark,airodump-ng,tcpdump,dumpcap}] [-o OUTPUT] [--parser {scapy,tshark}] [--args ...] [-u [UPLOAD]] [-d [DOWNLOAD]]
               [--set-key SET_KEY] [--no-webserver]
               [interface]

Wi-Fi packet capture and parsing tool.

positional arguments:
  interface             Wireless interface to use (e.g., wlan0mon).

options:
  -h, --help            show this help message and exit
  -t {hcxdumptool,tshark,airodump-ng,tcpdump,dumpcap}, --tool {hcxdumptool,tshark,airodump-ng,tcpdump,dumpcap}
                        Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).
  -o OUTPUT, --output OUTPUT
                        Output file or directory for the capture (if required).
  --parser {scapy,tshark}
                        Parser to use for processing the capture (default: scapy).
  --args ...            Additional arguments for the capture tool.
  -u [UPLOAD], --upload [UPLOAD]
                        Upload a specific PCAP file or all unmarked files in the capture directory.
  -d [DOWNLOAD], --download [DOWNLOAD]
                        Download potfile from WPA-SEC (default path if no path provided).
  --set-key SET_KEY     Set the WPA-SEC key in the database.
  --no-webserver        Disable web server and run CLI-only operations.

```

Customize Database Queries

Queries are defined in config/queries.yaml and can be customized or extended. Example:
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
Features

    Supports multiple capture tools: hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap.
    Parses captured data using Scapy (default) or TShark.
    Stores parsed data in a SQLite database for further analysis.
    Uploads and downloads data with WPA-SEC integration.
    Modular and extensible architecture with YAML-configured SQL queries.
    Flask-based web server for interactive query visualization.

Directory Structure

    config/: Configuration files for the project.
    database/: Contains the SQLite database for parsed data.
    capture/: Stores captured PCAP files.
    logs/: Logs for various components.
    tools/: Scripts for database initialization and parsing.
    utils/: Utility modules for handling captures, parsing, and WPA-SEC integration.
    web/: Flask-based web application for viewing and querying data.

License

This project is licensed under the MIT License. See the LICENSE file for details.
Attribution

This project makes use of the following third-party tools and libraries:

    Scapy (BSD License): Used for parsing network traffic. Scapy License
    TShark (LGPL): Used as an optional parser and capture tool. Wireshark License
    hcxdumptool (GPL): Used for capturing WPA handshakes. hcxdumptool License
    Aircrack-ng Suite (GPL): Includes airodump-ng for packet capture. Aircrack License