# WMAP: Wi-Fi Monitoring and Analysis Platform

WMAP is a modular tool for capturing, parsing, and analyzing Wi-Fi traffic, with support for WPA-SEC integration and live traffic monitoring.

## Installation

### Clone the Repository:

```bash
git clone https://github.com/your-repo/wmap.git
cd wmap

Install Dependencies:

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

Configuration

Edit the config/config.py file to set up default directories and configure your WPA-SEC key:

wpasec_stanev_org_key = "your_wpa_sec_key"  # Set your optional WPA-SEC key here

The default directory structure is defined in the CONFIG dictionary and can be customized.
Usage
Capture Packets and Parse:

./wmap.py wlan0 -t hcxdumptool -o capture.pcap --parser scapy

WPA-SEC Integration:
Upload Captures:

    Upload all unmarked captures in the default capture directory:

./wmap.py -u

Upload a specific capture file:

    ./wmap.py -u /path/to/capture.pcap

Download Potfile:

    Download WPA-SEC potfile to the default capture directory:

./wmap.py -d

Specify a custom download location:

    ./wmap.py -d /path/to/save/potfile.pot

Manage WPA-SEC Key:

    Set the WPA-SEC key:

    ./wmap.py --set-key your_key_here

Run Web Server:

Launch the web server to view and query data:

./wmap.py

Disable the web server for CLI-only operations:

./wmap.py --no-webserver

Customize Database Queries

Queries are defined in config/queries.yaml and can be customized or extended. Example:

- id: "20"
  description: "Open Networks with High Traffic"
  query: >
    SELECT ssid, source_mac AS ap_mac, COUNT(*) AS packet_count
    FROM beacons
    JOIN packets ON beacons.id = packets.id
    WHERE encryption IS NULL OR encryption = 'Open'
    GROUP BY ssid, source_mac
    ORDER BY packet_count DESC;

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