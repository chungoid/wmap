# WMAP: Wi-Fi Monitoring & Analysis Platform

Supports capturing, parsing, storing, and analyzing live or previously captured Wi-Fi traffic.

## Installation

### Clone the Repository:

```bash
git clone https://github.com/chungoid/wmap.git
cd wmap
```
### Install Dependencies:
```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage
```
example:
    ./wmap.py --set-key <your key>
    sudo ./wmap.py --active wlan0
    ./wmap.py --upload 
    ./wmap.py --download

python wmap.py [-h] [--active] [--passive] [-u [UPLOAD]] [-d [DOWNLOAD]] [--set-key SET_KEY] [--get-key] [--no-webserver] [--parse-existing PARSE_EXISTING] [interface]

Wireless capturing, parsing, and analyzing.

positional arguments:
  interface             Name of the wireless interface (optional if parsing existing file)

options:
  -h, --help            show this help message and exit
  --active              Enable active scanning mode
  --passive             Enable passive scanning mode
  -u [UPLOAD], --upload [UPLOAD]
                        Upload a specific PCAP file or all unmarked files in the capture directory.
  -d [DOWNLOAD], --download [DOWNLOAD]
                        Download potfile from WPA-SEC (default path if no path provided).
  --set-key SET_KEY     Set the WPA-SEC key in the database.
  --get-key             Get the WPA-SEC key from the database.
  --no-webserver        Disable web server and run CLI-only operations.
  --parse-existing PARSE_EXISTING
                        Parse an existing capture file (e.g., /path/to/file.pcap).
```

## Customize Database Queries

Queries are defined in config/queries.yaml and can be customized or extended. Example:
```
  - id: "10"
    description: "Count of Clients Associated with Each Access Point"
    query: >
      SELECT devices.mac AS ap_mac, devices.ssid, COUNT(clients.mac) AS client_count
      FROM devices
      LEFT JOIN clients ON devices.mac = clients.associated_ap
      WHERE devices.device_type = 'AP'
      GROUP BY devices.mac, devices.ssid
      ORDER BY client_count DESC;
```
## Features

    Parses captured data using Scapy (default).
    Stores parsed data in a SQLite database for further analysis.
    Uploads and downloads data with WPA-SEC integration.
    Extensible YAML-configured SQL queries in wmap/config/queries.yaml.
    Flask-based web server for interactive query visualization.

## Directory Structure

    config/: Configuration files for the project.
    database/: Contains the SQLite database for parsed data.
    capture/: Stores captured PCAP files.
    logs/: Logs for various components.
    utils/: Utility modules for handling captures, parsing, and WPA-SEC integration.
    web/: Flask-based web application for viewing and querying data.

## License

This project is licensed under the MIT License. See the LICENSE file for details.
Attribution

This project makes use of the following third-party tools and libraries:

    Scapy (BSD License): Used for parsing network traffic. Scapy License
    TShark (LGPL): Used as an optional parser and capture tool. Wireshark License
    hcxdumptool (GPL): Used for capturing WPA handshakes. hcxdumptool License
    Aircrack-ng Suite (GPL): Includes airodump-ng for packet capture. Aircrack License