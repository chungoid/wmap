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
    sudo python3 wmap -sk <your key>
    sudo python3 wmap -g -a wlan0 
    sudo python3 wmap -u
    sudo python3 wmap -d

usage: wmap [-h] [-a] [-p] [-g] [-e PCAPNG_FILE [NMEA_FILE ...]] [-u [UPLOAD]] [-d [DOWNLOAD]] [-sk SET_KEY] [-gk] [-nw] [interface]

Wireless capturing, parsing, and analyzing.

positional arguments:
  interface             Name of the wireless interface (required for scanning)

options:
  -h, --help            show this help message and exit
  -a, --active          Enable active scanning mode
  -p, --passive         Enable passive scanning mode
  -g, --gpsd            Enable GPS logging with hcxdumptool
  -e PCAPNG_FILE [NMEA_FILE ...], --existing PCAPNG_FILE [NMEA_FILE ...]
                        Parse an existing PCAPNG file. Optionally provide an NMEA file for GPS data.
  -u [UPLOAD], --upload [UPLOAD]
                        Upload PCAPNG(s) to WPA-SEC
  -d [DOWNLOAD], --download [DOWNLOAD]
                        Download potfile from WPA-SEC
  -sk SET_KEY, --set-key SET_KEY
                        Set the WPA-SEC API key in the database.
  -gk, --get-key        Retrieve the WPA-SEC API key from the database.
  -nw, --no-webserver   Disable web server and run CLI-only operations.

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
    hcxdumptool (GPL): Used for capturing WPA handshakes. hcxdumptool License
