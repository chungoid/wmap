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

    Parses captured data using Scapy.
    Stores parsed data in a SQLite database for further analysis.
    Uploads and downloads data with WPA-SEC integration.
    Extensible YAML-configured SQL queries in wmap/config/queries.yaml.
    Flask-based web server for interactive query visualization.

## License

This project is licensed under the GNU General Public License v2 (GPL v2). See the LICENSE file for details.