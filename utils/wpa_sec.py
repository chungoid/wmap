import os
import requests
import sqlite3

from config.config import CONFIG, DEFAULT_DB_PATH


def download_potfile(output_file, db_path=DEFAULT_DB_PATH):
    """Download the potfile from WPA-SEC."""
    key = get_wpasec_key("wpa_sec_key", db_path)
    if not key:
        print("Error: WPA-SEC key not set in the database. Use --set-key to configure it.")
        return

    url = "https://wpa-sec.stanev.org/?api&dl=1"
    headers = {"Cookie": f"key={key}"}

    try:
        print("Downloading potfile from WPA-SEC...")
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        with open(output_file, "wb") as f:
            f.write(response.content)

        print(f"Potfile downloaded successfully and saved to {output_file}.")
    except requests.RequestException as e:
        print(f"Error downloading potfile: {e}")


def upload_pcap(pcap_file, db_path=DEFAULT_DB_PATH):
    """Upload a PCAP file to WPA-SEC."""
    key = get_wpasec_key("wpa_sec_key", db_path)
    if not key:
        print("Error: WPA-SEC key not set in the database. Use --set-key to configure it.")
        return

    url = "https://wpa-sec.stanev.org/?api&upload"
    headers = {"Cookie": f"key={key}"}

    try:
        print(f"Uploading {pcap_file} to WPA-SEC...")
        with open(pcap_file, "rb") as file:
            files = {"file": file}
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
        print(f"Upload successful: {response.text}")
    except requests.RequestException as e:
        print(f"Error uploading PCAP file: {e}")


def upload_all_pcaps(db_path=DEFAULT_DB_PATH):
    """Automatically upload all PCAP files from the capture directory."""
    key = get_wpasec_key("wpa_sec_key", db_path)
    if not key:
        print("Error: WPA-SEC key not set in the database. Use --set-key to configure it.")
        return

    capture_dir = CONFIG["capture_dir"]
    for filename in os.listdir(capture_dir):
        filepath = os.path.join(capture_dir, filename)

        if filename.endswith(".uploaded"):
            print(f"Skipping already uploaded file: {filename}")
            continue

        if not filename.endswith((".pcap", ".pcapng", ".cap")):
            print(f"Skipping non-PCAP file: {filename}")
            continue

        upload_pcap(filepath, db_path)
        os.rename(filepath, f"{filepath}.uploaded")


def get_wpasec_key(key, db_path=DEFAULT_DB_PATH):
    """Retrieve a setting value from the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None


def set_wpasec_key(key, value, db_path=DEFAULT_DB_PATH):
    """Update or insert a setting in the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()
    print(f"Set {key} to {value} in the database.")

