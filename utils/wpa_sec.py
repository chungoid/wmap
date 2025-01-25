import os
import requests
from config.config import CONFIG


def download_potfile(output_file):
    """Download the potfile from WPA-SEC."""
    key = CONFIG.get("wpa_sec_key")
    if not key:
        print("Error: WPA-SEC key not configured in config.py.")
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


def upload_pcap(pcap_file):
    """Upload a PCAP file to WPA-SEC."""
    key = CONFIG.get("wpa_sec_key")
    if not key:
        print("Error: WPA-SEC key not configured in config.py.")
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


def upload_all_pcaps():
    """Automatically upload all PCAP files from the capture directory."""
    key = CONFIG.get("wpa_sec_key")
    if not key:
        print("Error: WPA-SEC key not configured in config.py.")
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

        upload_pcap(filepath)
        os.rename(filepath, f"{filepath}.uploaded")
