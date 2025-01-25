import os

# USER OPTIONS
wpasec_stanev_org_key = ""  # Define your key from wpa-sec.stanev.org
HOSTADDR = "0.0.0.0"  # Default address for /web/app.py
PORT = 8080  # Default port for /web/app.py

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Configuration dictionary
CONFIG = {
    "log_dir": os.path.join(BASE_DIR, "logs"),
    "db_dir": os.path.join(BASE_DIR, "database"),
    "capture_dir": os.path.join(BASE_DIR, "capture"),
    "tools_dir": os.path.join(BASE_DIR, "tools"),
    "tests_dir": os.path.join(BASE_DIR, "tests"),
    "web_dir": os.path.join(BASE_DIR, "web"),
    "wpa_sec_key": wpasec_stanev_org_key,  # Placeholder for the user's WPA-SEC key
}

# Web Server Settings
WEB_SERVER = {
    "host": HOSTADDR,  # Default to all interfaces
    "port": PORT       # Default port
}

# Default database path
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")

# Log file paths
LOG_FILES = {
    "scapy_parser": os.path.join(CONFIG["log_dir"], "scapy_parser.log"),
    "tshark_parser": os.path.join(CONFIG["log_dir"], "tshark_parser.log"),
    "query_runner": os.path.join(CONFIG["log_dir"], "query_runner.log"),
}

def ensure_directories():
    """Create necessary directories based on CONFIG."""
    for dir_path in CONFIG.values():
        if isinstance(dir_path, str):
            os.makedirs(dir_path, exist_ok=True)