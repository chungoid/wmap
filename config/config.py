import os
from utils.init_db import initialize_db

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
    "config_dir": os.path.join(BASE_DIR, "config"),
    "pcap_file": None  # Dynamically updated during capture
}

# Default Paths
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")
DEFAULT_OUI_PATH = os.path.join(CONFIG["config_dir"], "oui_lowercase.txt")

# Web Server Settings
WEB_SERVER = {
    "host": "0.0.0.0",  # Default to all interfaces
    "port": 8080        # Default port
}

# Centralized log paths for all modules
LOG_FILES = {
    "wmap": os.path.join(CONFIG["log_dir"], "wmap.log"),
    "scapy_parser": os.path.join(CONFIG["log_dir"], "scapy_parser.log"),
    "wpa_sec": os.path.join(CONFIG["log_dir"], "wpa_sec.log"),
    "init_db": os.path.join(CONFIG["log_dir"], "init_db.log"),
    "config": os.path.join(CONFIG["log_dir"], "config.log"),
}

def ensure_directories_and_database():
    """
    Ensure necessary directories are initialized and the database is created.
    """
    try:
        print("Checking directories...")
        for key, dir_path in CONFIG.items():
            if key.endswith("_dir") and dir_path:
                os.makedirs(dir_path, exist_ok=True)
                print(f"Directory ensured: {dir_path}")

        print(f"Ensuring database at {DEFAULT_DB_PATH}...")
        initialize_db(DEFAULT_DB_PATH)
        print("Database initialization complete.")
    except Exception as e:
        print(f"Error ensuring directories and database: {e}")
