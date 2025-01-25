import os
from tools.init_db import initialize_database

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
    "pcap_file": None,  # Dynamically updated during capture
}

# Web Server Settings
WEB_SERVER = {
    "host": "0.0.0.0",  # Default to all interfaces
    "port": 8080        # Default port
}

# Default database path
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")

# Centralized log paths for all modules
LOG_FILES = {
    "scapy_parser": os.path.join(CONFIG["log_dir"], "scapy_parser.log"),
    "tshark_parser": os.path.join(CONFIG["log_dir"], "tshark_parser.log"),
    "query_runner": os.path.join(CONFIG["log_dir"], "query_runner.log"),
    "wrapper": os.path.join(CONFIG["log_dir"], "wrapper.log"),
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
        initialize_database(DEFAULT_DB_PATH)
        print("Database initialization complete.")
    except Exception as e:
        print(f"Error ensuring directories and database: {e}")
        raise