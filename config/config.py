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

# Log file paths
LOG_FILES = {
    "scapy_parser": os.path.join(CONFIG["log_dir"], "scapy_parser.log"),
    "tshark_parser": os.path.join(CONFIG["log_dir"], "tshark_parser.log"),
    "query_runner": os.path.join(CONFIG["log_dir"], "query_runner.log"),
    "wrapper": os.path.join(CONFIG["log_dir"], "wrapper.log"),
}


def ensure_directories_and_database():
    """
    Ensure necessary directories exist and initialize the database.
    """
    # Ensure directories
    for key, dir_path in CONFIG.items():
        if isinstance(dir_path, str) and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)
            print(f"Created missing directory: {dir_path}")

    # Initialize database
    db_path = CONFIG.get("db_dir", "") + "/wmap.db"
    if os.path.exists(db_path):
        print("Database is already initialized.")
    else:
        print("Initializing database...")
        initialize_database(db_path)