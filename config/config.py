import os
import logging

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Configuration dictionary
CONFIG = {
    "log_dir": os.path.join(BASE_DIR, "logs"),
    "db_dir": os.path.join(BASE_DIR, "database"),
    "capture_dir": os.path.join(BASE_DIR, "capture"),
    "web_dir": os.path.join(BASE_DIR, "web"),
    "config_dir": os.path.join(BASE_DIR, "config"),
    "pcap_file": "wmap.pcapng",
}

# Insert in CONFIG dictionary above if you want
#"tests_dir": os.path.join(BASE_DIR, "tests")

# Default Paths
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")
DEFAULT_OUI_PATH = os.path.abspath(os.path.join(CONFIG["config_dir"], "oui_lowercase.txt"))

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
    "setup_work": os.path.join(CONFIG["log_dir"], "setup_work.log"),
}


def setup_logging():
    for logger_name, log_file in LOG_FILES.items():
        logger = logging.getLogger(logger_name)
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)