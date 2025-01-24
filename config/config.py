import os

# Base project directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Default directories
CONFIG = {
    "log_dir": os.path.join(BASE_DIR, "logs"),
    "db_dir": os.path.join(BASE_DIR, "database"),
    "capture_dir": os.path.join(BASE_DIR, "capture"),
    "tools_dir": os.path.join(BASE_DIR, "tools"),
    "tests_dir": os.path.join(BASE_DIR, "tests"),
    "web_dir": os.path.join(BASE_DIR, "web"),
}

# Default database file
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")

# Default log file paths
LOG_FILES = {
    "scapy_parser": os.path.join(CONFIG["log_dir"], "scapy_parser.log"),
    "tshark_parser": os.path.join(CONFIG["log_dir"], "tshark_parser.log"),
    "query_runner": os.path.join(CONFIG["log_dir"], "query_runner.log"),
}

# Ensure all directories exist
def ensure_directories():
    for dir_path in CONFIG.values():
        os.makedirs(dir_path, exist_ok=True)