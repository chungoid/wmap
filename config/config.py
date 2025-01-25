import os

# define your key from wpa-sec.stanev.org
wpasec_stanev_org_key = ""

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
        if isinstance(dir_path, str) and os.path.isdir(os.path.dirname(dir_path)):
            os.makedirs(dir_path, exist_ok=True)