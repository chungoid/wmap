import os
import logging
from logging.handlers import RotatingFileHandler


# Base directory of the project
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Configuration dictionary
CONFIG = {
    "log_dir": os.path.join(BASE_DIR, "logs"),
    "db_dir": os.path.join(BASE_DIR, "database"),
    "capture_dir": os.path.join(BASE_DIR, "capture"),
    "web_dir": os.path.join(BASE_DIR, "web"),
    "config_dir": os.path.join(BASE_DIR, "config"),
#    "test_dir": os.path.join(BASE_DIR, "tests"),
}

# Default Paths
DEFAULT_DB_PATH = os.path.join(CONFIG["db_dir"], "wmap.db")
DEFAULT_OUI_PATH = os.path.join(CONFIG["config_dir"], "oui_lowercase.txt")
DEFAULT_QUERIES_PATH = os.path.join(CONFIG["config_dir"], "queries.yaml")


# Centralized log paths for all modules
LOG_FILES = {
    "wmap": os.path.join(CONFIG["log_dir"], "wmap.log"),
#    "test": os.path.join(CONFIG["log_dir"], "test.log")
}


# Web Server Settings
WEB_SERVER = {
    "host": "0.0.0.0",  # Default to all interfaces
    "port": 8080        # Default port
}


def setup_logging():
    """Configure logging for all modules and fix log directory ownership."""

    # Ensure the log directory exists
    if not os.path.exists(CONFIG["log_dir"]):
        os.makedirs(CONFIG["log_dir"], exist_ok=True)

    for logger_name, log_file in LOG_FILES.items():
        logger = logging.getLogger(logger_name)

        # Prevent adding duplicate handlers
        if not logger.hasHandlers():
            handler = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=3)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.DEBUG)




