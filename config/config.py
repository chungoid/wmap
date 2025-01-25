import os

# USER OPTIONS
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
    "web_dir": os.path.join(BASE_DIR, "web"),
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

def ensure_directories_and_database():
    """Ensure necessary directories and the database are initialized."""
    missing_dirs = []

    # Check and create directories
    for key, dir_path in CONFIG.items():
        if dir_path.strip():  # Ensure valid paths
            if not os.path.exists(dir_path):
                missing_dirs.append(dir_path)
                os.makedirs(dir_path, exist_ok=True)

    # Print a single message
    if missing_dirs:
        print(f"Initialized missing directories: {', '.join(missing_dirs)}")
    else:
        print("All required directories are already initialized.")

    # Ensure database is initialized
    db_path = DEFAULT_DB_PATH
    if not os.path.exists(db_path):
        from tools.init_db import initialize_database
        print("Initializing database...")
        initialize_database(db_path)
        print(f"Database initialized at: {db_path}")
    else:
        print("Database is already initialized.")