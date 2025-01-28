import sqlite3
import logging
import os
from config.config import CONFIG, DEFAULT_DB_PATH

# Ensure the logs directory exists
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'setup_work.log')

# Configure logging
logger = logging.getLogger("setup_work")
logging.basicConfig(level=logging.DEBUG, filename=LOG_FILE, filemode='w',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

def initialize_db(db_path):
    """Initialize the SQLite database with the required schema."""
    conn = None
    try:
        logger.info(f"Initializing database at {db_path}...")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create access_points table
        logger.info("Creating access_points table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_points (
            mac TEXT PRIMARY KEY,
            ssid TEXT,
            encryption TEXT,
            device_type TEXT,
            last_seen TEXT,
            manufacturer TEXT,
            signal_strength INTEGER,
            channel INTEGER,
            rates TEXT,
            extended_capabilities TEXT,
            ht_capabilities TEXT,
            vht_capabilities TEXT
        )
        """)
        logger.info("Created table: access_points")

        # Create clients table
        logger.info("Creating clients table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            ssid TEXT,
            last_seen TEXT,
            manufacturer TEXT,
            signal_strength INTEGER,
            associated_ap TEXT,
            FOREIGN KEY (associated_ap) REFERENCES access_points(mac)
        )
        """)
        logger.info("Created table: clients")

        # Create wpa_sec_results table
        logger.info("Creating wpa_sec_results table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS wpa_sec_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT NOT NULL,
            source_mac TEXT,
            ssid TEXT,
            password TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(bssid, ssid) ON CONFLICT REPLACE
        )
        """)
        logger.info("Created table: wpa_sec_results")

        # Create settings table
        logger.info("Creating settings table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)
        logger.info("Created table: settings")

        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def ensure_directories_and_database():
    """
    Ensure necessary directories are initialized and the database is created.
    """
    try:
        logger.info("Checking directories...")
        for key, dir_path in CONFIG.items():
            if key.endswith("_dir") and dir_path:
                os.makedirs(dir_path, exist_ok=True)
                logger.info(f"Directory ensured: {dir_path}")

        logger.info(f"Ensuring database at {DEFAULT_DB_PATH}...")
        initialize_db(DEFAULT_DB_PATH)
        logger.info("Database initialization complete.")
    except Exception as e:
        logger.error(f"Error ensuring directories and database: {e}")
        print(f"Error ensuring directories and database: {e}")