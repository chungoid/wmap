import sqlite3
import logging
import os
from config.config import CONFIG, DEFAULT_DB_PATH

# Configure logging
logger = logging.getLogger("init_db")


def initialize_db(db_path):
    """Initialize the SQLite database with the required schema."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create access_points table
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
        logging.info("Created table: access_points")

        # Create clients table
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
        logging.info("Created table: clients")

        # Create wpa_sec_results table
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
        logging.info("Created table: wpa_sec_results")

        # Create settings table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)
        logging.info("Created table: settings")

        conn.commit()
        logging.info("Database initialized successfully.")
    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
    finally:
        if conn:
            conn.close()

def ensure_directories_and_database():
    """
    Ensure necessary directories are initialized and the database is created.
    """
    try:
        logging.info("Checking directories...")
        for key, dir_path in CONFIG.items():
            if key.endswith("_dir") and dir_path:
                os.makedirs(dir_path, exist_ok=True)
                logging.info(f"Directory ensured: {dir_path}")

        logging.info(f"Ensuring database at {DEFAULT_DB_PATH}...")
        initialize_db(DEFAULT_DB_PATH)
        logging.info("Database initialization complete.")
    except Exception as e:
        logging.error(f"Error ensuring directories and database: {e}")
        print(f"Error ensuring directories and database: {e}")


