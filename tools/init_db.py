import sqlite3
import logging
import os
from config.config import CONFIG

# Configure logging
log_file = os.path.join(CONFIG['log_dir'], "init_db.log")
logging.basicConfig(filename=log_file, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def initialize_db(db_path):
    """Initialize the SQLite database with the required schema."""
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create devices table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
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
        logging.info("Created table: devices")

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
            FOREIGN KEY (associated_ap) REFERENCES devices(mac)
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
