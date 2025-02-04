import sqlite3
import logging
import os
from contextlib import contextmanager

from config.config import CONFIG, DEFAULT_DB_PATH
from utils.helpers import fix_permissions


logger = logging.getLogger("wmap")

@contextmanager
def get_db_connection(db_path=DEFAULT_DB_PATH):
    """Context manager for SQLite database connection."""
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

def initialize_db(db_conn):
    """Initialize the SQLite database with the required schema, ensuring GPS support."""

    try:
        logger.info("Initializing database...")
        cursor = db_conn.cursor()

        # Create access_points table
        logger.info("Creating or updating access_points table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_points (
            mac TEXT PRIMARY KEY,
            ssid TEXT,
            encryption TEXT,
            last_seen TEXT,
            manufacturer TEXT,
            signal_strength INTEGER,
            channel INTEGER,
            extended_capabilities TEXT,
            total_data INTEGER DEFAULT 0,
            frame_counts TEXT DEFAULT '{}',
            latitude REAL DEFAULT NULL,
            longitude REAL DEFAULT NULL
        )
        """)

        # Create clients table
        logger.info("Creating or updating clients table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            mac TEXT PRIMARY KEY,
            ssid TEXT,
            last_seen TEXT,
            manufacturer TEXT,
            signal_strength INTEGER,
            associated_ap TEXT,
            total_data INTEGER DEFAULT 0,
            frame_counts TEXT DEFAULT '{}',
            latitude REAL DEFAULT NULL,
            longitude REAL DEFAULT NULL,
            FOREIGN KEY (associated_ap) REFERENCES access_points(mac)
        )
        """)

        # Create WPA security results table
        logger.info("Creating or updating wpa_sec_results table")
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

        # Create settings table
        logger.info("Creating or updating settings table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """)

        db_conn.commit()
        logger.info("Database initialized successfully.")

    except sqlite3.Error as e:
        logger.error(f"Error initializing database: {e}")


def ensure_directories_and_database():
    """Ensure necessary directories are initialized and fix permissions immediately."""
    try:
        created_dirs = []  # Track newly created directories

        for key, dir_path in CONFIG.items():
            if key.endswith("_dir") and dir_path:
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                    created_dirs.append(dir_path)  # Track newly created directories

        for dir_path in created_dirs:
            logger.debug("Directory '{}' created.".format(dir_path))

        with get_db_connection(DEFAULT_DB_PATH) as db_conn:
            initialize_db(db_conn)

        try:
            fix_permissions(created_dirs)
        except Exception as e:
            logger.warning(f"Error fixing permissions: {e}")

    except Exception as e:
        logger.warning(f"Error ensuring directories and database: {e}")







