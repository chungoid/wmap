import sqlite3
import logging
import os

from contextlib import contextmanager
from config.config import CONFIG, DEFAULT_DB_PATH

# Ensure the logs directory exists
LOG_DIR = 'logs'
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, 'setup_work.log')

# Configure logging
logger = logging.getLogger("setup_work")
logging.basicConfig(level=logging.DEBUG, filename=LOG_FILE, filemode='w',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

@contextmanager
def get_db_connection(db_path=DEFAULT_DB_PATH):
    """Context manager for SQLite database connection."""
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()

def initialize_db(db_conn):
    """Initialize the SQLite database with the required schema."""
    try:
        logger.info("Initializing database...")
        cursor = db_conn.cursor()

        # Create access_points table with frame_counts JSON column
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
            extended_capabilities TEXT,
            total_data INTEGER DEFAULT 0,
            frame_counts TEXT DEFAULT '{}'  -- Stores frame counts as JSON
        )
        """)

        logger.info("Creating clients table")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            mac TEXT PRIMARY KEY,
            ssid TEXT,
            last_seen TEXT,
            manufacturer TEXT,
            signal_strength INTEGER,
            associated_ap TEXT,
            total_data INTEGER DEFAULT 0,
            frame_counts TEXT DEFAULT '{}',  -- NEW: Stores frame counts as JSON
            FOREIGN KEY (associated_ap) REFERENCES access_points(mac)
        )
        """)

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

        logger.info("Creating settings table")
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

        with get_db_connection(DEFAULT_DB_PATH) as db_conn:
            initialize_db(db_conn)  # Pass connection, NOT path!

        logger.info("Database initialization complete.")
    except Exception as e:
        logger.error(f"Error ensuring directories and database: {e}")
        print(f"Error ensuring directories and database: {e}")

