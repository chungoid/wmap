import sqlite3

def initialize_database(dbpath):
    """Initialize the SQLite database with the required schema."""
    conn = sqlite3.connect(dbpath)
    cursor = conn.cursor()

    # Main Packets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_sec INTEGER,
        ts_usec INTEGER,
        phyname TEXT,
        source_mac TEXT,
        dest_mac TEXT,
        trans_mac TEXT,
        freq INTEGER,
        channel INTEGER,
        packet_len INTEGER,
        signal INTEGER,
        datasource TEXT,
        dlt TEXT,
        error TEXT,
        tags TEXT,
        datarate REAL,
        hash TEXT
    );
    """)

    # Beacons Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS beacons (
        id INTEGER PRIMARY KEY,
        ssid TEXT,
        encryption TEXT,
        capabilities TEXT,
        beacon_interval INTEGER,
        FOREIGN KEY (id) REFERENCES packets(id)
    );
    """)

    # Probes Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY,
        ssid TEXT,
        is_response BOOLEAN,
        FOREIGN KEY (id) REFERENCES packets(id)
    );
    """)

    # Deauthentication Frames Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS deauth_frames (
        id INTEGER PRIMARY KEY,
        reason_code INTEGER,
        FOREIGN KEY (id) REFERENCES packets(id)
    );
    """)

    # Data Frames Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS data_frames (
        id INTEGER PRIMARY KEY,
        payload BLOB,
        FOREIGN KEY (id) REFERENCES packets(id)
    );
    """)

    # WPA-SEC Results Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS wpa_sec_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        source_mac TEXT,
        ssid TEXT,
        password TEXT,
        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(bssid, ssid) ON CONFLICT REPLACE
    );
    """)

    conn.commit()
    conn.close()
    print(f"Database initialized successfully at '{dbpath}'.")