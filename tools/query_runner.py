import sqlite3
import argparse
import json
import os

def execute_query(cursor, query, description):
    """Helper function to execute a query and return results."""
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return {"description": description, "results": results}
    except sqlite3.Error as e:
        return {"description": description, "error": str(e)}

def list_queries():
    """Return a dictionary of all queries."""
    return {
        "1": {
            "description": "List All Unique SSIDs",
            "query": "SELECT DISTINCT ssid FROM beacons;"
        },
        "2": {
            "description": "List All Devices",
            "query": """
                SELECT DISTINCT source_mac FROM packets
                UNION
                SELECT DISTINCT dest_mac FROM packets
                WHERE source_mac IS NOT NULL OR dest_mac IS NOT NULL;
            """
        },
        "3": {
            "description": "Count Total Packets Captured",
            "query": "SELECT COUNT(*) AS total_packets FROM packets;"
        },
        "4": {
            "description": "List All Access Points",
            "query": """
                SELECT DISTINCT source_mac AS ap_mac, ssid, encryption
                FROM beacons
                JOIN packets ON beacons.id = packets.id;
            """
        },
        "5": {
            "description": "List APs by Signal Strength",
            "query": """
                SELECT source_mac AS ap_mac, signal, ssid
                FROM packets
                JOIN beacons ON packets.id = beacons.id
                WHERE signal IS NOT NULL
                ORDER BY signal DESC;
            """
        },
        "6": {
            "description": "Count Unique SSIDs Per Encryption Type",
            "query": """
                SELECT encryption, COUNT(DISTINCT ssid) AS ssid_count
                FROM beacons
                GROUP BY encryption
                ORDER BY ssid_count DESC;
            """
        },
        "7": {
            "description": "Top APs by Data Transmitted",
            "query": """
                SELECT source_mac AS ap_mac, SUM(datarate) AS total_data_transmitted
                FROM packets
                GROUP BY source_mac
                ORDER BY total_data_transmitted DESC
                LIMIT 10;
            """
        },
        "8": {
            "description": "APs with Weak or No Encryption",
            "query": """
                SELECT source_mac AS ap_mac, ssid, encryption
                FROM beacons
                WHERE encryption IS NULL OR encryption = 'Open';
            """
        },
        "9": {
            "description": "Devices Sending Probe Requests",
            "query": """
                SELECT source_mac, ssid
                FROM probes
                JOIN packets ON probes.id = packets.id;
            """
        },
        "10": {
            "description": "Devices Broadcasting Probe Floods",
            "query": """
                SELECT source_mac, COUNT(ssid) AS ssid_count
                FROM probes
                GROUP BY source_mac
                HAVING ssid_count > 10
                ORDER BY ssid_count DESC;
            """
        },
        "11": {
            "description": "Devices Sending Deauthentication Frames",
            "query": """
                SELECT source_mac, COUNT(*) AS deauth_count
                FROM deauth_frames
                JOIN packets ON deauth_frames.id = packets.id
                GROUP BY source_mac
                HAVING deauth_count > 50
                ORDER BY deauth_count DESC;
            """
        },
        "12": {
            "description": "Timeline of Beacon Frames",
            "query": """
                SELECT strftime('%Y-%m-%d %H:%M', ts_sec, 'unixepoch') AS time_slot, COUNT(*) AS beacon_count
                FROM packets
                JOIN beacons ON packets.id = beacons.id
                GROUP BY time_slot
                ORDER BY time_slot;
            """
        },
        "13": {
            "description": "Most Active Devices by Packet Count",
            "query": """
                SELECT source_mac, COUNT(*) AS packet_count
                FROM packets
                WHERE source_mac IS NOT NULL
                GROUP BY source_mac
                ORDER BY packet_count DESC
                LIMIT 10;
            """
        },
        "14": {
            "description": "List Hidden APs",
            "query": """
                SELECT source_mac AS ap_mac, ssid, encryption
                FROM beacons
                WHERE ssid IS NULL OR ssid = '';
            """
        },
        "15": {
            "description": "Detect Channel Hopping Devices",
            "query": """
                SELECT source_mac, COUNT(DISTINCT channel) AS channel_count
                FROM packets
                WHERE channel IS NOT NULL
                GROUP BY source_mac
                HAVING channel_count > 3
                ORDER BY channel_count DESC;
            """
        },
        "16": {
            "description": "APs with Most Associated Devices",
            "query": """
                SELECT source_mac AS ap_mac, COUNT(DISTINCT dest_mac) AS client_count
                FROM packets
                WHERE dest_mac IS NOT NULL
                GROUP BY source_mac
                ORDER BY client_count DESC
                LIMIT 10;
            """
        },
        "17": {
            "description": "Frequent SSIDs in Probe Requests",
            "query": """
                SELECT ssid, COUNT(*) AS request_count
                FROM probes
                GROUP BY ssid
                ORDER BY request_count DESC
                LIMIT 10;
            """
        },
        "18": {
            "description": "Signal Strength Distribution",
            "query": """
                SELECT source_mac, AVG(signal) AS avg_signal, MIN(signal) AS min_signal, MAX(signal) AS max_signal
                FROM packets
                WHERE signal IS NOT NULL
                GROUP BY source_mac
                ORDER BY avg_signal DESC
                LIMIT 10;
            """
        },
        "19": {
            "description": "Packet Size Analysis",
            "query": """
                SELECT source_mac, AVG(packet_len) AS avg_size, MAX(packet_len) AS max_size, MIN(packet_len) AS min_size
                FROM packets
                WHERE packet_len IS NOT NULL
                GROUP BY source_mac
                ORDER BY avg_size DESC
                LIMIT 10;
            """
        },
        "20": {
            "description": "Open Networks with High Traffic",
            "query": """
                SELECT ssid, source_mac AS ap_mac, COUNT(*) AS packet_count
                FROM beacons
                JOIN packets ON beacons.id = packets.id
                WHERE encryption IS NULL OR encryption = 'Open'
                GROUP BY ssid, source_mac
                ORDER BY packet_count DESC
                LIMIT 10;
            """
        }
    }

def run_queries(db_path, output_path):
    """Run all queries against the database and save results to a JSON file."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    queries = list_queries()
    results = {}

    for key, value in queries.items():
        query_result = execute_query(cursor, value["query"], value["description"])
        results[key] = query_result

    conn.close()

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as outfile:
        json.dump(results, outfile, indent=4)

    print(f"Results saved to {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run predefined queries on the database.")
    parser.add_argument("db_path", type=str, help="Path to the SQLite database file.")
    parser.add_argument("output_path", type=str, help="Path to save the query results as JSON.")
    args = parser.parse_args()

    run_queries(args.db_path, args.output_path)