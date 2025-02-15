import threading
import sys
import os
import logging
import sqlite3
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template, send_from_directory
from flask_socketio import SocketIO

# **Fix Import Path Issues for `web.utils`**
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from web.utils import load_queries
from config.config import WEB_SERVER, LOG_FILES

# **Setup Logging for `web`**
web_logger = logging.getLogger("web")
web_logger.setLevel(logging.DEBUG)

web_log_file = LOG_FILES.get("web", "logs/web.log")
web_handler = RotatingFileHandler(web_log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
web_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
web_handler.setFormatter(web_formatter)
web_logger.addHandler(web_handler)

# **Initialize Flask & SocketIO**
app = Flask(__name__, static_folder="static", template_folder="templates")
socketio = SocketIO(app, cors_allowed_origins="*")  # Do NOT use async_mode="eventlet"

# Paths
QUERY_FILE = os.path.join("config", "queries.yaml")
DATABASE_FILE = os.path.join("database", "wmap.db")

# Load Queries
queries = load_queries(QUERY_FILE)

def execute_query(sql):
    """Execute an SQL query and return results."""
    try:
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
        web_logger.debug(f"Executed Query: {sql}")
        return results
    except sqlite3.Error as e:
        web_logger.error(f"Database Error: {e}")
        return {"error": str(e)}

# **Emit live AP & Client data**
def emit_live_data():
    """Continuously fetch and send APs & associated clients to connected clients."""
    while True:
        web_logger.info("Fetching live AP and Client data...")

        # Query APs and Clients with manufacturer info
        ap_query = """
            SELECT mac, ssid, encryption, signal_strength, last_seen, channel, extended_capabilities, manufacturer
            FROM access_points
        """
        client_query = """
            SELECT mac, ssid, associated_ap, last_seen, signal_strength, manufacturer
            FROM clients
        """

        access_points = execute_query(ap_query)
        clients = execute_query(client_query)

        # Organize clients by AP using MAC and SSID
        client_mapping = {}
        for client_mac, client_ssid, client_associated_ap, last_seen, signal_strength, client_manufacturer in clients:
            # Use associated AP MAC if available, otherwise match by SSID
            ap_key = client_associated_ap if client_associated_ap != "ff:ff:ff:ff:ff:ff" else client_ssid

            if ap_key not in client_mapping:
                client_mapping[ap_key] = []

            client_mapping[ap_key].append({
                "mac": client_mac,
                "ssid": client_ssid or "Unknown",
                "manufacturer": client_manufacturer or "Unknown",
                "last_seen": last_seen,
                "signal_strength": signal_strength
            })

        # Format APs with their associated clients and manufacturer
        formatted_aps = []
        for ap in access_points:
            mac, ssid, encryption, signal_strength, last_seen, channel, extended_capabilities, ap_manufacturer = ap

            # Attach clients based on MAC or SSID match
            attached_clients = client_mapping.get(mac, [])
            if not attached_clients and ssid:
                attached_clients = client_mapping.get(ssid, [])

            formatted_aps.append({
                "mac": mac,
                "ssid": ssid,
                "encryption": encryption,
                "manufacturer": ap_manufacturer or "Unknown",
                "signal_strength": signal_strength,
                "last_seen": last_seen,
                "channel": channel,
                "extended_capabilities": extended_capabilities,
                "clients": attached_clients  # Attach matched clients
            })

        # Log emitted data
        web_logger.debug(f"Emitting AP & Client Data: {formatted_aps}")

        # **Emit data to clients**
        socketio.emit("update_ap_client_data", formatted_aps)

        # **Use `socketio.sleep()` instead of `time.sleep()` to prevent blocking**
        socketio.sleep(5)

# **Start emitting live data in a separate thread**
threading.Thread(target=emit_live_data, daemon=True).start()

@app.route("/run-query/<query_id>", methods=["GET"])
def run_query(query_id):
    """Execute a user-selected query from any category."""
    web_logger.info(f"Received request to run query: {query_id}")

    # Iterate through categories correctly
    for category in queries["categories"]:  # Ensure we access the 'categories' list
        for query in category["queries"]:  # Now correctly loop through the list of queries
            if query["id"] == query_id:
                web_logger.info(f"Executing query: {query_id}")
                results = execute_query(query["sql"])
                return jsonify({"id": query_id, "description": query["description"], "results": results})

    # If no matching query is found, return an error
    web_logger.warning(f"Query {query_id} not found.")
    return jsonify({"error": f"Query {query_id} not found."}), 404

# Load categorized queries
queries_by_category = load_queries(QUERY_FILE)

@app.route("/available-queries", methods=["GET"])
def list_queries():
    """Return available queries."""
    web_logger.info("Listing all available queries...")

    if not queries:
        web_logger.warning("No queries found in queries.yaml.")
        return jsonify({"error": "No queries available."}), 500

    structured_queries = [
        {
            "category": category["name"],
            "queries": [
                {"id": query["id"], "description": query["description"]}
                for query in category["queries"]
            ]
        }
        for category in queries["categories"]
    ]

    # Log queries before sending
    web_logger.debug(f"Structured Queries Sent: {structured_queries}")

    return jsonify(structured_queries)

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory("static", filename)

@app.route("/")
def home():
    """Serve the main HTML page."""
    web_logger.info("Serving homepage index.html")
    return render_template("index.html")

if __name__ == "__main__":
    # Detect if running as a detached subprocess (no interactive terminal)
    is_detached = not sys.stdin.isatty()

    # Log Web Server Start
    web_logger.info("Starting Web Server...")

    socketio.run(
        app,
        host=WEB_SERVER["host"],
        port=WEB_SERVER["port"],
        debug=not is_detached,  # Disable debug mode if running detached
        use_reloader=False  # Fully disable the reloader to prevent stdin issues
    )