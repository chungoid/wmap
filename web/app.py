import sys
import os
import logging
import threading
import sqlite3
import time
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify, render_template
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

# **Flask App & SocketIO**
app = Flask(__name__, static_folder="static", template_folder="templates")
socketio = SocketIO(app, cors_allowed_origins="*")

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

        ap_query = "SELECT mac, ssid, encryption, signal_strength, last_seen, channel, extended_capabilities FROM access_points"
        client_query = "SELECT mac, associated_ap, last_seen, signal_strength FROM clients"

        access_points = execute_query(ap_query)
        clients = execute_query(client_query)

        # Organize clients by associated AP
        client_mapping = {}
        for client in clients:
            client_mac, associated_ap, last_seen, signal_strength = client
            if associated_ap not in client_mapping:
                client_mapping[associated_ap] = []
            client_mapping[associated_ap].append({
                "mac": client_mac,
                "last_seen": last_seen,
                "signal_strength": signal_strength
            })

        # Format APs with their associated clients
        formatted_aps = []
        for ap in access_points:
            mac, ssid, encryption, signal_strength, last_seen, channel, extended_capabilities = ap
            formatted_aps.append({
                "mac": mac,
                "ssid": ssid,
                "encryption": encryption,
                "signal_strength": signal_strength,
                "last_seen": last_seen,
                "channel": channel,
                "extended_capabilities": extended_capabilities,
                "clients": client_mapping.get(mac, [])  # Attach associated clients
            })

        # Log emitted data
        web_logger.debug(f"Emitting AP & Client Data: {formatted_aps}")

        socketio.emit("update_ap_client_data", formatted_aps)
        time.sleep(5)  # Refresh every 5 seconds

# Start emitting live data in a separate thread
threading.Thread(target=emit_live_data, daemon=True).start()

# **Serve Homepage**
@app.route("/")
def home():
    """Serve the main HTML page."""
    web_logger.info("Serving homepage index.html")
    return render_template("index.html")  # Ensure index.html exists in `templates/`

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
    """Return available queries categorized properly."""
    web_logger.info("Listing all available queries...")

    if not queries or "categories" not in queries:
        web_logger.warning("No queries found or 'categories' key missing in queries.yaml.")
        return jsonify({"error": "No queries available."}), 500

    # **Extract all queries under their categories**
    structured_queries = []
    for category in queries["categories"]:
        category_name = category.get("name", "Uncategorized")
        if "queries" in category:
            structured_queries.append({
                "category": category_name,
                "queries": [{"id": q["id"], "description": q["description"]} for q in category["queries"]]
            })

    web_logger.debug(f"Structured Queries Sent: {structured_queries}")
    return jsonify(structured_queries)  # Return queries properly categorized

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
