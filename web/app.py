from flask import Flask, jsonify
from web.utils import load_queries, get_query_by_id
import sqlite3
import os

# Flask App
app = Flask(__name__)

# Paths
QUERY_FILE = os.path.join('config', 'queries.yaml')
DATABASE_FILE = os.path.join('database', 'wmap.py.db')

# Load Queries
queries = load_queries(QUERY_FILE)


def execute_query(db_path, query):
    """Execute a query on the database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    except sqlite3.Error as e:
        return {"error": str(e)}


@app.route('/queries', methods=['GET'])
def list_queries():
    """List all available queries."""
    return jsonify(queries)


@app.route('/query/<query_id>', methods=['GET'])
def run_query(query_id):
    """Run a specific query by ID."""
    query_entry = get_query_by_id(queries, query_id)
    if not query_entry:
        return jsonify({"error": f"Query with ID {query_id} not found."}), 404

    query = query_entry['query']
    description = query_entry['description']

    results = execute_query(DATABASE_FILE, query)
    if isinstance(results, dict) and "error" in results:
        return jsonify({"error": results["error"]}), 500

    return jsonify({
        "id": query_id,
        "description": description,
        "results": results
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)