import yaml
from config.config import CONFIG

def load_queries(query_file=None):
    """
    Load queries from the YAML file.
    If no query file is specified, defaults to CONFIG['queries_file'].
    """
    query_file = query_file or CONFIG.get("queries_file")
    if not query_file:
        raise ValueError("No query file specified and none defined in the configuration.")

    try:
        with open(query_file, "r") as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        raise FileNotFoundError(f"Query file '{query_file}' not found.")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file '{query_file}': {e}")

def get_query_by_id(queries, query_id):
    """
    Retrieve a query by its ID.
    """
    for query in queries:
        if query.get("id") == query_id:
            return query
    return None

def list_query_ids(queries):
    """
    List all available query IDs and their descriptions.
    """
    return [(query["id"], query["description"]) for query in queries]

def execute_query(cursor, query):
    """
    Execute a given query using a database cursor.
    Returns results or an error message.
    """
    try:
        cursor.execute(query["sql"])
        results = cursor.fetchall()
        return {"id": query["id"], "description": query["description"], "results": results}
    except Exception as e:
        return {"id": query["id"], "description": query["description"], "error": str(e)}

def run_queries(cursor, queries):
    """
    Run all queries and return results.
    """
    results = []
    for query in queries:
        result = execute_query(cursor, query)
        results.append(result)
    return results