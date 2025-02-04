import yaml
import logging

web_logger = logging.getLogger("web")
web_logger.setLevel(logging.DEBUG)


def load_queries(query_file):
    """
    Load and validate queries.yaml, ensuring it follows the correct structure.
    """
    try:
        with open(query_file, "r") as file:
            data = yaml.safe_load(file)

        # Ensure the root key is present
        if "categories" not in data:
            raise ValueError("Invalid format: Missing 'categories' key at root level.")

        # Validate each category
        for category in data["categories"]:
            if "name" not in category or "queries" not in category:
                raise ValueError(f"Invalid category format: {category}")

            for query in category["queries"]:
                if "id" not in query or "description" not in query or "sql" not in query:
                    raise ValueError(f"Invalid query format: {query}")

        return data

    except FileNotFoundError:
        raise FileNotFoundError(f"Query file not found: {query_file}")

    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file '{query_file}': {e}")

    except Exception as e:
        raise ValueError(f"Unexpected error loading queries: {e}")
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