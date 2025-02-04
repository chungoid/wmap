import os
import datetime
import pwd
import subprocess
import getpass
import logging

from config.config import CONFIG, WEB_SERVER, WEB_SERVER_PATH


logger = logging.getLogger("wmap")

def generate_capture_filename():
    """Generate a unique PCAPNG filename based on timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    from config.config import CONFIG
    return os.path.join(CONFIG["capture_dir"], f"wmap_{timestamp}.pcapng")

def generate_nmea_filename():
    """Generate a unique NMEA filename based on timestamp."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    from config.config import CONFIG
    return os.path.join(CONFIG["capture_dir"], f"wmap_{timestamp}.nmea")

def check_permissions():
    """Warn the user if they do not have write permissions to key directories."""
    from config.config import CONFIG
    directories = [CONFIG["capture_dir"], CONFIG["log_dir"], CONFIG["db_dir"]]

    for directory in directories:
        if not os.access(directory, os.W_OK):
            logger.warning(f"Warning: You do not have write permissions to {directory}. Run with sudo or fix ownership.")


def get_owner(path):
    """Return the owner of a file or directory."""
    try:
        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception as e:
        logger.warning(f"Could not determine owner of {path}: {e}")
        return None


def fix_permissions(paths=None):
    """Fix ownership of files and directories affected by sudo.

    If no paths are provided, it defaults to fixing all key directories.
    """
    try:
        username = os.getenv("SUDO_USER", getpass.getuser())
        expected_owner = pwd.getpwnam(username).pw_uid
        from config.config import CONFIG

        if paths is None:
            paths = [CONFIG["db_dir"], CONFIG["log_dir"], CONFIG["capture_dir"]]

        for path in paths:
            if os.path.exists(path):
                current_owner = os.stat(path).st_uid

                if current_owner == expected_owner:
                    logger.debug(f"Skipping {path}, already correctly owned by {username}")
                    continue  # Only skip if already owned by the correct user

                # Fix ownership if incorrect
                subprocess.run(["sudo", "chown", "-R", f"{username}:{username}", path], check=True)
                logger.debug(f"Successfully fixed permissions for {path}, changed ownership to {username}")

    except Exception as e:
        logger.warning(f"Could not fix permissions for {paths}: {e}")


def stop_webserver():
    """Find and stop any existing web server process using the configured port."""
    web_port = WEB_SERVER["port"]  # Get the configured webserver port

    try:
        # Find processes using the port
        result = subprocess.run(
            ["lsof", "-t", "-i", f":{web_port}"], capture_output=True, text=True
        )

        if result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                # Check if the PID belongs to a Python process (Flask web server)
                process_info = subprocess.run(
                    ["ps", "-o", "comm=", "-p", pid], capture_output=True, text=True
                )
                process_name = process_info.stdout.strip()

                if "python" in process_name.lower():  # Only kill Python processes
                    subprocess.run(["kill", "-9", pid])
                    logger.info(f"Stopped existing web server (PID: {pid})")
                else:
                    logger.info(f"Skipping non-Python process (PID: {pid} - {process_name})")

    except Exception as e:
        logger.warning(f"Could not check for existing web server: {e}")


def start_webserver():
    """Start the web server, ensuring no previous instance is running."""
    logger.info(f"Attempting to start web server: {WEB_SERVER_PATH}")

    if os.path.exists(WEB_SERVER_PATH):
        stop_webserver()  # Stop existing server before starting a new one
        logger.info(f"Starting web server from {WEB_SERVER_PATH}...")

        with open(os.path.join(CONFIG["log_dir"], "web.log"), "a") as log_file:
            result = subprocess.Popen(["python3", WEB_SERVER_PATH], stdout=log_file, stderr=log_file)
            logger.info(f"Web server started with PID: {result.pid}")

    else:
        logger.error(f"Web server file not found: {WEB_SERVER_PATH}")




