import os
import datetime
import pwd
import subprocess
import getpass
import logging


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


