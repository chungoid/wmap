#!/usr/bin/env python3
import os
import sys
import subprocess
import logging

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
sys.path.insert(0, BASE_DIR)
from config.config import CONFIG

# Define directories
capture_dir = CONFIG["capture_dir"]
log_dir = CONFIG["log_dir"]
wrapper_log_file = os.path.join(log_dir, "wrapper.log")

# Set up logging
os.makedirs(log_dir, exist_ok=True)
logging.basicConfig(
    filename=wrapper_log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Define paths to the original tools
TOOL_PATHS = {
    "hcxdumptool": "/usr/bin/hcxdumptool",
    "airodump-ng": "/usr/sbin/airodump-ng",
    "tshark": "/usr/bin/tshark",
    "tcpdump": "/usr/bin/tcpdump",
    "dumpcap": "/usr/bin/dumpcap",
}


def main():
    if len(sys.argv) < 3:  # Expect at least the tool and one argument
        logging.error("Usage: wrapper.py <tool> -- [args...]")
        print("Usage: wrapper.py <tool> -- [args...]")
        print("Supported tools: hcxdumptool, airodump-ng, tshark, tcpdump, dumpcap")
        sys.exit(1)

    tool = sys.argv[1]
    if tool not in TOOL_PATHS:
        logging.error(f"Unsupported tool '{tool}'. Supported tools: {', '.join(TOOL_PATHS.keys())}")
        print(f"Error: Unsupported tool '{tool}'. Supported tools: {', '.join(TOOL_PATHS.keys())}")
        sys.exit(1)

    original_tool_path = TOOL_PATHS[tool]
    if "--" not in sys.argv:
        logging.error("Missing '--' separator. Ensure tool-specific arguments are after '--'.")
        print("Error: Missing '--' separator. Ensure tool-specific arguments are after '--'.")
        sys.exit(1)

    # Extract arguments after the '--' separator
    args_index = sys.argv.index("--") + 1
    args = sys.argv[args_index:]
    redirected_args = []
    i = 0

    while i < len(args):
        if args[i] in ["-w", "--write"] and i + 1 < len(args):
            # Redirect the output file to the capture directory
            original_output = args[i + 1]
            new_output = os.path.join(capture_dir, os.path.basename(original_output))
            redirected_args += [args[i], new_output]
            logging.info(f"Redirecting output to: {new_output}")
            i += 2
        else:
            redirected_args.append(args[i])
            i += 1

    # Add a default output file for tools that support it, if no output argument is provided
    if tool in ["hcxdumptool", "airodump-ng", "tshark", "tcpdump", "dumpcap"]:
        if not any(arg in redirected_args for arg in ["-w", "--write"]):
            default_output = os.path.join(capture_dir, f"{tool}_capture.pcap")
            redirected_args += ["-w", default_output]
            logging.info(f"No output specified, defaulting to: {default_output}")

    # Construct the final command
    command = [original_tool_path] + redirected_args
    logging.debug(f"Executing command: {' '.join(command)}")
    print(f"Executing: {' '.join(command)}")

    # Change working directory to the capture directory
    try:
        os.makedirs(capture_dir, exist_ok=True)

        result = subprocess.run(command, check=True, capture_output=True, text=True, cwd=capture_dir)
        logging.info(f"Capture with {tool} completed successfully.")
        print(f"Capture with {tool} completed successfully.")
        if result.stdout:
            logging.debug(f"Tool output:\n{result.stdout}")
            print(result.stdout)
        if result.stderr:
            logging.warning(f"Warnings or errors:\n{result.stderr}")
            print(f"Warnings or errors:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during capture with {tool}: {e}")
        if e.stderr:
            logging.error(f"Tool output:\n{e.stderr}")
            print(f"Tool output:\n{e.stderr}")
        sys.exit(e.returncode)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()