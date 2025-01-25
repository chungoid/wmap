import os
from config.config import CONFIG, LOG_FILES
import logging
import subprocess
import sys

LOG_FILE = LOG_FILES["wrapper"]
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

capture_dir = CONFIG["capture_dir"]

# Define paths to the original tools
TOOL_PATHS = {
    "hcxdumptool": "/usr/bin/hcxdumptool",
    "airodump-ng": "/usr/sbin/airodump-ng",
    "tshark": "/usr/bin/tshark",
    "tcpdump": "/usr/bin/tcpdump",
    "dumpcap": "/usr/bin/dumpcap",
}

def main():
    if len(sys.argv) < 2:
        print("Usage: wrapper.py <tool> [args...]")
        print("Supported tools: hcxdumptool, airodump-ng, tshark, tcpdump, dumpcap")
        sys.exit(1)

    tool = sys.argv[1]
    if tool not in TOOL_PATHS:
        print(f"Error: Unsupported tool '{tool}'. Supported tools: {', '.join(TOOL_PATHS.keys())}")
        sys.exit(1)

    original_tool_path = TOOL_PATHS[tool]
    args = sys.argv[2:]  # Remaining arguments after the tool name
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

    try:
        os.makedirs(capture_dir, exist_ok=True)
        result = subprocess.run(command, check=True, capture_output=True, text=True, cwd=capture_dir)
        logging.info(f"Capture with {tool} completed successfully.")
        if result.stdout:
            logging.debug(result.stdout)
        if result.stderr:
            logging.warning(f"Warnings or errors:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error during capture with {tool}: {e}")
        if e.stderr:
            logging.error(f"Tool output:\n{e.stderr}")
        sys.exit(e.returncode)

if __name__ == "__main__":
    main()
