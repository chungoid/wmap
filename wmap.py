import os
import subprocess
import argparse
from config.config import CONFIG, ensure_directories
from tools.init_db import initialize_database

def run_capture_tool(tool, interface, additional_args):
    """Run the specified capture tool with user-defined options."""
    print(f"Starting capture with {tool} on {interface}...")
    command = [tool, "-i", interface] + additional_args
    try:
        subprocess.run(command, check=True)
        print(f"Capture completed with {tool}.")
    except subprocess.CalledProcessError as e:
        print(f"Error during capture with {tool}: {e}")
        if e.stderr:
            print(f"Tool output:\n{e.stderr.decode('utf-8')}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Initialize Wi-Fi packet capture.")
    parser.add_argument("interface", type=str, help="Wireless interface to use (e.g., wlan0mon).")
    parser.add_argument("-t", "--tool", type=str, required=True,
                        choices=["hcxdumptool", "tshark", "airodump-ng", "tcpdump", "dumpcap"],
                        help="Capture tool to use (e.g., hcxdumptool, tshark, airodump-ng, tcpdump, dumpcap).")
    parser.add_argument("-o", "--output", type=str, required=True,
                        help="Output file or directory for the capture.")
    parser.add_argument("--args", nargs=argparse.REMAINDER, help="Additional arguments for the capture tool.")

    args = parser.parse_args()

    # Ensure all project directories exist
    ensure_directories()

    # Initialize the database if it doesn't already exist
    db_path = CONFIG["db_dir"] + "/wmap.db"
    if not os.path.exists(db_path):
        print(f"Initializing database at {db_path}...")
        initialize_database(db_path)
    else:
        print(f"Database already exists at {db_path}.")

    # Ensure output directory exists
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # Append user-defined arguments to the tool command
    additional_args = args.args if args.args else []

    # Adjust output argument for specific tools
    if args.tool == "hcxdumptool":
        additional_args += ["-o", args.output]
    elif args.tool == "tshark":
        additional_args += ["-w", args.output]
    elif args.tool == "airodump-ng":
        additional_args += ["--write", os.path.splitext(args.output)[0]]
    elif args.tool == "tcpdump":
        additional_args += ["-w", args.output]
    elif args.tool == "dumpcap":
        additional_args += ["-w", args.output]

    # Run the capture tool with user-defined options
    run_capture_tool(args.tool, args.interface, additional_args)


if __name__ == "__main__":
    main()
