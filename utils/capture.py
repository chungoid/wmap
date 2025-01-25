import os
import sys
import subprocess
from config.config import CONFIG

WRAPPER_PATH = os.path.join(os.path.dirname(__file__), "wrapper.py")

def prepare_output_directory(output_path):
    """Ensure the output directory exists."""
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)


def determine_tool_args(tool, output, additional_args):
    """Adjust arguments for the specific capture tool."""
    if tool == "hcxdumptool":
        additional_args += ["-o", output]
    elif tool == "tshark":
        additional_args += ["-w", output]
    elif tool == "airodump-ng":
        additional_args += ["--write", os.path.splitext(output)[0]]
    elif tool == "tcpdump":
        additional_args += ["-w", output]
    elif tool == "dumpcap":
        additional_args += ["-w", output]
    return additional_args


def capture_packets(tool, additional_args):
    """
    Run the specified capture tool using the wrapper script.

    :param tool: The capture tool to run (e.g., hcxdumptool, airodump-ng, etc.).
    :param additional_args: List of additional arguments to pass to the tool.
    """
    if not os.path.exists(WRAPPER_PATH):
        raise FileNotFoundError(f"Wrapper script not found at {WRAPPER_PATH}")

    command = ["python3", WRAPPER_PATH, tool] + additional_args
    print(f"Starting capture with command: {' '.join(command)}")

    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print("Capture completed successfully.")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"Warnings or errors:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Error during capture with {tool}: {e}")
        if e.stderr:
            print(f"Tool output:\n{e.stderr}")
        exit(e.returncode)