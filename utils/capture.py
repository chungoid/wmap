import os
import subprocess
from config.config import CONFIG

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
    """Run the specified capture tool."""
    # Adjust output paths to use the capture directory
    for i, arg in enumerate(additional_args):
        if arg in ["-w", "--write"]:  # Common output arguments
            output_index = i + 1
            if output_index < len(additional_args):
                output_file = additional_args[output_index]
                if not os.path.isabs(output_file):  # If not absolute path
                    new_path = os.path.join(CONFIG["capture_dir"], output_file)
                    additional_args[output_index] = new_path
                    print(f"Adjusted output file path to: {new_path}")

    # Construct the command and execute it
    print(f"Starting capture with {tool}...")
    command = [tool] + additional_args
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"Capture completed with {tool}.")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"Warnings or errors:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Error during capture with {tool}: {e}")
        if e.stderr:
            print(f"Tool output:\n{e.stderr}")
        exit(1)