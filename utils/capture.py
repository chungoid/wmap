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
    # Force all outputs into the capture directory
    output_arg = None
    for i, arg in enumerate(additional_args):
        if arg in ["-w", "--write"]:
            output_arg = i + 1
            break

    if output_arg and output_arg < len(additional_args):
        # Adjust the output file path
        original_output = additional_args[output_arg]
        if not os.path.isabs(original_output):  # If relative path
            new_output = os.path.join(CONFIG["capture_dir"], original_output)
        else:  # If absolute path
            new_output = os.path.join(CONFIG["capture_dir"], os.path.basename(original_output))
        additional_args[output_arg] = new_output
        print(f"Redirecting output to: {new_output}")
    else:
        # If no -w/--write is specified, enforce a default file in the capture directory
        default_output = os.path.join(CONFIG["capture_dir"], f"{tool}_capture.pcap")
        additional_args += ["-w", default_output]
        print(f"No output file specified, defaulting to: {default_output}")

    # Construct the command and execute it
    print(f"Starting capture with command: {' '.join([tool] + additional_args)}")
    try:
        result = subprocess.run([tool] + additional_args, check=True, capture_output=True, text=True)
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