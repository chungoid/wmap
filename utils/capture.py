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
    # Force output redirection for tools that support it
    redirected_args = []
    i = 0
    while i < len(additional_args):
        if additional_args[i] in ["-w", "--write"] and i + 1 < len(additional_args):
            original_output = additional_args[i + 1]
            # Redirect to capture directory
            new_output = os.path.join(CONFIG["capture_dir"], os.path.basename(original_output))
            redirected_args += [additional_args[i], new_output]
            print(f"Redirecting output to: {new_output}")
            i += 2  # Skip the argument and its value
        else:
            redirected_args.append(additional_args[i])
            i += 1

    # Default output redirection if none is specified
    if "-w" not in redirected_args and "--write" not in redirected_args:
        default_output = os.path.join(CONFIG["capture_dir"], f"{tool}_capture.pcap")
        redirected_args += ["-w", default_output]
        print(f"No output specified, defaulting to: {default_output}")

    # Construct the full command
    command = [tool] + redirected_args
    print(f"Starting capture with command: {' '.join(command)}")

    # Execute the command
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