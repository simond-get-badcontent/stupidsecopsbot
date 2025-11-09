#!/usr/bin/python3
"""
A script to perform network scanning using Nmap. It defines an MCP server with
tools to run pre-defined Nmap scans and specific port scans on given targets.
"""

import subprocess
import sys
from mcp.server.fastmcp import FastMCP

# --------------------------------------------------------------------------------------------------
# stupidsecopsbot
# --------------------------------------------------------------------------------------------------
# Author: Simon Lundmark
# --------------------------------------------------------------------------------------------------
# Changelog:
# 2025-11-09: Created and tested. //Simon
# --------------------------------------------------------------------------------------------------
# Install notes:
# pip install mcp
# --------------------------------------------------------------------------------------------------
# Current version:
VERSION = "v. 0.1"
# --------------------------------------------------------------------------------------------------
# Run this script with the "test" argument to perform self-tests
# ./stupidsecopsbot.py test
# --------------------------------------------------------------------------------------------------

# Initialize the FastMCP server with the name "Nmap-Server"
server = FastMCP("Nmap-Server")


def check_nmap():
    """
    Checks if the 'nmap' command is available on the system.
    Prints status messages to stderr.
    Returns True if nmap is installed, False otherwise.
    """
    print("Checking if 'nmap' command is available...", file=sys.stderr)
    try:
        # Try running 'nmap -V' to check if nmap is installed
        subprocess.run(['nmap', '-V'], capture_output=True, check=True)
        print("Nmap is installed and accessible.", file=sys.stderr)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        # If nmap is not found or returns an error, print instructions
        print("FATAL ERROR: Nmap is not installed or not in system PATH.", file=sys.stderr)
        print("On Ubuntu, run: sudo apt install nmap", file=sys.stderr)
        return False

# This (@server.tool) is a decorator making the function below callable.
@server.tool()
def scan_network(target: str, scan_type: str = "quick") -> str:
    """
    Runs a pre-defined Nmap scan against a target.

    :param target: The target to scan (e.g., "192.168.1.1/24" or "scanme.nmap.org").
    :param scan_type: The type of scan to run.
        Allowed values:
        - "quick": Fast scan (-T4 -F)
        - "full": Scans all ports (-p-)
        - "service": Detects services (-sV)
        - "ping": A simple ping scan (-sn)
    :return: The raw text output from the Nmap scan.
    """
    # Map scan types to their corresponding Nmap flags
    scan_flags = {
        "quick": "-T4 -F",
        "full": "-p-",
        "service": "-sV",
        "ping": "-sn"
    }
    # Get the flags for the requested scan type, default to "quick" if not found
    flags = scan_flags.get(scan_type, "-T4 -F")
    # Build the command as a list for subprocess
    command = ['nmap'] + flags.split() + [target]
    return _run_command(command)


@server.tool()
def scan_ports(target: str, ports: str) -> str:
    """
    Scans specific ports on a target.

    :param target: The target to scan (e.g., "192.168.1.1").
    :param ports: The ports to scan (e.g., "80,443" or "1-1000").
    :return: The raw text output from the Nmap scan.
    """
    # Build the command to scan specific ports
    command = ['nmap', '-p', ports, target]
    return _run_command(command)


def _run_command(command: list) -> str:
    """
    Helper function to execute any Nmap command safely.

    :param command: The command to execute as a list.
    :return: The output from the command, or an error message.
    """
    # Define allowed characters for command arguments to prevent injection
    safe_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/,"
    for arg in command:
        if not all(c in safe_chars for c in arg):
            return "Error: Invalid characters in arguments. Rejected."
    print(f"Executing Nmap command: {' '.join(command)}", file=sys.stderr)
    try:
        # Run the command and capture output
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=300  # Set a timeout for long scans
        )
        print("Scan completed successfully.", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        # Handle Nmap command errors
        print(f"Nmap command failed: {e.stderr}", file=sys.stderr)
        return f"Nmap command failed. Error: {e.stderr}"
    except Exception as e:
        # Handle unexpected errors
        print(f"An unexpected error occurred: {str(e)}", file=sys.stderr)
        return f"An unexpected server error occurred: {str(e)}"


def super_cool_banner():
    """This program will probably not even work without this."""
    print("\n" * 50)
    print("""
 _______  _______  __   __  _______  ___   ______   _______  _______  _______ 
|       ||       ||  | |  ||       ||   | |      | |       ||       ||       |
|  _____||_     _||  | |  ||    _  ||   | |  _    ||  _____||    ___||       |
| |_____   |   |  |  |_|  ||   |_| ||   | | | |   || |_____ |   |___ |       |
|_____  |  |   |  |       ||    ___||   | | |_|   ||_____  ||    ___||      _|
 _____| |  |   |  |       ||   |    |   | |       | _____| ||   |___ |     |_ 
|_______|  |___|  |_______||___|    |___| |______| |_______||_______||_______|
 _______  _______  _______  _______  _______  _______                         
|       ||       ||       ||  _    ||       ||       |                        
|   _   ||    _  ||  _____|| |_|   ||   _   ||_     _|                        
|  | |  ||   |_| || |_____ |       ||  | |  |  |   |                          
|  |_|  ||    ___||_____  ||  _   | |  |_|  |  |   |                          
|       ||   |     _____| || |_|   ||       |  |   |                          
|_______||___|    |_______||_______||_______|  |___| Hey, it's me, stupid!
    """, VERSION)


if __name__ == "__main__":
    # Check if nmap is installed before starting the server or running tests
    super_cool_banner()
    if not check_nmap():
        sys.exit(1)
    # If script is run with "test" argument, perform test scans
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        print("--- RUNNING LOGIC TEST ---")
        print("\n[Test 1: Quick Scan on scanme.nmap.org]")
        results = scan_network("scanme.nmap.org", "quick")
        print(results)
        print("\n[Test 2: Port Scan on scanme.nmap.org for ports 80,443]")
        results_ports = scan_ports("scanme.nmap.org", "80,443")
        print(results_ports)
        print("\n--- TEST COMPLETE ---")
    else:
        # Start the MCP server and wait for commands via stdio
        print("Nmap MCP server starting, awaiting commands via stdio...", file=sys.stderr)
        server.run(transport="stdio")
