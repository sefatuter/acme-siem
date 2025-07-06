#!/usr/bin/python3

import sys
import datetime

# The log file used by Wazuh Active Response
LOG_FILE = "/var/ossec/logs/active-responses.log"

def write_log(message):
    """Writes a message to the active-responses.log file with a timestamp."""
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {sys.argv[0]}: {message}\n")

def main():
    # --- Start of Diagnostic ---
    write_log("--- SCRIPT STARTED ---")

    # Log the command-line arguments received (like $1, $2, etc. in shell)
    write_log(f"Received arguments: {sys.argv}")

    # Read the JSON alert sent from the manager via standard input
    input_json = sys.stdin.read()

    # Log the JSON data received from stdin
    write_log(f"Received stdin data: {input_json.strip()}") # .strip() cleans up newlines

    # --- End of Diagnostic ---
    write_log("--- SCRIPT FINISHED ---")

if __name__ == "__main__":
    main()
