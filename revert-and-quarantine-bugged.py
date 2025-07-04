#!/usr/bin/python3

import sys
import json
import datetime
import os
import shutil

# --- Configuration ---
# These paths must match the ones you set up in Phase 1
LOG_FILE = "/var/ossec/logs/active-responses.log"
GOLDEN_IMAGE_BASE_DIR = "/var/ossec/etc/golden_images"
QUARANTINE_DIR = "/var/ossec/quarantine"

def write_log(message):
    """Writes a message to the active-responses.log file with a timestamp."""
    with open(LOG_FILE, mode="a") as log_file:
        log_file.write(f"{datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')} {os.path.basename(sys.argv[0])}: {message}\n")

def main():
    write_log("--- Script Started ---")

    # 1. Read the JSON alert from the manager
    try:
        input_json = sys.stdin.read()
        data = json.loads(input_json)
    except json.JSONDecodeError:
        write_log("ERROR: Could not decode JSON input from stdin.")
        sys.exit(1)
    except Exception as e:
        write_log(f"ERROR: An unexpected error occurred while reading input: {e}")
        sys.exit(1)

    # 2. Extract the filename from the JSON data
    try:
        # This is the direct path to the filename in your log sample
        filename = data['parameters']['alert']['syscheck']['path']
        write_log(f"Identified file for remediation: {filename}")
    except KeyError:
        write_log("ERROR: Could not find filename in the alert JSON ('alert.syscheck.path').")
        sys.exit(1)

    # 3. Define paths and perform safety checks
    golden_image_path = os.path.join(GOLDEN_IMAGE_BASE_DIR, filename.lstrip('/'))

    if not os.path.exists(golden_image_path):
        write_log(f"CRITICAL: No golden image found at '{golden_image_path}'. Aborting to prevent data loss.")
        sys.exit(1)

    # 4. Perform the quarantine and revert actions
    try:
        # Ensure the quarantine directory exists
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

        # Create a unique name for the quarantined file
        timestamp = int(datetime.datetime.now().timestamp())
        quarantined_file_name = f"{os.path.basename(filename)}_{timestamp}.quarantined"
        quarantined_file_path = os.path.join(QUARANTINE_DIR, quarantined_file_name)

        # a) Quarantine the bad file
        shutil.copy2(filename, quarantined_file_path)
        write_log(f"Quarantined unauthorized version to: {quarantined_file_path}")

        # b) Revert to the golden image
        shutil.copy2(golden_image_path, filename)
        write_log(f"SUCCESS: Reverted '{filename}' using its golden image.")

    except Exception as e:
        write_log(f"ERROR: An error occurred during the file operation: {e}")
        sys.exit(1)

    write_log("--- Script Finished ---")
    sys.exit(0)

if __name__ == "__main__":
    main()
