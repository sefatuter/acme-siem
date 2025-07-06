#!/usr/bin/env bash

# --- Corrected script to kill bash -i reverse shell and log directly ---
# It now logs everything to /var/ossec/logs/active-responses.log for easy debugging.

# The dedicated log file for Active Response on the agent.
LOG_FILE="/var/ossec/logs/active-responses.log"

# Read the full alert JSON from Wazuh's standard input.
read -r JSON

# Log the received data for debugging.
echo "$(date): AR script started. Received JSON: ${JSON}" >> ${LOG_FILE}

# Extract the PID using the robust grep command.
# The \K tells grep to drop everything before it from the final output.
PID=$(echo "$JSON" | grep -oP '"full_log":"[^"]*\s+\K[0-9]+(?=\s+bash\s+-i)')

# If no PID was found, log it and exit.
if [[ -z "$PID" ]]; then
  echo "$(date): Could not find a matching PID in the JSON. Exiting." >> ${LOG_FILE}
  exit 0
fi

echo "$(date): Found PID ${PID} for bash -i reverse shell." >> ${LOG_FILE}

# Kill the process: first gracefully (SIGTERM), then forcefully (SIGKILL).
# The '2>/dev/null' suppresses errors if the process is already gone.
echo "$(date): Sending SIGTERM (15) to PID ${PID}..." >> ${LOG_FILE}
kill -15 "$PID" 2>/dev/null

# Wait a moment to see if it terminated.
sleep 1

# Check if the process still exists (kill -0). If it does, kill it with SIGKILL.
if kill -0 "$PID" 2>/dev/null; then
  echo "$(date): Process still exists. Sending SIGKILL (9) to PID ${PID}." >> ${LOG_FILE}
  kill -9 "$PID" 2>/dev/null
  MSG="Action complete. Forcefully killed PID ${PID}."
  echo "Host Blocked by close-port Active Response"
else
  MSG="Action complete. Process with PID ${PID} terminated gracefully."
fi

echo "$(date): ${MSG}" >> ${LOG_FILE}

exit 0
