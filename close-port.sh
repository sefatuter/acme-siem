#!/usr/bin/env bash

# --- Corrected script to kill a process and report success back to the manager ---
# It logs actions locally and sends a unique message back to create a confirmation alert.

LOG_FILE="/var/ossec/logs/active-responses.log"

read -r JSON

echo "$(date): AR script started. Received JSON: ${JSON}" >> ${LOG_FILE}

PID=$(echo "$JSON" | grep -oP '"full_log":"[^"]*\s+\K[0-9]+(?=\s+.*eval\(hex2bin)')

if [[ -z "$PID" ]]; then
  echo "$(date): Could not find a matching PID for a process containing 'eval(hex2bin)'. Exiting." >> ${LOG_FILE}
  exit 0
fi

echo "$(date): Found PID ${PID} for process containing 'eval(hex2bin)'." >> ${LOG_FILE}

echo "$(date): Sending SIGTERM (15) to PID ${PID}..." >> ${LOG_FILE}
kill -15 "$PID" 2>/dev/null
sleep 1

if kill -0 "$PID" 2>/dev/null; then
  echo "$(date): Process still exists. Sending SIGKILL (9) to PID ${PID}." >> ${LOG_FILE}
  kill -9 "$PID" 2>/dev/null
  MSG="Action complete. Forcefully killed PID ${PID}."
else
  MSG="Action complete. Process with PID ${PID} terminated gracefully."
fi

echo "$(date): ${MSG}" >> ${LOG_FILE}

# --- NEW/MODIFIED PART ---
# Send a unique, structured message back to the Wazuh manager.
# This specific message will be used by our new rule to generate a high-level alert.
echo "Wazuh AR: Success - Process PID ${PID} terminated by close-port.sh."
echo "AR_CONFIRMATION: SCRIPT=close-port.sh STATUS=success PID=${PID}" >> ${LOG_FILE}

exit 0
