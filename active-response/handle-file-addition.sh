#!/bin/bash

# Active Response Script for File Addition (Rule ID 554)
# This script handles new files added to monitored directories
# by moving them to a pending directory for review

read INPUT_JSON

LOG_FILE="/var/ossec/logs/active-responses.log"

# Extract file path from the JSON input
FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path' 2>/dev/null)

# Directories - using custom directory outside queue to prevent automatic cleanup
PENDING_DIR="/var/ossec/queue/pending-changes"

# Create directory if it doesn't exist
mkdir -p "$PENDING_DIR"

# Log the input for debugging
echo "$(date): [ADDITION] Received input: ${INPUT_JSON}" >> ${LOG_FILE}

# Alternative method to extract file path if jq fails
if [ "$FILE_PATH" = "null" ] || [ -z "$FILE_PATH" ]; then
    echo "$(date): Could not extract file path with jq, trying alternative method" >> ${LOG_FILE}
    FILE_PATH=$(echo "$INPUT_JSON" | grep -oP '"path":"[^"]*"' | cut -d'"' -f4)
fi

# Skip if we couldn't extract file path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    echo "$(date): ERROR - Could not extract file path from alert" >> ${LOG_FILE}
    exit 1
fi

echo "$(date): Processing newly added file: $FILE_PATH" >> ${LOG_FILE}

# Check if the added file still exists
if [ ! -f "$FILE_PATH" ]; then
    echo "$(date): WARNING - Added file $FILE_PATH no longer exists" >> ${LOG_FILE}
    exit 0
fi

# Get file information
FILENAME=$(basename "$FILE_PATH")
TIMESTAMP=$(date +%s)
PENDING_FILE="$PENDING_DIR/$FILENAME.added.$TIMESTAMP"

echo "$(date): Moving added file to pending directory: $PENDING_FILE" >> ${LOG_FILE}

# Move the file to pending directory for approval
if mv "$FILE_PATH" "$PENDING_FILE"; then
    echo "$(date): SUCCESS - File moved from $FILE_PATH to $PENDING_FILE" >> ${LOG_FILE}
    echo "$(date): Original directory restored to previous state" >> ${LOG_FILE}
else
    echo "$(date): ERROR - Failed to move file from $FILE_PATH to $PENDING_FILE" >> ${LOG_FILE}
    exit 1
fi

echo "$(date): File addition blocked - awaiting SOC approval for: $FILE_PATH" >> ${LOG_FILE}

exit 0
