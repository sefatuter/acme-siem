#!/bin/bash
read INPUT_JSON
LOG_FILE="/var/ossec/logs/active-responses.log"
FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path' 2>/dev/null)

# Directories
PENDING_DIR="/var/ossec/queue/pending-changes"
BASELINE_DIR="/var/ossec/queue/baseline"

# Create directories if they don't exist
mkdir -p "$PENDING_DIR"
mkdir -p "$BASELINE_DIR"

# File name
FILENAME=$(basename "$FILE_PATH")
BASELINE_FILE="$BASELINE_DIR/$FILENAME.original"

# Check if we have a baseline for this file
# If no baseline exists, create one from current state and exit
if [ ! -f "$BASELINE_FILE" ]; then
    echo "$(date): No baseline found for $FILE_PATH, creating baseline now" >> ${LOG_FILE}
    cp "$FILE_PATH" "$BASELINE_FILE"
    echo "$(date): Baseline created for $FILE_PATH at $BASELINE_FILE" >> ${LOG_FILE}
    exit 0
fi

# Check if the monitored file exists
if [ ! -f "$FILE_PATH" ]; then
    echo "$(date): ERROR - Monitored file $FILE_PATH does not exist" >> ${LOG_FILE}
    exit 1
fi

echo "$(date): Received input: ${INPUT_JSON}" >> ${LOG_FILE}

# /home/sefatuter/test.txt or /etc/hosts
echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path' >> ${LOG_FILE}

if [ "$FILE_PATH" = "null" ] || [ -z "$FILE_PATH" ]; then
    echo "$(date): Could not extract file path with jq, trying alternative method" >> ${LOG_FILE}
    FILE_PATH=$(echo "$INPUT_JSON" | grep -oP '"path":"[^"]*"' | cut -d'"' -f4)
fi

# Skip if we couldn't extract file path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    echo "$(date): ERROR - Could not extract file path from alert" >> ${LOG_FILE}
    exit 1
fi

echo "$(date): Processing file: $FILE_PATH" >> ${LOG_FILE}

# Check if current file is different from baseline
if cmp -s "$FILE_PATH" "$BASELINE_FILE"; then
    echo "$(date): File $FILE_PATH is already at baseline, skipping revert" >> ${LOG_FILE}
    exit 0
fi

# Save current (modified) file for approval with more precise timestamp
TIMESTAMP=$(date +%s%N | cut -b1-13)  # milliseconds precision
PENDING_FILE="$PENDING_DIR/$FILENAME.modified.$TIMESTAMP"
echo "$(date): Saving modified file to: $PENDING_FILE" >> ${LOG_FILE}
cp "$FILE_PATH" "$PENDING_FILE"

# Revert to baseline
echo "$(date): Reverting $FILE_PATH to baseline" >> ${LOG_FILE}
cp "$BASELINE_FILE" "$FILE_PATH"

# Extract diff information for logging
DIFF_INFO=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.diff' 2>/dev/null)
if [ "$DIFF_INFO" != "null" ] && [ -n "$DIFF_INFO" ]; then
    echo "$(date): Changes detected: $DIFF_INFO" >> ${LOG_FILE}
fi

echo "$(date): SUCCESS - $FILE_PATH reverted to baseline, modified version saved as $PENDING_FILE" >> ${LOG_FILE}
exit 0
