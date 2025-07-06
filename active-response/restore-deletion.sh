#!/bin/bash


read INPUT_JSON


LOG_FILE="/var/ossec/logs/active-responses.log"
FILE_PATH=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path' 2>/dev/null)

# Directories
BASELINE_DIR="/var/ossec/queue/baseline"

# Create directories if they don't exist
mkdir -p "$BASELINE_DIR"

# Get filename without path for storage
FILENAME=$(basename "$FILE_PATH")

# Check if we have a baseline for this file
BASELINE_FILE="$BASELINE_DIR/$FILENAME.original"

# Log the input for debugging
echo "$(date): [DELETION] Received input: ${INPUT_JSON}" >> ${LOG_FILE}

# If jq fails or path is null, try alternative extraction methods
if [ "$FILE_PATH" = "null" ] || [ -z "$FILE_PATH" ]; then
    echo "$(date): [DELETION] Could not extract file path with jq, trying alternative method" >> ${LOG_FILE}
    # Try to extract from the path field
    FILE_PATH=$(echo "$INPUT_JSON" | sed -n 's/.*"path":"\([^"]*\)".*/\1/p')
    
    # If still empty, try to extract from full_log
    if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
        echo "$(date): [DELETION] Trying to extract from full_log field" >> ${LOG_FILE}
        FILE_PATH=$(echo "$INPUT_JSON" | sed -n "s/.*File '\([^']*\)' deleted.*/\1/p")
    fi
fi

# Skip if we couldn't extract file path
if [ -z "$FILE_PATH" ] || [ "$FILE_PATH" = "null" ]; then
    echo "$(date): [DELETION] ERROR - Could not extract file path from alert" >> ${LOG_FILE}
    exit 1
fi


echo "$(date): [DELETION] Processing deleted file: $FILE_PATH" >> ${LOG_FILE}

# If no baseline exists, we cannot restore
if [ ! -f "$BASELINE_FILE" ]; then
    echo "$(date): [DELETION] ERROR - No baseline found for $FILE_PATH, cannot restore deleted file" >> ${LOG_FILE}
    exit 1
fi

# Check if the file is actually deleted (should not exist)
if [ -f "$FILE_PATH" ]; then
    echo "$(date): [DELETION] WARNING - File $FILE_PATH still exists, may be a false positive" >> ${LOG_FILE}
fi

# Restore file from baseline
echo "$(date): [DELETION] Restoring $FILE_PATH from baseline" >> ${LOG_FILE}
cp "$BASELINE_FILE" "$FILE_PATH"

# Set ownership to root:root
chown root:root "$FILE_PATH"
echo "$(date): [DELETION] Ownership set to root:root" >> ${LOG_FILE}

# Restore permissions
BASELINE_PERMS=$(stat -c "%a" "$BASELINE_FILE" 2>/dev/null)
if [ $? -eq 0 ]; then
    chmod "$BASELINE_PERMS" "$FILE_PATH"
    echo "$(date): [DELETION] Permissions restored: $BASELINE_PERMS" >> ${LOG_FILE}
fi


# Verify restoration was successful
if [ -f "$FILE_PATH" ]; then
    echo "$(date): [DELETION] SUCCESS - File $FILE_PATH restored from baseline" >> ${LOG_FILE}
    
    # Preserve original file permissions and ownership if possible
    # Get baseline file permissions
    BASELINE_PERMS=$(stat -c "%a" "$BASELINE_FILE" 2>/dev/null)
    if [ $? -eq 0 ]; then
        chmod "$BASELINE_PERMS" "$FILE_PATH"
        echo "$(date): [DELETION] Permissions restored: $BASELINE_PERMS" >> ${LOG_FILE}
    fi
    
else
    echo "$(date): [DELETION] ERROR - Failed to restore $FILE_PATH from baseline" >> ${LOG_FILE}
    exit 1
fi


# Extract additional alert information for logging
ALERT_LEVEL=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.level' 2>/dev/null)
ALERT_DESC=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.description' 2>/dev/null)
ALERT_ID=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.rule.id' 2>/dev/null)
AGENT_NAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.name' 2>/dev/null)
AGENT_IP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.agent.ip' 2>/dev/null)
TIMESTAMP=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.timestamp' 2>/dev/null)

echo "$(date): [DELETION] Alert Details - Rule ID: $ALERT_ID, Level: $ALERT_LEVEL, Agent: $AGENT_NAME ($AGENT_IP)" >> ${LOG_FILE}

if [ "$ALERT_LEVEL" != "null" ] && [ -n "$ALERT_LEVEL" ]; then
    echo "$(date): [DELETION] Alert Description: $ALERT_DESC" >> ${LOG_FILE}
fi


echo "$(date): [DELETION] Active response completed successfully" >> ${LOG_FILE}

exit 0
