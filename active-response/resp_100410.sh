#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# resp_100410.sh  –  Wazuh active-response for rule 100410 (“CPU spike”)
#
#  • Reads alert JSON from STDIN (as Wazuh pipes it) and extracts PID/CPU/command
#    from parameters.alert.full_log, e.g. "95.4 yes root 1561243".
#  • Captures a quick triage snapshot and stores it in:
#        /var/ossec/active-response/tmp/100410/current_<tag>.txt
#  • Anything it echos to STDERR lands in /var/ossec/logs/active-responses.log
#
# Manual use:
#        ./resp_100410.sh          # auto-selects top-CPU process
#        ./resp_100410.sh 1561243  # target a specific PID
# ---------------------------------------------------------------------------
set -euo pipefail

RULE_ID=100410
OUTDIR="/var/ossec/active-response/tmp/${RULE_ID}"
mkdir -p "$OUTDIR"

log() { echo "$(date '+%F %T') [$RULE_ID] $*" >&2; }

##############################################################################
# 1. Pull PID / CPU / PROC_NAME
##############################################################################
PID=""
CPU=""
PROC_NAME=""

if [ -t 0 ]; then
  # ── manual run ────────────────────────────────────────────────────────────
  PID="${1:-}"
  if [[ -z "$PID" ]]; then
    PID=$(ps -eo pid,%cpu --sort=-%cpu | awk 'NR==2 {print $1}')
  fi
  CPU="manual"
  PROC_NAME=$(ps -p "$PID" -o comm= 2>/dev/null || echo "")
  log "manual run -> PID=${PID}"
else
  # ── called by Wazuh – consume the JSON piped in ──────────────────────────
  read -r ALERT_JSON || true
  echo "$ALERT_JSON" > "${OUTDIR}/current_alert.json"

  FULL_LOG=$(echo "$ALERT_JSON" | jq -r '.parameters.alert.full_log // empty')
  # Example FULL_LOG: "95.4 yes             root     1561243"
  if [[ -n "$FULL_LOG" ]]; then
    PARSED=$(echo "$FULL_LOG" | tr -s ' ')         # squeeze spaces
    CPU=$(echo "$PARSED" | awk '{print $1}')
    PROC_NAME=$(echo "$PARSED" | awk '{print $2}')
    PID=$(echo "$PARSED" | awk '{print $NF}')
  fi
  log "alert run -> PID=${PID} CPU=${CPU} PROC=${PROC_NAME}"
fi

# ── sanity guard ───────────────────────────────────────────────────────────
if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
  log "ERROR: no valid PID – aborting"
  exit 1
fi

##############################################################################
# 2. Command map (single-quoted values; $PID expanded outside)
##############################################################################
declare -A CMD_MAP=(
  # host context ------------------------------------------------------------
  [running-services]='systemctl list-units --type=service --state=running'
  [top-cpu-procs]='ps axo %cpu,pid,ppid,user,etime,cmd --sort=-%cpu | head -n 25'
  [listening-ports]='ss -tulpen'
  [established-conns]='ss -tanp state established | head -n 50'
  [world-writable-dirs]='find / -type d -perm -0002 -maxdepth 2 2>/dev/null | head -n 200'
  [last-logins]='last -n 20'
  [lastb-failures]='lastb -n 20 || true'

  # focus on the hot process -----------------------------------------------
  [pid-summary-proc]='ps -p '"$PID"' -o pid,ppid,user,%cpu,%mem,etime,stat,cmd'
  [threads-cpu-proc]='top -b -H -n 1 -p '"$PID"' | head -n 20'
  [limits-proc]='cat /proc/'"$PID"'/limits'
  [sched-proc]='cat /proc/'"$PID"'/sched'
)

##############################################################################
# 3. Run & capture
##############################################################################
for tag in "${!CMD_MAP[@]}"; do
  {
    echo "# $(date '+%F %T') — ${CMD_MAP[$tag]}"
    bash -c "${CMD_MAP[$tag]}" 2>&1
  } > "${OUTDIR}/current_${tag}.txt" || true
done

log "snapshot saved → $OUTDIR (PID=$PID CPU=$CPU PROC=$PROC_NAME)"
exit 0
