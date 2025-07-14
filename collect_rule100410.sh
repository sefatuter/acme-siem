#!/usr/bin/env bash
set -euo pipefail

AGENT_RULE_ID="100410"
BASE_DIR="/var/ossec/baselines/${AGENT_RULE_ID}"
mkdir -p "$BASE_DIR"

PID=""

declare -A CMD_MAP=(
  [running-services]="systemctl list-units --type=service --state=running"
  [top-cpu-procs]="ps axo %cpu,pid,ppid,user,etime,cmd --sort=-%cpu | head -n 25"
  [listening-ports]="ss -tulpen"
  [established-conns]="ss -tanp state established | head -n 50"
  [world-writable-dirs]="find / -type d -perm -0002 -maxdepth 2 2>/dev/null | head -n 200"
  [last-logins]="last -n 20"
  [lastb-failures]="lastb -n 20 || true"

  [pid-summary-proc]='ps -p '"$PID"' -o pid,ppid,user,%cpu,%mem,etime,stat,cmd'
  [threads-cpu-proc]='top -b -H -n 1 -p '"$PID"' | head -n 20'
  [limits-proc]='cat /proc/'"$PID"'/limits'
  [sched-proc]='cat /proc/'"$PID"'/sched'
)

for tag in "${!CMD_MAP[@]}"; do
  bash -c "${CMD_MAP[$tag]}" > "${BASE_DIR}/${tag}.txt" 2>&1 || true
done

exit 0
