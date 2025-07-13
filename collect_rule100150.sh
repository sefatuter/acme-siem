#!/usr/bin/env bash
# collect_rule100150.sh — baseline snapshot for rule 100150
# Creates:  /var/ossec/baselines/100150/<tag>.txt
# --------------------------------------------------------------------
set -euo pipefail

RULE_ID="100150"
BASE_DIR="/var/ossec/baselines/${RULE_ID}"
mkdir -p "$BASE_DIR"

# ── commands to capture ────────────────────────────────────────────────
declare -A CMD_MAP=(
  [proc-tree]="ps auxwf | head -n 60"
  [find-tmp-new]="find /tmp -xdev -type f -mtime -1 -ls | sort -k10,11"
  [procs-from-tmp]="ls -alR /proc/*/cwd 2>/dev/null | grep '/tmp' | head -n 100"
  [auth-last20]="last -n 20"
  [tmp-files]="ls /tmp/"
)

# ── run each command, ignore benign non-zero exits ─────────────────────
for tag in "${!CMD_MAP[@]}"; do
  bash -c "${CMD_MAP[$tag]}" > "${BASE_DIR}/${tag}.txt" 2>&1
done

exit 0
