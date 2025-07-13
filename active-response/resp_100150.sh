#!/usr/bin/env bash
# resp_100150.sh — active response for rule 100150
# Output files: /var/ossec/active-response/tmp/100150/<tag>.txt
# --------------------------------------------------------------------
set -euo pipefail

RULE_ID="100150"
OUTDIR="/var/ossec/active-response/tmp/${RULE_ID}"
mkdir -p "$OUTDIR"

# ── same command list as baseline script ───────────────────────────────
declare -A CMD_MAP=(
  [proc-tree]="ps auxwf | head -n 60"
  [find-tmp-new]="find /tmp -xdev -type f -mtime -1 -ls | sort -k10,11"
  [procs-from-tmp]="ls -alR /proc/*/cwd 2>/dev/null | grep '/tmp' | head -n 100"
  [auth-last20]="last -n 20"
  [tmp-files]="ls /tmp/"
)

# ── collect outputs (overwrite each alert; diff-viewer picks latest) ────
for tag in "${!CMD_MAP[@]}"; do
  bash -c "${CMD_MAP[$tag]}" > "${OUTDIR}/current_${tag}.txt" 2>&1
done

exit 0
