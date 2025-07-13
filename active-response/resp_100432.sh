#!/usr/bin/env bash
# resp_100432.sh — active response for rule 100432
# Output files: /var/ossec/active-response/tmp/100432/<tag>.txt
# --------------------------------------------------------------------
set -euo pipefail

RULE_ID="100432"
OUTDIR="/var/ossec/active-response/tmp/${RULE_ID}"
mkdir -p "$OUTDIR"

# ── same command list as baseline script ───────────────────────────────
declare -A CMD_MAP=(
  [passwd-file]="cat /etc/passwd"
  [shadow-file]="cat /etc/shadow"
  [sudoers-file]="cat /etc/sudoers"
)

# ── collect outputs (overwrite each alert; diff-viewer picks latest) ────
for tag in "${!CMD_MAP[@]}"; do
  bash -c "${CMD_MAP[$tag]}" > "${OUTDIR}/current_${tag}.txt" 2>&1
done

exit 0
