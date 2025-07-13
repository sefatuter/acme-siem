#!/usr/bin/env bash
# resp_100410.sh – quick-triage snapshot when rule 100410 fires
# Dumps into /var/ossec/active-response/tmp/100410/current_<tag>.txt
# ------------------------------------------------------------------
set -euo pipefail

RULE_ID="100410"
OUTDIR="/var/ossec/active-response/tmp/${RULE_ID}"
mkdir -p "${OUTDIR}"

# Consume alert JSON from Wazuh (not otherwise used, but must be read)
read -r _ || true

# ── command list: tag | actual command ────────────────────────────────
COMMANDS="
running-services|systemctl list-units --type=service --state=running
top-cpu-procs|ps axo %cpu,pid,ppid,user,etime,cmd --sort=-%cpu | head -n 25
listening-ports|ss -tulpen
established-conns|ss -tanp state established | head -n 50
world-writable-dirs|find / -type d -perm -0002 -maxdepth 2 2>/dev/null | head -n 200
uid0-users|awk -F: '(\$3==0){print}' /etc/passwd
cron-system|systemctl list-timers --all --no-pager
cron-all-users|for u in \$(cut -d: -f1 /etc/passwd); do echo \"# \$u\"; crontab -u \"\$u\" -l 2>/dev/null; done
last-logins|last -n 20
lastb-failures|lastb -n 20 || true
kernel-mods|lsmod
uptime|uptime
dmesg-new|dmesg | tail -n 40
"

# ── run each command and capture output ───────────────────────────────
while IFS='|' read -r tag cmd; do
  [ -z "${tag}" ] && continue            # skip blank lines
  bash -c "${cmd}" > "${OUTDIR}/current_${tag}.txt" 2>&1
done <<EOF
${COMMANDS}
EOF
