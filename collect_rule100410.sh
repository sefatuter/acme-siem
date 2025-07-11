#!/bin/sh
# collect_rule100410.sh – POSIX version (works under /bin/sh)
set -eu

AGENT_RULE_ID="100410"
BASE_DIR="/var/ossec/baselines/${AGENT_RULE_ID}"
mkdir -p "${BASE_DIR}"

# command list:  tag|actual command
COMMANDS="
running-services|systemctl list-units --type=service --state=running
top-cpu-procs|ps axo %cpu,pid,ppid,user,etime,cmd --sort=-%cpu | head -n 25
listening-ports|ss -tulpen
established-conns|ss -tanp state established | head -n 50
world-writable-dirs|find / -type d -perm -0002 -maxdepth 2 2>/dev/null | head -n 200
uid0-users|awk -F: '(\$3==0){print}' /etc/passwd
cron-system|systemctl list-timers --all --no-pager
cron-all-users|for u in \$(cut -d: -f1 /etc/passwd); do echo \"# \$u\"; crontab -u \"\$u\" -l 2>/dev/nul>
last-logins|last -n 20
lastb-failures|lastb -n 20 || true
kernel-mods|lsmod
uptime|uptime
dmesg-new|dmesg | tail -n 40
"

echo "$COMMANDS" | while IFS='|' read -r tag cmd; do
  # skip empty lines
  [ -z "$tag" ] && continue
  sh -c "$cmd" > "${BASE_DIR}/${tag}.txt" 2>&1
done
