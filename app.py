#!/usr/bin/env python3
"""
Rule-aware diff dashboard for Wazuh FIM baseline vs. current copies.
Start:  python3 app.py
Browse: http://127.0.0.1:5081
"""
from flask import Flask, render_template, abort, url_for
from pathlib import Path
import difflib, os, re
from datetime import datetime

BASELINE_ROOT = Path("/var/ossec/baselines")
CURRENT_ROOT  = Path("/var/ossec/active-response/tmp")
PORT = 5081

# Rule metadata - descriptions and timestamps
RULE_METADATA = {
    "100410": {
        "description": "Process consuming excessive CPU resources",
        "level": 10,
        "group": "cpu_monitor"
    },
    "100150": {
        "description": "FIM: Executable file detected in temporary directory",
        "level": 10,
        "group": "file_integrity"
    },
    "100432": {
        "description": "Critical system file modified",
        "level": 12,
        "group": "file_integrity,system_config"
    }
}

# File metadata - descriptions for each file type
FILE_METADATA = {
    "ls-tmp-tree.txt": {
        "description": "Recursive listing of /tmp directory contents with detailed file attributes (ls -lapR /tmp | head -n 400)",
        "category": "filesystem"
    },
    "proc-tree.txt": {
        "description": "Process tree showing running processes with hierarchy and resource usage (ps -auxwf | head -n 60)",
        "category": "process"
    },
    "find-tmp-new.txt": {
        "description": "Recently modified files in /tmp directory within last 24 hours (sudo find /tmp -xdev -type f -mtime -1 -ls)",
        "category": "security"
    },
    "audit-tmp.txt": {
        "description": "Audit trail of file access events in /tmp directory (sudo ausearch -f /tmp/* | aureport -i)",
        "category": "security"
    },
    "procs-from-tmp.txt": {
        "description": "Processes with current working directory in /tmp (ls -alR /proc/*/cwd | grep '/tmp')",
        "category": "security"
    },
    "netstat-ports.txt": {
        "description": "Network connections and listening ports with process information (ss -tulpen)",
        "category": "network"
    },
    "cron-jobs.txt": {
        "description": "User cron jobs and systemd timers for scheduled task monitoring (crontab -l; systemctl list-timers)",
        "category": "system"
    },
    "auth-last20.txt": {
        "description": "Last 20 user login sessions and authentication events (last -n 20)",
        "category": "security"
    },
    "tmp-files.txt": {
        "description": "List of files currently present in /tmp directory for baseline comparison",
        "category": "filesystem"
    },
    "established-conns.txt": {
        "description": "Currently established network connections and their process associations",
        "category": "network"
    },
    "cron-system.txt": {
        "description": "System-wide cron jobs and scheduled tasks from /etc/cron.* directories",
        "category": "system"
    },
    "top-cpu-procs.txt": {
        "description": "Top processes consuming CPU resources sorted by usage percentage",
        "category": "process"
    },
    "listening-ports.txt": {
        "description": "Network ports in listening state with associated processes and services",
        "category": "network"
    },
    "world-writable-dirs.txt": {
        "description": "World-writable directories that could pose security risks",
        "category": "security"
    },
    "uid0-users.txt": {
        "description": "Users with UID 0 (root privileges) from /etc/passwd",
        "category": "security"
    },
    "running-services.txt": {
        "description": "Currently running system services and their status",
        "category": "system"
    },
    "cron-all-users.txt": {
        "description": "Cron jobs for all users including user-specific crontabs",
        "category": "system"
    },
    "passwd-file.txt": {
        "description": "System user accounts and their configuration from /etc/passwd",
        "category": "security"
    },
    "shadow-file.txt": {
        "description": "Password hashes and account security settings from /etc/shadow",
        "category": "security"
    },
    "sudoers-file.txt": {
        "description": "Sudo privileges and access control configuration from /etc/sudoers",
        "category": "security"
    }
}

# Critical system files that should be flagged for any change
CRITICAL_SYSTEM_FILES = {
    "passwd",
    "shadow",
    "sudoers",
    "sudoers-config.txt",
    "shadow-audit.txt",
    "passwd-changes.txt",
    "group",
    "gshadow",
    "hosts",
    "hosts.allow",
    "hosts.deny",
    "ssh_config",
    "sshd_config",
    "authorized_keys"
}

app = Flask(__name__)

# ── helpers ─────────────────────────────────────────────────────────────
def rule_dirs():
    """Return set of rule-IDs that exist in both roots."""
    bl = {p.name for p in BASELINE_ROOT.iterdir() if p.is_dir()}
    cu = {p.name for p in CURRENT_ROOT.iterdir() if p.is_dir()}
    return sorted(bl & cu)

def get_rule_metadata(rule_id):
    """Return metadata for a rule ID with automatic timestamp from files."""
    base_metadata = RULE_METADATA.get(rule_id, {
        "description": f"Rule {rule_id} - No description available",
        "level": "Unknown",
        "group": "unknown"
    })
    
    # Get the latest timestamp from files in this rule's directories
    latest_timestamp = "No timestamp"
    
    try:
        # Check both baseline and current directories for the latest file
        latest_time = 0
        
        # Check baseline directory
        base_dir = BASELINE_ROOT / rule_id
        if base_dir.exists() and base_dir.is_dir():
            for file_path in base_dir.iterdir():
                if file_path.is_file():
                    file_time = file_path.stat().st_mtime
                    latest_time = max(latest_time, file_time)
        
        # Check current directory
        current_dir = CURRENT_ROOT / rule_id
        if current_dir.exists() and current_dir.is_dir():
            for file_path in current_dir.iterdir():
                if file_path.is_file():
                    file_time = file_path.stat().st_mtime
                    latest_time = max(latest_time, file_time)
        
        # Convert to readable format
        if latest_time > 0:
            from datetime import datetime
            latest_timestamp = datetime.fromtimestamp(latest_time).strftime("%Y-%m-%d %H:%M:%S")
    
    except Exception:
        latest_timestamp = "Unable to read timestamp"
    
    # Add timestamp to metadata
    result = base_metadata.copy()
    result["timestamp"] = latest_timestamp
    return result

def get_file_metadata(filename):
    """Return metadata for a file."""
    return FILE_METADATA.get(filename, {
        "description": f"File analysis data: {filename}",
        "category": "unknown"
    })

def get_rules_with_metadata():
    """Return list of tuples (rule_id, metadata) for all available rules."""
    rules = rule_dirs()
    return [(rule_id, get_rule_metadata(rule_id)) for rule_id in rules]

def get_pairs_with_metadata(rule_id):
    """Return list of (logical_name, baseline_path, current_path, file_metadata)"""
    base_dir = BASELINE_ROOT / rule_id
    cur_dir  = CURRENT_ROOT  / rule_id
    if not (base_dir.is_dir() and cur_dir.is_dir()):
        return []
    pairs = []
    for cur in cur_dir.glob("current_*"):
        logical = cur.name.removeprefix("current_")
        base = base_dir / logical
        if base.exists():
            file_metadata = get_file_metadata(logical)
            pairs.append((logical, base, cur, file_metadata))
    return pairs

def get_pairs(rule_id):
    """Return list of (logical_name, baseline_path, current_path)"""
    base_dir = BASELINE_ROOT / rule_id
    cur_dir  = CURRENT_ROOT  / rule_id
    if not (base_dir.is_dir() and cur_dir.is_dir()):
        return []
    pairs = []
    for cur in cur_dir.glob("current_*"):
        logical = cur.name.removeprefix("current_")
        base = base_dir / logical
        if base.exists():
            pairs.append((logical, base, cur))
    return pairs

def file_changed(baseline: Path, current: Path) -> tuple:
    """
    Check if file has changed.
    Returns (is_changed, is_critical)
    """
    try:
        baseline_content = baseline.read_text(encoding='utf-8', errors='ignore')
        current_content = current.read_text(encoding='utf-8', errors='ignore')
    except:
        # If we can't read as text, fall back to binary comparison
        baseline_content = baseline.read_bytes().decode('utf-8', errors='ignore')
        current_content = current.read_bytes().decode('utf-8', errors='ignore')
    
    # Check if this is a critical system file
    filename = baseline.name
    is_critical = filename in CRITICAL_SYSTEM_FILES
    
    # Simple binary comparison
    is_changed = baseline_content != current_content
    
    return is_changed, is_critical

def html_diff(baseline: Path, current: Path) -> str:
    """Generate HTML side-by-side diff table using difflib.HtmlDiff."""
    try:
        with baseline.open(encoding='utf-8', errors='ignore') as f1:
            baseline_lines = f1.readlines()
        with current.open(encoding='utf-8', errors='ignore') as f2:
            current_lines = f2.readlines()
    except:
        # Fallback for binary files
        baseline_lines = [baseline.read_bytes().decode('utf-8', errors='ignore')]
        current_lines = [current.read_bytes().decode('utf-8', errors='ignore')]

    # Check if files are identical
    if baseline_lines == current_lines:
        return '<div class="no-changes">Files are identical</div>'

    # Create side-by-side diff table
    differ = difflib.HtmlDiff(tabsize=4, wrapcolumn=120)
    table = differ.make_table(
        baseline_lines,
        current_lines,
        fromdesc=f"Baseline ({baseline.name})",
        todesc=f"Current ({current.name})",
        context=True,
        numlines=3
    )
    
    return table


# ── routes ──────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return render_template("root.html", rules_with_metadata=get_rules_with_metadata())

@app.route("/<rid>/")
def rule_index(rid):
    pairs = get_pairs_with_metadata(rid)
    if not pairs:
        abort(404, "rule ID not found")
    
    data = []
    for name, baseline_path, current_path, file_meta in pairs:
        is_changed, is_critical = file_changed(baseline_path, current_path)
        data.append((name, is_changed, file_meta, is_critical))
    
    rule_metadata = get_rule_metadata(rid)
    return render_template("rule.html", rid=rid, files=data, rule_metadata=rule_metadata)

@app.route("/<rid>/diff/<logical>")
def show_diff(rid, logical):
    base = BASELINE_ROOT / rid / logical
    cur  = CURRENT_ROOT  / rid / f"current_{logical}"
    if not (base.exists() and cur.exists()):
        abort(404, "file pair not found")
    rule_metadata = get_rule_metadata(rid)
    file_metadata = get_file_metadata(logical)
    return render_template("diff.html",
                                  rid=rid, logical=logical,
                                  table=html_diff(base, cur),
                                  rule_metadata=rule_metadata,
                                  file_metadata=file_metadata)

# ── main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not (BASELINE_ROOT.is_dir() and CURRENT_ROOT.is_dir()):
        print("ERROR: baseline or current root missing.")
        os._exit(1)
    print(f"Serving diff dashboard on http://127.0.0.1:{PORT}/ …")
    app.run(host="0.0.0.0", port=PORT)
