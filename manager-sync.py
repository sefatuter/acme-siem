#!/usr/bin/env python3
"""
manager-sync.py  —  Copy *all* FIM data from each agent to the manager.

For every agent in AGENTS it replicates:

    /var/ossec/active-response/tmp/   →  /var/ossec/active-response/tmp/
    /var/ossec/baselines/             →  /var/ossec/baselines/

All nested rule-ID folders come along unchanged, so the manager ends up with an
identical tree.  Requirements are still just rsync + key-based SSH.
"""

import pathlib, subprocess, sys, time

# ── agents to pull from ─────────────────────────────────────────────────
AGENTS = [
    ("root", "10.128.0.11", "ubuntu-s1"),
    # ("root", "10.128.0.12", "agent-2"),
]

# ── fixed paths ────────────────────────────────────────────────────────
REMOTE_PENDING_ROOT  = "/var/ossec/active-response/tmp/"   # trailing slash ⚠
REMOTE_BASELINE_ROOT = "/var/ossec/baselines/"             # trailing slash ⚠

LOCAL_PENDING_ROOT   = pathlib.Path("/var/ossec/active-response/tmp")
LOCAL_BASELINE_ROOT  = pathlib.Path("/var/ossec/baselines")

# ── rsync options ──────────────────────────────────────────────────────
RSYNC = [
    "rsync",
    "-az",          # archive + compress
    "--delete",     # remove local files that vanished on the agent
    "--chmod=F644", # sane perms
]

def rsync_one(user, host, src, dest):
    cmd = RSYNC + [f"{user}@{host}:{src}", str(dest)]
    return subprocess.run(cmd, capture_output=True, text=True)

def sync_agent(user, host, label):
    print(f"\n=== {label} ({host}) ===")
    t0 = time.time()

    for src, dest in (
        (REMOTE_PENDING_ROOT,  LOCAL_PENDING_ROOT),
        (REMOTE_BASELINE_ROOT, LOCAL_BASELINE_ROOT),
    ):
        dest.mkdir(parents=True, exist_ok=True)
        res = rsync_one(user, host, src, dest)
        if res.returncode == 0:
            transferred = len(res.stdout.strip().splitlines())
            print(f" ✓ {src} → {dest}  ({transferred} items)")
        else:
            print(f" ✗ {src} – {res.stderr.strip()}")
    print(f"done in {time.time() - t0:.1f}s")

def main():
    if subprocess.call(["which", "rsync"], stdout=subprocess.DEVNULL):
        sys.exit("ERROR: rsync not found; install it first.")

    overall = time.time()
    for user, host, label in AGENTS:
        sync_agent(user, host, label)
    print(f"\nAll agents finished in {time.time() - overall:.1f}s")

if __name__ == "__main__":
    main()
