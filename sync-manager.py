#!/usr/bin/env python3
import pathlib, requests, time
import hashlib

AGENTS = [{"name": "ubuntu-s1", "url": "http://10.128.0.11:5080"}]

DEST_PENDING  = pathlib.Path("/var/ossec/queue/manager-pending")
DEST_BASELINE = pathlib.Path("/var/ossec/queue/manager-baseline")
CHUNK = 8192

LAST_SENT = {}                       # path → sha256  (lives only while script runs)
LAST_DIGEST = {}                     # agent → baseline-digest


# ------------------------------------------------------------------------
def sha256(path: pathlib.Path, block=65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(block), b""):
            h.update(chunk)
    return h.hexdigest()

# ---------- helpers ---------------------------------------------------------
def fetch_list(base_url, kind):
    return requests.get(f"{base_url}/{kind}/", timeout=10).json()

def download(base_url, kind, relpath, dest_root):
    dest = dest_root / relpath
    dest.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(f"{base_url}/{kind}/{relpath}", stream=True, timeout=30) as r:
        r.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(CHUNK):
                fh.write(chunk)
    return dest

def upload(base_url, kind, relpath, src_path):
    with open(src_path, "rb") as fh:
        r = requests.put(f"{base_url}/{kind}/{relpath}", data=fh, timeout=30)
        r.raise_for_status()


def sync_one(agent):
    base_url   = agent["url"].rstrip("/")
    agent_name = agent["name"]

    # 1. pull pending diffs  (unchanged)
    for f in fetch_list(base_url, "pending"):
        dest = DEST_PENDING / agent_name / f
        if not dest.exists():
            p = download(base_url, "pending", f, DEST_PENDING / agent_name)
            print(f"[+] {agent_name} diff  → {p}")

    # 2. pull baseline originals (only when digest changed)
    baseline_remote = []                              # ← guarantee it exists
    digest = requests.get(f"{base_url}/baseline-digest", timeout=5).text
    if LAST_DIGEST.get(agent_name) != digest:
        LAST_DIGEST[agent_name] = digest
        baseline_remote = fetch_list(base_url, "baseline")
        for f in baseline_remote:
            dest = DEST_BASELINE / agent_name / f
            if not dest.exists():
                p = download(base_url, "baseline", f,
                             DEST_BASELINE / agent_name)
                print(f"[+] {agent_name} base → {p}")

    # 3. push/refresh .original files (upload loop) --------------------------
    baseline_local = DEST_BASELINE / agent_name
    for path in baseline_local.rglob("*.original"):
        rel       = path.relative_to(baseline_local).as_posix()
        file_hash = sha256(path)
        if LAST_SENT.get((agent_name, rel)) == file_hash:
            continue
        upload(base_url, "baseline", rel, path)
        LAST_SENT[(agent_name, rel)] = file_hash
        print(f"[→] {agent_name} synced {rel}")

def main():
    while True:
        for a in AGENTS:
            try:
                sync_one(a)
            except Exception as e:
                print(f"[!] {a['name']}: {e}")
        time.sleep(30)

if __name__ == "__main__":
    main()
