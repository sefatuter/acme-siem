#!/usr/bin/env python3
"""
Rule-aware diff dashboard for Wazuh FIM baseline vs. current copies.
Start:  python3 diff_dashboard.py
Browse: http://127.0.0.1:5081
"""
from flask import Flask, render_template, abort, url_for
from pathlib import Path
import difflib, os

BASELINE_ROOT = Path("/var/ossec/baselines")
CURRENT_ROOT  = Path("/var/ossec/active-response/tmp")
PORT = 5081

app = Flask(__name__)

# ── helpers ─────────────────────────────────────────────────────────────
def rule_dirs():
    """Return set of rule-IDs that exist in both roots."""
    bl = {p.name for p in BASELINE_ROOT.iterdir() if p.is_dir()}
    cu = {p.name for p in CURRENT_ROOT.iterdir() if p.is_dir()}
    return sorted(bl & cu)

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

def file_changed(baseline: Path, current: Path) -> bool:
    return baseline.read_bytes() != current.read_bytes()

def html_diff(baseline: Path, current: Path) -> str:
    with baseline.open() as f1, current.open() as f2:
        tbl = difflib.HtmlDiff(tabsize=4, wrapcolumn=120).make_table(
            f1.readlines(), f2.readlines(),
            fromdesc=f"Baseline ({baseline.name})",
            todesc=f"Current ({current.name})",
            context=True, numlines=5
        )
    return tbl


# ── routes ──────────────────────────────────────────────────────────────
@app.route("/")
def root():
    return render_template("root.html", rules=rule_dirs())

@app.route("/<rid>/")
def rule_index(rid):
    pairs = get_pairs(rid)
    if not pairs:
        abort(404, "rule ID not found")
    data = [(n, file_changed(b, c)) for n, b, c in pairs]
    return render_template("rule.html", rid=rid, files=data)

@app.route("/<rid>/diff/<logical>")
def show_diff(rid, logical):
    base = BASELINE_ROOT / rid / logical
    cur  = CURRENT_ROOT  / rid / f"current_{logical}"
    if not (base.exists() and cur.exists()):
        abort(404, "file pair not found")
    return render_template("diff.html",
                                  rid=rid, logical=logical,
                                  table=html_diff(base, cur))

# ── main ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not (BASELINE_ROOT.is_dir() and CURRENT_ROOT.is_dir()):
        print("ERROR: baseline or current root missing.")
        os._exit(1)
    print(f"Serving diff dashboard on http://127.0.0.1:{PORT}/ …")
    app.run(host="0.0.0.0", port=PORT)
