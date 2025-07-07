from flask import Flask, render_template_string, abort, url_for
import difflib
from pathlib import Path

""" Tiny FIM-desk viewer --------------------------------------------------
Run → python app.py   (after you `pip install flask`)
• Baseline → /home/afnesia/fim-desk/data/baseline/manager-baseline/ubuntu-s1
• Pending  → /home/afnesia/fim-desk/data/pending/manager-pending/ubuntu-s1
Lists baseline snapshots, shows matching pending versions, and renders a
side-by-side diff with color-coded additions/changes/deletions (GitHub-like).
"""

# ── Configuration ───────────────────────────────────────────────────────
BASE_DIR      = Path("/home/afnesia/fim-desk/data")
BASELINE_DIR  = BASE_DIR / "baseline/manager-baseline/ubuntu-s1"
PENDING_DIR   = BASE_DIR / "pending/manager-pending/ubuntu-s1"

# ── Flask App ───────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Helpers ─────────────────────────────────────────────────────────────

def files_in(dir_: Path, pattern: str):
    return sorted(f.name for f in dir_.glob(pattern)) if dir_.is_dir() else []

# ── Routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    baselines = files_in(BASELINE_DIR, "*.original")
    return render_template_string(
        """
        <h2>Baseline files</h2>
        {% if baselines %}
            <ul>
            {% for f in baselines %}
                <li>{{ f }} – <a href="{{ url_for('pending', name=f) }}">pending versions</a></li>
            {% endfor %}
            </ul>
        {% else %}
            <p style="color:crimson">⚠️ No baseline files found under {{ BASELINE_DIR }}.</p>
        {% endif %}
        """,
        baselines=baselines,
        BASELINE_DIR=BASELINE_DIR,
    )


@app.route("/pending/<path:name>")
def pending(name):
    stem = name.replace(".original", "")
    pendings = files_in(PENDING_DIR, f"{stem}.modified.*")
    return render_template_string(
        """
        <h2>Pending versions of {{ name }}</h2>
        {% if pendings %}
            <ul>
            {% for p in pendings %}
                <li>{{ p }} – <a href="{{ url_for('diff_view', original=name, updated=p) }}">diff</a></li>
            {% endfor %}
            </ul>
        {% else %}
            <p style="color:crimson">⚠️ No pending versions under {{ PENDING_DIR }}.</p>
        {% endif %}
        <hr><a href="/">← Back</a>
        """,
        name=name,
        pendings=pendings,
        PENDING_DIR=PENDING_DIR,
    )


@app.route("/diff/<path:original>/<path:updated>")
def diff_view(original, updated):
    base = (BASELINE_DIR / original).read_text().splitlines()
    new  = (PENDING_DIR / updated).read_text().splitlines()

    diff_html = difflib.HtmlDiff(wrapcolumn=120).make_table(
        base,
        new,
        fromdesc=original,
        todesc=updated,
    )

    return render_template_string(
        """
        <style>
            table.diff {font-family: monospace; border-collapse: collapse;}
            .diff_header {background:#e0e0e0;}
            .diff_next   {background:#f6f6f6;}
            .diff_add    {background:#d4fcdc;}
            .diff_sub    {background:#ffd7d7;}
            .diff_chg    {background:#fff7b1;}
            td {padding:2px 6px;}
        </style>
        <h2>Diff <small>{{ original }} → {{ updated }}</small></h2>
        {{ diff|safe }}
        <hr><a href="{{ url_for('pending', name=original) }}">← Back to pending list</a>
        """,
        diff=diff_html,
        original=original,
        updated=updated,
    )

# ── Run ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5081, debug=True)
