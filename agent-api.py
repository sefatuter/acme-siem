#!/usr/bin/env python3
import os
from flask import Flask, jsonify, send_from_directory, abort, request

BASE_PENDING  = "/var/ossec/queue/pending-changes"
BASE_BASELINE = "/var/ossec/queue/baseline"

app = Flask(__name__)

@app.route("/pending/", methods=["GET"])
def list_pending():
    files = [f for f in os.listdir(BASE_PENDING)
             if os.path.isfile(os.path.join(BASE_PENDING, f))]
    return jsonify(files)

@app.route("/pending/<path:filename>", methods=["GET"])
def download(filename):
    # Simple safety check to block `../../../etc/passwd`
    if "/" in filename or filename.startswith(".."):
        abort(400)
    return send_from_directory(BASE_PENDING, filename, as_attachment=True)

# ── baseline originals ─────────────────────────────────────
@app.route("/baseline/", methods=["GET"])
def list_baseline():
    # recurse because baseline may hold sub-dirs
    out = []
    for root, _, files in os.walk(BASE_BASELINE):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), BASE_BASELINE)
            out.append(rel)
    return jsonify(out)

@app.route("/baseline/<path:filename>", methods=["GET"])
def download_baseline(filename):
    if filename.startswith(".."):
        abort(400)
    return send_from_directory(BASE_BASELINE, filename, as_attachment=True)

@app.route("/baseline/<path:filename>", methods=["PUT"])
def upload_baseline(filename):
    if filename.startswith(".."):
        abort(400)
    dst = os.path.join(BASE_BASELINE, filename)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with open(dst, "wb") as f:
        f.write(request.data)
    return ("", 204)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5080)
