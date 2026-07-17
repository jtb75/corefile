"""
Corefile — crash-dump forensics, from cloud resource back to the offending line.

============================ DEMO / SAFETY NOTICE ============================
This application is INTENTIONALLY VULNERABLE. It exists to demonstrate a secure
coding pipeline: a SAST scanner run against this repository should flag every
weakness planted below. The vulns are mapped to believable product features so
the findings feel narratively inevitable during a live demo.

Run it on localhost only. Never deploy it. See SECURITY_DEMO.md for the full
catalogue of planted findings and their file:line locations.
=============================================================================
"""

import os
import json
import sqlite3
import pickle
import hashlib
import base64

from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    send_file,
    abort,
)

import config
from symbolicate import symbolicate_request

app = Flask(__name__)

BASE = os.path.dirname(os.path.abspath(__file__))
DUMPS_DIR = os.path.join(BASE, "dumps")


# --------------------------------------------------------------------------
# Database bootstrap (in-memory-ish sqlite seeded from data/seed.json)
# --------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS cases;
        DROP TABLE IF EXISTS signatures;
        CREATE TABLE cases (id TEXT PRIMARY KEY, org TEXT, title TEXT, body TEXT);
        CREATE TABLE signatures (id INTEGER PRIMARY KEY, module TEXT, func TEXT, note TEXT);
        """
    )
    seed_path = os.path.join(BASE, "data", "seed.json")
    with open(seed_path) as fh:
        seed = json.load(fh)
    for c in seed["cases"]:
        conn.execute(
            "INSERT INTO cases VALUES (?,?,?,?)",
            (c["id"], c["org"], c["title"], c["body"]),
        )
    for i, s in enumerate(seed["signatures"]):
        conn.execute(
            "INSERT INTO signatures VALUES (?,?,?,?)",
            (i, s["module"], s["func"], s["note"]),
        )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.errorhandler(404)
def segfault(_e):
    # Easter egg: the classic core-dump message as a 404.
    return render_template("404.html"), 404


# --------------------------------------------------------------------------
# API — each endpoint is a believable feature with a planted weakness.
# --------------------------------------------------------------------------

# VULN 1 — Broken access control / auth bypass.
# /api/cases/<id> trusts a client-supplied ?org= and an X-Role header, and
# honours a ?debug=1 backdoor. It never checks that the caller owns the case.
@app.route("/api/cases/<case_id>")
def get_case(case_id):
    requested_org = request.args.get("org", "public")
    role = request.headers.get("X-Role", "viewer")
    if request.args.get("debug") == "1":
        role = "admin"  # backdoor: anyone can self-elevate

    conn = get_db()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    if row is None:
        abort(404)

    # No ownership check: the record is returned no matter which org asked.
    return jsonify(
        {
            "id": row["id"],
            "org": row["org"],
            "title": row["title"],
            "body": row["body"],
            "viewer_role": role,
            "requested_as_org": requested_org,
        }
    )


# VULN 2 — SQL injection.
# Crash-signature search concatenates the query straight into SQL.
@app.route("/api/signatures")
def search_signatures():
    q = request.args.get("q", "")
    conn = get_db()
    sql = "SELECT module, func, note FROM signatures WHERE module LIKE '%" + q + "%'"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# VULN 3 — OS command injection (sink lives in symbolicate.py:42).
# "Symbolicate corefile" shells out to addr2line with user-controlled input.
@app.route("/api/symbolicate")
def api_symbolicate():
    try:
        frame = symbolicate_request()
    except Exception:  # noqa: BLE001 — addr2line may be absent on the demo host
        frame = "checkout-api!retry_payment at checkout-api.c:118"
    return jsonify({"frame": frame})


# VULN 4 — Path traversal.
# Download the raw corefile by name; ../ escapes the dumps directory.
@app.route("/api/corefile")
def download_corefile():
    name = request.args.get("name", "latest.core")
    path = DUMPS_DIR + "/" + name
    with open(path) as fh:
        return fh.read()


# VULN 5 — Insecure deserialization.
# "Parse" an uploaded corefile's metadata sidecar via pickle -> RCE on craft.
@app.route("/api/parse")
def parse_corefile():
    raw = request.args.get("meta", "")
    meta = pickle.loads(base64.b64decode(raw))
    return jsonify({"parsed": True, "meta": str(meta)})


# VULN 6 — Code injection.
# "Derived metric" evaluates a user-supplied expression against the dump stats.
@app.route("/api/metric")
def metric():
    expr = request.args.get("expr", "1+1")
    return jsonify({"expr": expr, "value": eval(expr)})


# VULN 7 — Weak hashing (MD5) used as a corefile integrity fingerprint.
@app.route("/api/fingerprint")
def fingerprint():
    data = request.args.get("data", "")
    digest = hashlib.md5(data.encode()).hexdigest()
    return jsonify({"fingerprint": digest})


if __name__ == "__main__":
    init_db()
    # debug=True is itself a finding (Werkzeug console / info leak) — fitting.
    app.run(host=config.HOST, port=config.PORT, debug=True)
