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
    redirect,
    url_for,
    session,
    send_file,
    abort,
)

import config
import auth
from symbolicate import symbolicate_request

app = Flask(__name__)
# Server-side signed sessions for the Analyst Console (key hardcoded in config).
app.secret_key = config.SECRET_KEY

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


# --------------------------------------------------------------------------
# Private area — the Analyst Console. Authentication is CORRECT here; the
# planted weakness is authorization (IDOR / BOLA). Login required, ownership
# never checked. An anonymous scan can't reach any of this; an authenticated
# one walks straight into another analyst's stored cloud tokens.
# --------------------------------------------------------------------------
def current_uid():
    return session.get("uid")


def require_login():
    # Authentication gate only. Deliberately does NOT check object ownership.
    if not current_uid():
        abort(401)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        acct = auth.authenticate(request.form.get("email"), request.form.get("password"))
        if acct is None:
            return render_template("login.html", error="Invalid credentials"), 401
        session["uid"] = acct["uid"]
        return redirect(url_for("console"))
    if current_uid():
        return redirect(url_for("console"))
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/private")
def console():
    require_login()
    me = auth.get_account(current_uid())
    # Roster of every analyst (non-sensitive fields) — clicking one triggers
    # the IDOR fetch below against that analyst's uid.
    roster = [auth.public_view(a) for a in auth.all_accounts() if a["uid"] != me["uid"]]
    return render_template("console.html", me=me, roster=roster)


# VULN 8 — IDOR / Broken Object Level Authorization (OWASP API1).
# Any *authenticated* caller can read ANY account's private integration tokens
# just by changing <uid>. Login is enforced and works; ownership is not.
@app.route("/api/account/<uid>/integrations")
def account_integrations(uid):
    require_login()                       # authN enforced...
    acct = auth.get_account(uid)          # ...but no authZ: never checks uid == session uid
    if acct is None:
        abort(404)
    return jsonify(
        {
            "uid": acct["uid"],
            "owner": acct["email"],
            "org": acct["org"],
            "integrations": acct["integrations"],  # another analyst's secrets
        }
    )


# VULN 8b — IDOR on the account profile (same missing ownership check).
@app.route("/api/account/<uid>")
def account_profile(uid):
    require_login()
    acct = auth.get_account(uid)
    if acct is None:
        abort(404)
    return jsonify(auth.public_view(acct))


# VULN 9 — IDOR on private case notes: any logged-in analyst can read any
# case's full body regardless of which org owns it.
@app.route("/api/console/cases/<case_id>")
def console_case(case_id):
    require_login()
    conn = get_db()
    row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    conn.close()
    if row is None:
        abort(404)
    return jsonify(
        {"id": row["id"], "org": row["org"], "title": row["title"], "body": row["body"]}
    )


if __name__ == "__main__":
    init_db()
    # debug=True is itself a finding (Werkzeug console / info leak) — fitting.
    app.run(host=config.HOST, port=config.PORT, debug=True)
