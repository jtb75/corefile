# Planted findings — corefile.io demo

Every item here is **deliberate**. This app is a SAST/pipeline demonstration
target. Credentials are randomly generated, non-functional values that match
real formats so a secret scanner flags them — none map to a real account. Do
not deploy this app.

## A. Confirmed by `wizcli scan dir` (5 × HIGH → `WARN_BY_POLICY`)

These are what a live scan lands on. The **Security findings** tab in the UI
mirrors this table one-to-one.

| # | Type | Wiz rule | CWE | Location | Feature |
|---|------|----------|-----|----------|---------|
| 1 | SAST | `WS-I013-PYTHON-00193` | CWE-78 (OS command injection) | `symbolicate.py:42` | Symbolicate corefile |
| 2 | SAST | `WS-PYTHON-00330` | CWE-89 (SQL injection) | `app.py:130` | Crash-signature search |
| 3 | SAST | `WS-I013-PYTHON-00054` | CWE-95 (code injection / `eval`) | `app.py:166` | Derived metric |
| 4 | Secret | GitHub Classic PAT | — | `config.py:15` | Integration config |
| 5 | Secret | GitHub Classic PAT | — | `Dockerfile:7` | Image build ARG |

Reproduce:

```bash
wizcli scan dir "$(pwd)" --no-publish --by-policy-hits="AUDIT"
```

(`--no-publish` keeps the scan out of the Wiz portal; `--by-policy-hits=AUDIT`
reveals the detail tables, which the default `BLOCK` view suppresses.)

## B. Present in the app, NOT flagged by Wiz's current Python ruleset

Left in on purpose — they make the "one scanner isn't enough; you need layered
coverage (SCA, secret validation, DAST, review)" point, and any of them may
start flagging as rulesets evolve.

| Class | CWE | Location | Note |
|-------|-----|----------|------|
| Insecure deserialization | CWE-502 | `app.py` `/api/parse` | `pickle.loads` on request input — not in the current ruleset |
| Path traversal | CWE-22 | `app.py` `/api/corefile` | `open(DIR + "/" + name)` — not flagged |
| Weak hashing | CWE-327 | `app.py` `/api/fingerprint` | `hashlib.md5` — detected as low/informational at most |
| Broken access control | CWE-284 | `app.py` `/api/cases/<id>` | `?org=` / `X-Role` trust + `?debug=1` backdoor — a runtime/DAST finding, not static |
| Extra hardcoded secrets | CWE-798 | `config.py` | AWS key, Slack token, Sentry DSN, Postgres password, and the Flask `SECRET_KEY` (session-signing key → cookie forgery) — detected but below the secrets policy's HIGH bar (GitHub PATs are the reliable hit) |

## C. Private area — authenticated findings (Analyst Console)

The `/login` → `/private` area exists to demonstrate weaknesses that **only an
authenticated scan (or a source-aware review) can reach** — an anonymous scanner
sees a login wall and nothing else. Authentication here is deliberately *correct*
(salted `werkzeug` password hashing, signed server-side sessions); the planted
flaw is **authorization**.

| # | Class | CWE | Location | Note |
|---|-------|-----|----------|------|
| 8 | IDOR / Broken Object Level Auth (BOLA, OWASP API1) | CWE-639 | `app.py` `/api/account/<uid>/integrations` | Login enforced, ownership never checked → any analyst reads any other analyst's stored cloud tokens (incl. cross-org) |
| 8b | IDOR on profile | CWE-639 | `app.py` `/api/account/<uid>` | Same missing ownership check |
| 9 | IDOR on private case notes | CWE-639 | `app.py` `/api/console/cases/<id>` | Any logged-in analyst reads any case body regardless of owning org |

Demo accounts (password `corefile` for all): `arivera@acme-checkout.io` (u-1001),
`dpatel@acme-checkout.io` (u-1002), `controller@esa-launch.int` (u-2001, admin).

The `/private` page looks like an ordinary **Integrations** settings screen: it
shows only the logged-in analyst's own API keys, partially masked. Two things
make it a realistic BOLA demo:

- The page loads keys via `GET /api/account/<uid>/integrations`, always asking
  for its *own* uid — but the endpoint never checks ownership, so tampering the
  uid (in a proxy, or an authenticated scan) returns another analyst's keys.
- The masking is **cosmetic**: the full token is already in the JSON response
  and behind the client-side "Reveal" toggle, so it's not a security control.

To run an authenticated scan against this area, hand the scanner a valid
`session` cookie (log in, copy the cookie, set it as a request header in Wiz
DAST / Burp / ZAP).

Note: `/console` is **not** this app's page — with `debug=True` it's Werkzeug's
interactive debugger console (PIN-gated RCE). The private area lives at `/private`.

## Runtime demos (loopback only)

```bash
# Broken access control — read any org's case, self-elevate to admin
curl 'http://127.0.0.1:8000/api/cases/flight-501?org=anyone&debug=1'

# SQL injection — break out of the LIKE clause
curl "http://127.0.0.1:8000/api/signatures?q=%25'--"

# Path traversal — read a file outside dumps/
curl --path-as-is 'http://127.0.0.1:8000/api/corefile?name=../config.py'

# IDOR / BOLA — log in as one analyst, read another's private tokens
curl -s -c /tmp/cj.txt -d email=arivera@acme-checkout.io -d password=corefile \
  http://127.0.0.1:8000/login
curl -s -b /tmp/cj.txt http://127.0.0.1:8000/api/account/u-2001/integrations
```
