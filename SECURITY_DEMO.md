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
| Extra hardcoded secrets | CWE-798 | `config.py` | AWS key, Slack token, Sentry DSN, Postgres password — detected but below the secrets policy's HIGH bar (GitHub PATs are the reliable hit) |

## Runtime demos (loopback only)

```bash
# Broken access control — read any org's case, self-elevate to admin
curl 'http://127.0.0.1:8000/api/cases/flight-501?org=anyone&debug=1'

# SQL injection — break out of the LIKE clause
curl "http://127.0.0.1:8000/api/signatures?q=%25'--"

# Path traversal — read a file outside dumps/
curl --path-as-is 'http://127.0.0.1:8000/api/corefile?name=../config.py'
```
