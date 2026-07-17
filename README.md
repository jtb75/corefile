# corefile.io

A demo app for showing off a secure coding pipeline: navigate to it during a
pitch, open a live incident, and trace a crash from a **cloud resource all the
way back to the offending line of code** — then flip to **Security findings**
and watch a SAST scanner catch the weaknesses planted in this very repository.

> Your stack traces, unstacked.

The conceit: **corefile** is a (fictional) crash-dump forensics service. A core
dump is what a program leaves behind when it dies (`Segmentation fault (core
dumped)`). The product walks that ugly runtime artifact backwards —
`aws_ecs_service` → ECS task → image digest → Dockerfile → commit/PR →
`symbolicate.py:42` — which is exactly the cloud-to-code story, dramatized.

## Run it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:8000
```

The database seeds itself on first run.

## What to click during a demo

1. Land on the **SIGSEGV in prod-checkout-api** incident (already in flight).
2. Hit **▶ Run trace** — the six-stage graph animates cloud → code. The last
   node lands on the planted command-injection in `symbolicate.py:42`; click it.
3. Click **View security findings** → the **Security findings** tab lists every
   planted weakness with its real `file:line`. Run *your* scanner against the
   repo and match it up.
4. **Provenance** tab has the build chain and a Ken Thompson easter egg.

Other incidents (`flight-501`, `fingerd`, the null-deref) are there for flavor.

## ⚠️ This app is intentionally vulnerable

It is a demonstration target, in the spirit of DVWA / OWASP Juice Shop. It binds
to `127.0.0.1` only. **Do not deploy it or expose it to a network.** The full
catalogue of planted findings lives in [SECURITY_DEMO.md](SECURITY_DEMO.md).

Easter eggs, for the people in the room who'll notice: the 404 page, the
`ulimit -c unlimited` toggle, the `flight-501` incident (Ariane 5, 1996), the
`fingerd` case (Morris Worm, 1988), `tls_heartbeat_read` (Heartbleed), the
"billion-dollar mistake" null-deref, and the Thompson quote in Provenance.
