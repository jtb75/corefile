#!/usr/bin/env python3
"""
Mock cloud instance-metadata service — SSRF demo target (loopback only).

This stands in for the link-local metadata endpoint that a real cloud VM/pod
exposes at 169.254.169.254 (a.k.a. metadata.google.internal). On a laptop you
can't reach that address, so this mock lets the SSRF exploit land live during a
customer meeting: Corefile's /api/fetch is pointed here, and it walks back a
(fake) service-account token exactly as it would from real cloud metadata.

Everything it returns is a randomly-shaped FAKE. No value maps to a real
account or grants any access. Run on localhost only.

    python3 demo/ssrf/metadata_mock.py            # binds 127.0.0.1:8081

It mirrors GCP's layout (the header-gated /computeMetadata/v1 tree) AND AWS
IMDSv1 (/latest/meta-data/...), so one mock covers whichever cloud you're
narrating. The GCP tree checks for the 'Metadata-Flavor: Google' header the
way the real service does — flip STRICT_HEADER below if you want the demo to
show that gate instead of ignoring it.
"""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST, PORT = "127.0.0.1", 8081

# Real GCP metadata refuses requests lacking `Metadata-Flavor: Google`. A pure
# URL-only SSRF (like Corefile's /api/fetch) can't set that header, so for a
# laptop demo we default to NOT enforcing it — the exploit just works. Set this
# to True to make the demo tell the more nuanced GCP story (see RUNBOOK.md).
STRICT_HEADER = False

# --- clearly-fake spoils the SSRF walks back -------------------------------
FAKE_SA_EMAIL = "corefile-forensics@corefile-demo.iam.gserviceaccount.com"
FAKE_TOKEN = {
    # ya29.* is the real GCP access-token shape; this value is invented.
    "access_token": "ya29.DEMO-FAKE-DO-NOT-USE-a1B2c3D4e5F6g7H8i9J0kLmNoPqRsTuVwXyZ",
    "expires_in": 3599,
    "token_type": "Bearer",
}
# AWS IMDSv1 role-credential shape (also fake).
FAKE_AWS_CREDS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "ASIA-DEMO-FAKE-EXAMPLE01",
    "SecretAccessKey": "DEMOfakeSecret/EXAMPLEkeyNOTreal0000000000",
    "Token": "DEMO-FAKE-SESSION-TOKEN-not-a-real-credential",
    "Expiration": "2099-01-01T00:00:00Z",
}

# GCP tree: path -> body (str or dict; dict is JSON-encoded).
GCP = {
    "/computeMetadata/v1/": "instance/\nproject/\n",
    "/computeMetadata/v1/instance/service-accounts/": "default/\n",
    "/computeMetadata/v1/instance/service-accounts/default/": "email\nscopes\ntoken\n",
    "/computeMetadata/v1/instance/service-accounts/default/email": FAKE_SA_EMAIL,
    "/computeMetadata/v1/instance/service-accounts/default/scopes": (
        "https://www.googleapis.com/auth/cloud-platform\n"
    ),
    "/computeMetadata/v1/instance/service-accounts/default/token": FAKE_TOKEN,
    "/computeMetadata/v1/project/project-id": "corefile-demo",
}

# AWS IMDSv1 tree (no header required, like the real thing).
AWS = {
    "/latest/meta-data/iam/security-credentials/": "corefile-forensics-role\n",
    "/latest/meta-data/iam/security-credentials/corefile-forensics-role": FAKE_AWS_CREDS,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "GoogleFrontEnd/mock"

    def _send(self, code, body, ctype="text/plain"):
        if isinstance(body, (dict, list)):
            body, ctype = json.dumps(body, indent=2), "application/json"
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Metadata-Flavor", "Google")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        # AWS IMDSv1 — never header-gated.
        if path in AWS:
            return self._send(200, AWS[path])

        # GCP — optionally header-gated, like the real metadata server.
        if path in GCP:
            if STRICT_HEADER and self.headers.get("Metadata-Flavor") != "Google":
                return self._send(
                    403,
                    "Missing Metadata-Flavor:Google header.\n",
                )
            return self._send(200, GCP[path])

        if path == "/":
            return self._send(
                200,
                "mock instance-metadata service (SSRF demo target)\n"
                "try: /computeMetadata/v1/instance/service-accounts/default/token\n"
                "     /latest/meta-data/iam/security-credentials/\n",
            )
        return self._send(404, "not found\n")

    def log_message(self, fmt, *args):
        # Loud logging so the room can watch the SSRF requests arrive.
        print(f"[metadata-mock] {self.address_string()} -> {self.path}")


if __name__ == "__main__":
    print(f"[metadata-mock] listening on http://{HOST}:{PORT}  (STRICT_HEADER={STRICT_HEADER})")
    print("[metadata-mock] this is a FAKE target for the SSRF demo — loopback only, Ctrl-C to stop")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
