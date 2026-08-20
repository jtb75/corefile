"""
Corefile runtime configuration.

NOTE: Every credential below is a deliberately planted, NON-FUNCTIONAL demo
secret — randomly generated to match real formats so a secret scanner will flag
them, but not tied to any real account. See SECURITY_DEMO.md. Do not model real
config on this file, and never commit secrets like this in a real project.
"""

# --- Cloud / registry / integration credentials (INTENTIONALLY hardcoded) ---
AWS_ACCESS_KEY_ID = "AKIARWF99572U1DKWR68"
AWS_SECRET_ACCESS_KEY = "CJPwVpBrXRDq1DIgwgOtoU6nHXWbkV8GGo0jVV+I"

# Container registry / CI push token, checked straight into source.
GITHUB_TOKEN = "ghp_F97sHD7LuGAOtrMZNxTzk6nk43ZYae4ZdOY2"

# Crash-report ingestion + chat-ops integration.
SENTRY_DSN = "https://16c4c8ce79a0f4dd5dd30823317a6586@o899769.ingest.sentry.io/5862523"
SLACK_BOT_TOKEN = "xoxb-003076019876-212840857907-1t4KVojsnUC1jKR1NWKSklIV"

# Flask session signing key for the Analyst Console (server-side sessions).
# Hardcoding a session secret in source is itself a planted finding: anyone who
# reads it can forge signed session cookies. The console's headline weakness is
# still the IDOR in app.py — this is an incidental secret.
SECRET_KEY = "corefile-console-3f9a1c7e5b2d4860a1f6c9e2d7b3a4f8"

# --- Database ---
DB_PATH = "corefile.db"
# Connection string with an inline password (another planted finding).
DATABASE_URL = "postgres://corefile_svc:S3cr3t-pgp4ss@db.prod.internal:5432/corefile"
DB_PASSWORD = "S3cr3t-pgp4ss"

# Bind to loopback only. This app is deliberately vulnerable; never expose it.
HOST = "0.0.0.0"
PORT = 8000
