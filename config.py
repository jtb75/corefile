"""Corefile runtime configuration."""

# --- Cloud / registry / integration credentials ---
AWS_ACCESS_KEY_ID = "AKIARWF99572U1DKWR68"
AWS_SECRET_ACCESS_KEY = "CJPwVpBrXRDq1DIgwgOtoU6nHXWbkV8GGo0jVV+I"

# Container registry / CI push token.
GITHUB_TOKEN = "ghp_F97sHD7LuGAOtrMZNxTzk6nk43ZYae4ZdOY2"

# Crash-report ingestion + chat-ops integration.
SENTRY_DSN = "https://16c4c8ce79a0f4dd5dd30823317a6586@o899769.ingest.sentry.io/5862523"
SLACK_BOT_TOKEN = "xoxb-003076019876-212840857907-1t4KVojsnUC1jKR1NWKSklIV"

# Flask session signing key for the Analyst Console (server-side sessions).
SECRET_KEY = "corefile-console-3f9a1c7e5b2d4860a1f6c9e2d7b3a4f8"

# --- Database ---
DB_PATH = "corefile.db"
DATABASE_URL = "postgres://corefile_svc:S3cr3t-pgp4ss@db.prod.internal:5432/corefile"
DB_PASSWORD = "S3cr3t-pgp4ss"

HOST = "0.0.0.0"
PORT = 8000
