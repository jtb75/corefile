"""
Corefile — Analyst Console account store and authentication.

============================ DEMO / SAFETY NOTICE ============================
Part of an INTENTIONALLY VULNERABLE demo app. Note the deliberate contrast:
authentication here is *correct* — salted password hashing (werkzeug) and a
signed server-side session. The planted weakness in the private area is
AUTHORIZATION, not authentication: the /api/account/<uid>/integrations and
/api/console/cases/<id> endpoints in app.py require a valid login but never
check object ownership (IDOR / Broken Object Level Authorization, OWASP API1).

That's the whole point of the private area: login works fine, so an anonymous
scanner sees nothing, while an authenticated scan (or a source-aware review)
walks straight into another analyst's stored cloud tokens.

Every token below is a non-functional, randomly generated fake. See config.py.
=============================================================================
"""

from werkzeug.security import generate_password_hash, check_password_hash

# One shared password for every seeded analyst — keeps the live demo frictionless.
DEMO_PASSWORD = "corefile"

# Seeded analyst accounts. The uids are sequential on purpose: trivially
# enumerable (u-1001, u-1002, u-2001…), which is exactly what makes the
# IDOR/BOLA finding easy to walk an audience through.
_ACCOUNTS = {
    "u-1001": {
        "uid": "u-1001",
        "email": "arivera@acme-checkout.io",
        "name": "Ana Rivera",
        "org": "acme-checkout",
        "role": "analyst",
        # Per-analyst integration tokens — the prize an IDOR leaks.
        "integrations": {
            "github_pat": "ghp_9Fk2mQ8sVxWpLzR4tYbN7cJ1dHgE0aA6uZ3",
            "slack_bot_token": "xoxb-556677889900-4432110987766-Qp7Yr2Lm9Nx0Vb3Kd8W",
        },
        "cases": ["CF-4211", "CF-0009"],
    },
    "u-1002": {
        "uid": "u-1002",
        "email": "dpatel@acme-checkout.io",
        "name": "Dev Patel",
        "org": "acme-checkout",
        "role": "analyst",
        "integrations": {
            "aws_access_key_id": "AKIA6ODU7W2K4FQJ1XZP",
            "aws_secret_access_key": "hVb2Rk9pLmQ8sXwZ4tYc1dNf7gJ0aE6uKpR3oId",
        },
        "cases": ["CF-4211"],
    },
    "u-2001": {
        "uid": "u-2001",
        "email": "controller@esa-launch.int",
        "name": "Mission Controller",
        "org": "esa-launch",
        "role": "admin",
        "integrations": {
            "github_pat": "ghp_1Aa7Bb2Cc3Dd4Ee5Ff6Gg7Hh8Ii9Jj0Kk1L",
            "telemetry_signing_key": "tsk_live_51QwErTyUiOpAsDfGhJkLzXcVbNm0",
        },
        "cases": ["flight-501"],
    },
}

# Precompute salted hashes at import time. This is clean auth — NOT a finding.
for _acct in _ACCOUNTS.values():
    _acct["password_hash"] = generate_password_hash(DEMO_PASSWORD)


def authenticate(email, password):
    """Return the account dict for valid credentials, else None. Constant-ish
    time via werkzeug's check_password_hash. Authentication is intentionally
    correct — the planted flaw lives in authorization, not here."""
    email = (email or "").strip().lower()
    for acct in _ACCOUNTS.values():
        if acct["email"].lower() == email:
            if check_password_hash(acct["password_hash"], password or ""):
                return acct
            return None
    return None


def get_account(uid):
    return _ACCOUNTS.get(uid)


def all_accounts():
    return list(_ACCOUNTS.values())


def public_view(acct):
    """Non-sensitive projection used for the analyst roster listing."""
    return {
        "uid": acct["uid"],
        "name": acct["name"],
        "email": acct["email"],
        "org": acct["org"],
        "role": acct["role"],
    }
