#!/usr/bin/env python3
"""Small Kratos admin CLI (stdlib only). Used by the justfile; run `just` to see the commands.

Talks to the Kratos admin API (KRATOS_ADMIN_URL, default http://localhost:4434).
API reference: https://www.ory.sh/docs/kratos/reference/api
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

ADMIN = os.environ.get("KRATOS_ADMIN_URL", "http://localhost:4434").rstrip("/")
PUBLIC = os.environ.get("KRATOS_PUBLIC_URL", "http://localhost:4433").rstrip("/")
PROXY = os.environ.get("OATHKEEPER_PROXY_URL", "http://localhost:8080").rstrip("/")


def call(method, path, body=None, base=ADMIN, headers=None):
    req = urllib.request.Request(
        path if path.startswith("http") else base + path,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            is_json = raw and "json" in (r.headers.get("Content-Type") or "")
            return (json.loads(raw) if is_json else raw.decode()), r.headers
    except urllib.error.HTTPError as e:
        detail = e.read().decode()
        try:
            data = json.loads(detail)
            if "error" in data:
                detail = data["error"].get("reason") or data["error"].get("message") or detail
            else:  # a self-service flow with validation messages
                detail = "; ".join(m["text"] for m in data["ui"]["messages"]) or detail
        except (ValueError, KeyError, TypeError):
            pass
        sys.exit(f"error: {method} {path} -> {e.code}: {detail}")


def find(email):
    users, _ = call("GET", f"/admin/identities?credentials_identifier={urllib.request.quote(email)}")
    if not users:
        sys.exit(f"error: no user with email {email}")
    return users[0]


def identity_id(email):
    """Prints just the identity id, for scripts (`just delete-user` needs it after the identity is gone)."""
    print(find(email)["id"])


def users():
    rows, path = [], "/admin/identities?page_size=250"
    while path:
        page, headers = call("GET", path)
        rows += page
        nxt = re.search(r'<[^>]*(/admin/identities\?[^>]*)>; rel="next"', headers.get("Link") or "")
        path = nxt.group(1) if nxt and page else None
    print(f"{'ID':36}  {'EMAIL':32}  {'STATE':8}  {'VERIFIED':8}  CREATED")
    for u in rows:
        verified = any(a["verified"] for a in u.get("verifiable_addresses", []))
        print(f"{u['id']:36}  {u['traits'].get('email', ''):32}  {u['state']:8}  {'yes' if verified else 'no':8}  "
              f"{u['created_at'][:19].replace('T', ' ')}")
    print(f"\n{len(rows)} user(s)")


def user(email):
    u = find(email)
    full, _ = call("GET", f"/admin/identities/{u['id']}?include_credential=oidc")
    sessions, _ = call("GET", f"/admin/identities/{u['id']}/sessions?active=true")
    full["active_sessions"] = len(sessions or [])
    print(json.dumps(full, indent=2))


def add_user(email, password):
    u, _ = call("POST", "/admin/identities", {
        "schema_id": "default",
        "traits": {"email": email},
        "credentials": {"password": {"config": {"password": password}}},
        "verifiable_addresses": [{"value": email, "via": "email", "verified": True, "status": "completed"}],
    })
    print(f"created {u['id']}  {email}")


def revoke(email):
    u = find(email)
    call("DELETE", f"/admin/identities/{u['id']}/sessions")
    print(f"{email}: all sessions revoked (logged out everywhere)")


def recover(email):
    u = find(email)
    r, _ = call("POST", "/admin/recovery/code", {"identity_id": u["id"], "expires_in": "1h"})
    print(f"Send this to {email} (valid 1h):\n  link: {r['recovery_link']}\n  code: {r['recovery_code']}")


def set_state(email, state):
    u = find(email)
    call("PATCH", f"/admin/identities/{u['id']}", [{"op": "replace", "path": "/state", "value": state}])
    return u


def deactivate(email):
    set_state(email, "inactive")
    print(f"{email}: deactivated. Existing sessions stop working immediately and login is refused.")
    print("Sessions are suspended, not deleted: `activate` brings them back. Use `revoke` too for a permanent ban.")


def activate(email):
    set_state(email, "active")
    print(f"{email}: active again")


def delete_user(email):
    u = find(email)
    call("DELETE", f"/admin/identities/{u['id']}")
    print(f"deleted {u['id']}  {email} from Kratos")


def jwt(email, password):
    """Logs in via the API flow, calls the app through Oathkeeper, prints the JWT it injected."""
    flow, _ = call("GET", "/self-service/login/api", base=PUBLIC)
    login, _ = call("POST", f"/self-service/login?flow={flow['id']}", base=PUBLIC,
                    body={"method": "password", "identifier": email, "password": password})
    # Relies on the placeholder `app` echoing request headers back.
    echo, _ = call("GET", "/api/app/whoami", base=PROXY, headers={"Authorization": f"Bearer {login['session_token']}"})
    token = next((l.split(" ", 2)[2] for l in echo.splitlines() if l.lower().startswith("authorization: bearer ")), None)
    print(token or sys.exit("error: no JWT in the upstream response (is `app` still the echo placeholder?)"))


COMMANDS = {"id": identity_id, "jwt": jwt, "users": users, "user": user, "add-user": add_user,
            "revoke": revoke, "deactivate": deactivate, "activate": activate, "recover": recover, "delete-user": delete_user}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        sys.exit(f"usage: admin.py {{{','.join(COMMANDS)}}} [args...]")
    COMMANDS[sys.argv[1]](*sys.argv[2:])
