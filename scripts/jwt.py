#!/usr/bin/env python3
"""Prints the JWT your app would receive for a user (stdlib only): `just jwt EMAIL PASSWORD`.

Acts as a client, not an admin: logs in through Kratos' public API flow, then calls the
app through Oathkeeper. User administration is user-service's CLI (`just` lists it).
"""
import json
import os
import sys
import urllib.error
import urllib.request

PUBLIC = os.environ.get("KRATOS_PUBLIC_URL", "http://localhost:4433").rstrip("/")
PROXY = os.environ.get("OATHKEEPER_PROXY_URL", "http://localhost:8080").rstrip("/")


def call(method, url, body=None, headers=None):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode() if body is not None else None,
        method=method,
        headers={"Accept": "application/json", "Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw) if raw and "json" in (r.headers.get("Content-Type") or "") else raw.decode()
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
        sys.exit(f"error: {method} {url} -> {e.code}: {detail}")


def jwt(email, password):
    flow = call("GET", f"{PUBLIC}/self-service/login/api")
    login = call("POST", f"{PUBLIC}/self-service/login?flow={flow['id']}",
                 body={"method": "password", "identifier": email, "password": password})
    # Relies on the placeholder `app` echoing request headers back.
    echo = call("GET", f"{PROXY}/api/app/whoami", headers={"Authorization": f"Bearer {login['session_token']}"})
    token = next((l.split(" ", 2)[2] for l in echo.splitlines() if l.lower().startswith("authorization: bearer ")), None)
    print(token or sys.exit("error: no JWT in the upstream response (is `app` still the echo placeholder?)"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: jwt.py EMAIL PASSWORD")
    jwt(*sys.argv[1:])
