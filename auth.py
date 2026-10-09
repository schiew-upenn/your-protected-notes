"""auth.py — a minimal OAuth 2.1 authorization server for your-protected-notes.

Why this exists (ADR-0002, iteration 3): claude.ai custom connectors obtain
tokens via OAuth — discovery, dynamic client registration, PKCE, a browser
sign-in. Rather than depend on Stack Auth's (undocumented-for-this-dance)
OAuth posture, THIS server is its own authorization server: the login page
checks credentials against Neon Auth's password API and the token endpoint
hands back Neon Auth's own JWTs — which `server.py`'s verifier already trusts.
claude.ai never needs to know Neon Auth exists. (Originally Stack; Neon Auth
moved to Better Auth — ADR-0003.)

Prototype-grade, honestly: in-memory stores (single instance), public
clients + PKCE only, codes expire in 5 minutes. Session 7 professionalizes.
"""
import hashlib
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse

ISSUER = os.environ.get("PUBLIC_URL", "http://localhost:8000").rstrip("/")
NEON_AUTH_URL = os.environ.get("NEON_AUTH_URL", "").rstrip("/")   # Neon console -> Settings -> Better Auth -> Auth URL

# Neon Auth is now Better Auth, not Stack (ADR-0003). Its session lives in this
# cookie; we hold the signed value as the OAuth refresh token and trade it at
# /token for a short-lived JWT, which server.py verifies against the JWKS.
SESSION_COOKIE = "__Secure-neon-auth.session_token"

GUEST_TOKEN = "guest-no-shelf"   # a DECLARED guest credential: completes the
# OAuth dance for users who choose the commons; server.py maps it to guest
# mode explicitly (distinct from absent AND from invalid — ADR-0004 holds).

_codes: dict = {}     # code -> {tokens, code_challenge, redirect_uri, client_id, exp}
_clients: dict = {}   # client_id -> {redirect_uris}


def _neon_auth(path, payload=None, session=None):
    """Call Neon Auth (Better Auth). Returns (json body, session cookie value or None).

    Better Auth refuses requests without an Origin, and only accepts origins on
    the project's trusted-domains list — so PUBLIC_URL must be added there.
    """
    if not NEON_AUTH_URL:
        raise RuntimeError("NEON_AUTH_URL is not set — see .env.example.")
    h = {"Content-Type": "application/json", "Origin": ISSUER}
    if session:
        h["Cookie"] = f"{SESSION_COOKIE}={session}"
    req = urllib.request.Request(NEON_AUTH_URL + path,
                                 json.dumps(payload).encode() if payload is not None else None, h)
    with urllib.request.urlopen(req) as r:
        body = json.loads(r.read())
        cookies = r.headers.get_all("Set-Cookie") or []
    new_session = next((c.split(";", 1)[0].split("=", 1)[1] for c in cookies
                        if c.startswith(SESSION_COOKIE + "=")), None)
    return body, new_session


def _tokens_for(session):
    """Trade a Better Auth session for OAuth tokens: a fresh JWT + the session as refresh."""
    body, _ = _neon_auth("/token", session=session)
    return {"access_token": body["token"], "refresh_token": session}


LOGIN_FORM = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in — your-protected-notes</title>
<style>
body{{font-family:Georgia,serif;background:#FBF7EE;display:flex;justify-content:center;padding-top:8vh}}
.card{{background:#fff;border:2px solid #1E4D2B;border-radius:14px;padding:28px 32px;width:340px}}
h1{{font-family:system-ui,sans-serif;color:#1E4D2B;font-size:1.15em;margin:0 0 4px}}
p{{font-size:.85em;color:#555;margin:4px 0 14px}}
input,button{{width:100%;box-sizing:border-box;padding:10px;margin:5px 0;border-radius:8px;font-size:.95em}}
input{{border:1px solid #1E4D2B55;background:#fffef9}}
button{{border:none;background:#1E4D2B;color:#fff;font-weight:bold;cursor:pointer}}
.alt{{background:#fff;color:#1E4D2B;border:2px solid #1E4D2B}}
.err{{color:#F0654E;font-size:.85em}}</style></head><body>
<div class="card"><h1>your-protected-notes</h1>
<p>Sign in to get your private shelf. {err}</p>
<form method="post" action="{issuer}/authorize">
{hidden}
<input name="email" type="email" placeholder="email" required>
<input name="password" type="password" placeholder="password" required>
<button name="mode" value="signin" type="submit">Sign in</button>
<button name="mode" value="signup" type="submit" class="alt">New here — sign up</button>
<button name="mode" value="guest" type="submit" class="alt" formnovalidate style="border-style:dashed;color:#777;border-color:#999">Continue as guest — shared commons</button>
</form></div></body></html>"""


def register_oauth_routes(mcp):
    @mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def as_metadata(request: Request):
        return JSONResponse({
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/authorize",
            "token_endpoint": f"{ISSUER}/token",
            "registration_endpoint": f"{ISSUER}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
        })

    @mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def pr_metadata(request: Request):
        return JSONResponse({"resource": f"{ISSUER}/mcp",
                             "authorization_servers": [ISSUER]})

    # RFC 9728 path-suffixed variant some clients fetch
    @mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
    async def pr_metadata2(request: Request):
        return await pr_metadata(request)

    @mcp.custom_route("/register", methods=["POST"])
    async def register(request: Request):
        body = json.loads(await request.body() or b"{}")
        client_id = secrets.token_urlsafe(16)
        _clients[client_id] = {"redirect_uris": body.get("redirect_uris", [])}
        return JSONResponse({"client_id": client_id,
                             "token_endpoint_auth_method": "none",
                             "redirect_uris": body.get("redirect_uris", []),
                             "grant_types": ["authorization_code", "refresh_token"],
                             "response_types": ["code"]}, status_code=201)

    def _render_form(params, err=""):
        hidden = "\n".join(
            f'<input type="hidden" name="{k}" value="{urllib.parse.quote(v, safe="")}">'
            for k, v in params.items())
        return HTMLResponse(LOGIN_FORM.format(issuer=ISSUER, hidden=hidden,
                                              err=f'<span class="err">{err}</span>' if err else ""))

    @mcp.custom_route("/authorize", methods=["GET"])
    async def authorize_get(request: Request):
        q = dict(request.query_params)
        keep = {k: q.get(k, "") for k in
                ("client_id", "redirect_uri", "state", "code_challenge",
                 "code_challenge_method", "response_type", "scope", "resource")}
        return _render_form(keep)

    @mcp.custom_route("/authorize", methods=["POST"])
    async def authorize_post(request: Request):
        form = dict(await request.form())
        params = {k: urllib.parse.unquote(form.get(k, "")) for k in
                  ("client_id", "redirect_uri", "state", "code_challenge",
                   "code_challenge_method", "response_type", "scope", "resource")}
        if form.get("mode") == "guest":
            code = secrets.token_urlsafe(24)
            _codes[code] = {"tokens": {"access_token": GUEST_TOKEN, "refresh_token": GUEST_TOKEN},
                            "code_challenge": params["code_challenge"],
                            "redirect_uri": params["redirect_uri"],
                            "client_id": params["client_id"],
                            "exp": time.time() + 300}
            sep = "&" if "?" in params["redirect_uri"] else "?"
            return RedirectResponse(
                f'{params["redirect_uri"]}{sep}code={code}&state={urllib.parse.quote(params["state"], safe="")}',
                status_code=302)
        email, password = form.get("email", ""), form.get("password", "")
        path = "/sign-up/email" if form.get("mode") == "signup" else "/sign-in/email"
        payload = {"email": email, "password": password}
        if form.get("mode") == "signup":
            payload["name"] = email.split("@")[0]       # Better Auth requires a name
        try:
            _, session = _neon_auth(path, payload)
            tokens = _tokens_for(session)
        except urllib.error.HTTPError as e:
            # Parse the provider's error code so the human gets the TRUTH, not a shrug
            # (known-problems #1: the generic copy turned a created-account
            # retry into what read as rejection, live in class 2026-10-08).
            try:
                auth_code = json.loads(e.read()).get("code", "")
            except Exception:
                auth_code = ""
            if "ALREADY_EXISTS" in auth_code:
                msg = "Good news: this email already has an account — press SIGN IN instead."
            elif auth_code == "MISSING_ORIGIN" or "ORIGIN" in auth_code:
                msg = "The server's URL isn't on Neon Auth's trusted domains yet — ask its owner to add it."
            elif path.endswith("/sign-in/email"):
                msg = "Sign-in failed — wrong password, or no account yet (then use sign up)."
            else:
                msg = "Sign-up failed — password may be too weak (8+ characters), or try sign in."
            return _render_form(params, err=msg)
        code = secrets.token_urlsafe(24)
        _codes[code] = {"tokens": tokens,
                        "code_challenge": params["code_challenge"],
                        "redirect_uri": params["redirect_uri"],
                        "client_id": params["client_id"],
                        "exp": time.time() + 300}
        sep = "&" if "?" in params["redirect_uri"] else "?"
        return RedirectResponse(
            f'{params["redirect_uri"]}{sep}code={code}&state={urllib.parse.quote(params["state"], safe="")}',
            status_code=302)

    @mcp.custom_route("/token", methods=["POST"])
    async def token(request: Request):
        form = dict(await request.form())
        grant = form.get("grant_type")
        if grant == "authorization_code":
            rec = _codes.pop(form.get("code", ""), None)
            if not rec or rec["exp"] < time.time():
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            verifier = form.get("code_verifier", "")
            import base64
            expect = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            if rec["code_challenge"] and expect != rec["code_challenge"]:
                return JSONResponse({"error": "invalid_grant",
                                     "error_description": "PKCE verification failed"}, status_code=400)
            t = rec["tokens"]
            return JSONResponse({"access_token": t["access_token"],
                                 "token_type": "bearer", "expires_in": 900,   # Neon Auth JWTs last 15 min
                                 "refresh_token": t.get("refresh_token", "")})
        if grant == "refresh_token":
            if form.get("refresh_token", "") == GUEST_TOKEN:
                return JSONResponse({"access_token": GUEST_TOKEN, "token_type": "bearer",
                                     "expires_in": 31536000, "refresh_token": GUEST_TOKEN})
            try:
                t = _tokens_for(form.get("refresh_token", ""))
                return JSONResponse({"access_token": t["access_token"],
                                     "token_type": "bearer", "expires_in": 900,
                                     "refresh_token": t["refresh_token"]})
            except Exception:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
