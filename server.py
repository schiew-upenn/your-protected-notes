"""your-protected-notes — an MCP server that knows WHO is asking.

Your earlier servers answered anyone. This one has two modes:
  guest — no (or missing) token: you share one commons with every guest.
  user  — a verified Neon Auth identity: you get a private shelf.
The difference is one Authorization header, one JWKS check, and one
user_id column. That column is the whole lesson: state only becomes
YOURS when the server can tell who YOU are.

Every design choice has an ADR with the road not taken (docs/adr/) —
including the two we answered BEFORE writing code (0001: identity =
Stack `sub`, never email; 0002: guests share a commons rather than
being refused), which is the deliberative pattern this prototype also
exists to demonstrate.
"""
import os
import secrets
import urllib.parse

import psycopg
from mcp.server.fastmcp import Context, FastMCP

DATABASE_URL = os.environ.get("DATABASE_URL")
NEON_AUTH_URL = os.environ.get("NEON_AUTH_URL", "").rstrip("/")   # Neon console -> Settings -> Better Auth
JWKS_URL = os.environ.get("NEON_AUTH_JWKS_URL") or (
    f"{NEON_AUTH_URL}/.well-known/jwks.json" if NEON_AUTH_URL else None)
# Neon Auth (Better Auth) issues JWTs whose audience is the auth host's origin (ADR-0003).
_auth = urllib.parse.urlsplit(NEON_AUTH_URL)
AUDIENCE = f"{_auth.scheme}://{_auth.netloc}" if NEON_AUTH_URL else ""

# Crockford Base32 (no I, L, O, U — unambiguous aloud, unlucky words excluded).
# 4 chars = 32^4 = 1,048,576 petnames: plenty for a shelf of notes.
CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

mcp = FastMCP(
    "your-protected-notes",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 8000)),
)

# Petnames are unique PER SHELF, not globally (two users can both hold A7K2).
# A PK can't hold an expression, so a unique expression index does it.
SCHEMA = """
CREATE TABLE IF NOT EXISTS notes (
    petname  CHAR(4) NOT NULL,
    user_id  TEXT,                              -- NULL = the guest commons (ADR-0001 D2)
    note     TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS notes_shelf_petname
    ON notes (petname, COALESCE(user_id, ''));
"""


def db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set — see README step 1.")
    conn = psycopg.connect(DATABASE_URL)
    with conn.cursor() as cur:
        cur.execute(SCHEMA)
    conn.commit()
    return conn


def petname():
    return "".join(secrets.choice(CROCKFORD) for _ in range(4))


# ---------------------------------------------------------------- identity
def current_identity(ctx: Context):
    """Resolve the caller: (user_id, email) or (None, None) for a guest.

    ABSENT token  -> guest (a mode, not an error — ADR-0001 D4).
    INVALID token -> raises (an invalid credential must never silently
                     degrade to guest: that would hide broken auth as
                     working anonymity — ADR-0001 D4's whole point).
    """
    request = getattr(ctx.request_context, "request", None)  # starlette Request under streamable-http
    auth = request.headers.get("authorization", "") if request is not None else ""
    if not auth.lower().startswith("bearer "):
        return None, None
    token = auth.split(None, 1)[1]
    if token == "guest-no-shelf":      # the declared-guest credential (auth.py GUEST_TOKEN)
        return None, None              # chosen commons — a mode, never an error
    import jwt as pyjwt
    from jwt import PyJWKClient
    if not JWKS_URL:
        raise RuntimeError("NEON_AUTH_URL is not set — see .env.example.")
    signing_key = PyJWKClient(JWKS_URL).get_signing_key_from_jwt(token)
    claims = pyjwt.decode(
        token, signing_key.key, algorithms=["EdDSA", "ES256", "RS256"],   # Better Auth signs EdDSA
        audience=AUDIENCE or None,
        options={"verify_aud": bool(AUDIENCE)},
    )
    user_id = claims["sub"]                      # the identity (ADR-0001 D1)
    email = claims.get("email")                  # display only, never the key; Better Auth puts
    return user_id, email                        # it in the token (no users_sync table — ADR-0003)


# ------------------------------------------------------------------- tools
@mcp.tool()
def user_status(ctx: Context) -> str:
    """Who does this server think you are? Always available, in every mode."""
    user_id, email = current_identity(ctx)
    if user_id is None:
        return "guest — notes go to the shared guest commons. Sign in to get a private shelf."
    return f"user — signed in as {email or user_id}. Your notes are yours alone."


@mcp.tool()
def add_note(note: str, ctx: Context) -> str:
    """Keep a note. Guests write to the commons; users to their own shelf."""
    user_id, _ = current_identity(ctx)
    with db() as conn, conn.cursor() as cur:
        for _ in range(5):                      # 5 collision retries ≈ never fails (ADR-0001 D3)
            try:
                p = petname()
                cur.execute("INSERT INTO notes (petname, user_id, note) VALUES (%s, %s, %s)",
                            (p, user_id, note))
                conn.commit()
                shelf = "your shelf" if user_id else "the guest commons"
                return f"Noted as {p} on {shelf}."
            except psycopg.errors.UniqueViolation:
                conn.rollback()
    return "Could not find a free petname after 5 tries (astronomically unlikely — check the table)."


@mcp.tool()
def list_notes(ctx: Context) -> str:
    """Every note on YOUR current shelf (commons if guest), oldest first."""
    user_id, _ = current_identity(ctx)
    with db() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT petname, note, created_at FROM notes "
            "WHERE user_id IS NOT DISTINCT FROM %s ORDER BY created_at", (user_id,))
        rows = cur.fetchall()
    shelf = "your shelf" if user_id else "the guest commons"
    if not rows:
        return f"Nothing on {shelf} yet."
    return f"On {shelf}:\n" + "\n".join(f"  {p} ({ts:%Y-%m-%d %H:%M}): {n}" for p, n, ts in rows)


@mcp.tool()
def clear_notes(ctx: Context) -> str:
    """Clear YOUR current shelf — a guest can only clear the commons, never yours."""
    user_id, _ = current_identity(ctx)
    with db() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM notes WHERE user_id IS NOT DISTINCT FROM %s", (user_id,))
        n = cur.rowcount
        conn.commit()
    shelf = "your shelf" if user_id else "the guest commons"
    return f"Cleared {n} note(s) from {shelf}."


from auth import register_oauth_routes  # OAuth AS endpoints (ADR-0002 iter. 3)
register_oauth_routes(mcp)

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
