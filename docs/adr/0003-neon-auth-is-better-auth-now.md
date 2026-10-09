# ADR-0003: Neon Auth is Better Auth now, not Stack

- **Date**: 2026-10-08  |  **Iteration**: 1  |  **Status**: Implemented  |  **Deciders**: Kathryn Chiew (student), Claude Opus 5.5 (build)

**TL;DR**: Enabling Neon Auth on a project today provisions **Better Auth**, not Stack, so the template's Stack-specific login calls were swapped for Better Auth's; every decision in ADR-0001 still holds, and only the provider plumbing changed.

## Context

The course steps say to enable Neon Auth with provider Stack and copy a JWKS URL, a Stack project id and a publishable client key. On 2026-10-08 the Neon console offered no provider choice: Auth was "Powered by Better Auth", and Settings → Better Auth showed only an **Auth URL** and a **JWKS URL**. There is no Stack project id, no publishable key, and no `neon_auth.users_sync` table. `auth.py` called `api.stack-auth.com` directly, so the template's sign-in could not work as written.

## What changed, and what was verified live

Probed against the real Neon Auth endpoint before writing code:

| Concern | Stack (template) | Better Auth (now) |
|---|---|---|
| Sign up / sign in | `POST api.stack-auth.com/.../auth/password/sign-{up,in}` → tokens | `POST {NEON_AUTH_URL}/sign-{up,in}/email` → session cookie `__Secure-neon-auth.session_token` |
| Getting a JWT | returned directly | `GET {NEON_AUTH_URL}/token` with the session cookie → `{"token": <JWT>}` (15-minute lifetime) |
| Refresh | `/auth/sessions/current/refresh` with a refresh token | call `/token` again with the session (7-day lifetime); the session is our OAuth refresh token |
| Signature algorithm | ES256 / RS256 | **EdDSA**: the verifier had to accept it, or every signed-in call would fail |
| Audience | Stack project id | the auth host's origin, e.g. `https://ep-….neonauth….neon.tech` |
| Email for display | `neon_auth.users_sync` lookup | the `email` claim in the JWT itself, so `user_status` needs no database |
| Origin check | none | Better Auth **refuses requests without an `Origin`** from a trusted domain, so `PUBLIC_URL` must be listed under Settings → Better Auth → Domains |

Configuration shrinks from four auth variables to two: `NEON_AUTH_URL` (from which the JWKS URL and audience are derived) and `PUBLIC_URL`. `NEON_AUTH_JWKS_URL` is still honoured as an override.

Verified locally on 2026-10-08 with `scripts/2026-10-08-oauth-dance-probe.py` (discovery → DCR → sign-up → PKCE → user mode: passes), plus: no header → guest, declared guest → guest, garbled token → **error, not guest** (ADR-0001 D4 holds), a bogus refresh → 400, a real refresh → user mode, and the "already has an account" and wrong-password messages surface correctly.

## Roads not taken

- **Create a Stack project directly at stack-auth.com** so the template runs unmodified. Rejected because it adds a second identity provider outside the Neon project the data lives in, and course-mates on the same Neon console would hit the same wall anyway.
- **Send `Origin: http://localhost` from the server** to sidestep the trusted-domains list. Rejected because it spoofs an origin and depends on "Allow Localhost", which should be off in production.
- **Keep the `users_sync` lookup against Better Auth's own user table.** Unnecessary, because the JWT already carries the email, and a missing table would have turned every signed-in call into an error.

## Still true from ADR-0001

D1 (key on `sub`, never email), D2 (guest commons), D3 (petnames) and D4 (an invalid token is loud, never guest) are unchanged.
