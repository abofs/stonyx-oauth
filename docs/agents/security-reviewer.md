# SME Template: Security Reviewer — Stonyx OAuth

> **Inherits from:** `beatrix-shared/docs/framework/templates/agents/security-reviewer.md`
> Load the base template first, then layer this project-specific context on top.

## Project Context

**Repo:** `abofs/stonyx-oauth`
**Framework:** Authentication module for the Stonyx ecosystem
**Domain:** OAuth2 Authorization Code flow handling sensitive operations — client secret management, token exchange, session creation, and state token CSRF protection

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (ES Modules) |
| Token Exchange | Native `fetch` (POST to provider token endpoints with client secrets) |
| Session Storage | In-memory `Map` (keyed by UUID session IDs) |
| CSRF Protection | `StateStore` — `crypto.randomUUID()` state bound to a 32-byte client-held binding value (HttpOnly cookie), SHA-256 digest stored server-side, 10-minute TTL |
| Auth Provider | Discord (built-in), extensible via `OAuthFlow` base class |

## Architecture Patterns

- **Client secret handling:** `clientSecret` is passed through provider config and sent in token exchange POST bodies — it is never logged but lives in memory for the lifetime of the process
- **State token CSRF flow (#36):** `StateStore.issue()` mints a `crypto.randomUUID()` state *and* a 32-byte CSPRNG binding value; the state, the provider name, a SHA-256 digest of the binding value and the issue time go into `StateStore.pending`, and the plaintext binding value goes to the client as an `HttpOnly; SameSite=Lax; Path=/auth` cookie. `StateStore.consume()` accepts a callback only when the caller presents the binding value that hashes to the stored digest, for the provider the state was issued for, within 10 minutes.
  **Do not treat presence-plus-age as the CSRF protection.** That was the pre-#36 design and it is the vulnerability: any state issued to any visitor validated for any callback, so an attacker could harvest their own state and code and deliver them to a victim, logging the victim in as the attacker (RFC 6749 §10.12). The client binding is the control; the TTL is only replay-window limiting.
  The record is deleted as soon as the state is recognised — before the TTL, provider and binding checks — so every state gets exactly one attempt. That is deliberate (uniform one-attempt semantics, no repeatable oracle), not brute-force resistance.
- **Session ID as bearer token:** After successful OAuth callback, a UUID session ID is returned to the client; subsequent requests send it via `session-id` header — the session manager validates it against the in-memory Map with TTL check
- **Token exchange via fetch:** Code-for-token exchange uses `Content-Type: application/json` by default — some providers require `application/x-www-form-urlencoded`, which needs a provider-level `exchangeCode()` override

## Live Knowledge

- **Secret exposure risk:** `clientId` and `clientSecret` are stored as instance properties on `OAuthFlow` — any code that serializes or logs a provider instance could leak the secret; verify no toString/toJSON methods exist
- **Session fixation:** Sessions are created with `randomUUID()` and stored server-side — there is no session regeneration on privilege change, but since sessions are created fresh on each OAuth callback, fixation risk is limited to the session lifetime
- **Token storage:** Access tokens and refresh tokens are stored in the session Map alongside user data — if the session Map is ever serialized (e.g., for debugging), tokens would be exposed
- **No token revocation on logout:** `logout()` calls `sessionManager.destroy()` but does NOT revoke the access token at the provider — the access token remains valid until the provider's expiry; implement `revokeToken()` on providers for defense in depth
- **State token cleanup:** Expired pending states are only cleaned up when they're accessed during a callback — stale entries from abandoned auth flows accumulate in `StateStore.pending` indefinitely; there is no periodic cleanup, and `GET /auth/login/:provider` is unauthenticated. Tracked as [#38](https://github.com/abofs/stonyx-oauth/issues/38)
- **Redirect URI validation:** The `redirectUri` is set from config and used in both the authorization URL and token exchange — mismatches between configured and actual callback URLs cause silent token exchange failures; providers may also reject mismatches as a security measure
- **Open redirect potential:** If `frontendCallbackUrl` is configured, the callback handler redirects to that URL with the session ID as a query parameter — ensure this URL is not user-controllable
- **Authorization header for user info:** User info is fetched with `Authorization: Bearer {accessToken}` — the access token is sent over HTTPS to the provider's user info endpoint; verify no HTTP fallback exists
