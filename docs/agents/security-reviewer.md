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
| CSRF Protection | `crypto.randomUUID()` state tokens with 10-minute TTL |
| Auth Provider | Discord (built-in), extensible via `OAuthFlow` base class |

## Architecture Patterns

- **Client secret handling:** `clientSecret` is passed through provider config and sent in token exchange POST bodies — it is never logged but lives in memory for the lifetime of the process
- **State token CSRF flow:** State tokens are generated with `crypto.randomUUID()`, stored in `pendingStates` Map with timestamps, validated on callback, and immediately deleted (single-use) — expired tokens (>10 min) are rejected
- **Session ID as bearer token:** After successful OAuth callback, a UUID session ID is returned to the client; subsequent requests send it via `session-id` header — the session manager validates it against the in-memory Map with TTL check
- **Token exchange via fetch:** Code-for-token exchange uses `Content-Type: application/json` by default — some providers require `application/x-www-form-urlencoded`, which needs a provider-level `exchangeCode()` override

## Live Knowledge

- **Secret exposure risk:** `clientId` and `clientSecret` are stored as instance properties on `OAuthFlow` — any code that serializes or logs a provider instance could leak the secret; verify no toString/toJSON methods exist
- **Session fixation:** Sessions are created with `randomUUID()` and stored server-side — there is no session regeneration on privilege change, but since sessions are created fresh on each OAuth callback, fixation risk is limited to the session lifetime
- **Token storage:** Access tokens and refresh tokens are stored in the session Map alongside user data — if the session Map is ever serialized (e.g., for debugging), tokens would be exposed
- **No token revocation on logout:** `logout()` calls `sessionManager.destroy()` but does NOT revoke the access token at the provider — the access token remains valid until the provider's expiry; implement `revokeToken()` on providers for defense in depth
- **State token cleanup:** Expired pending states are only cleaned up when they're accessed during a callback — stale entries from abandoned auth flows accumulate in `pendingStates` indefinitely; there is no periodic cleanup
- **Redirect URI validation:** The `redirectUri` is set from config and used in both the authorization URL and token exchange — mismatches between configured and actual callback URLs cause silent token exchange failures; providers may also reject mismatches as a security measure
- **Open redirect potential:** If `frontendCallbackUrl` is configured, the callback handler redirects to that URL with the session ID as a query parameter — ensure this URL is not user-controllable
- **Authorization header for user info:** User info is fetched with `Authorization: Bearer {accessToken}` — the access token is sent over HTTPS to the provider's user info endpoint; verify no HTTP fallback exists
