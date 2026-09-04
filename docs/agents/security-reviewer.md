# SME Template: Security Reviewer — Stonyx OAuth

> **Inherits from:** `beatrix-shared/docs/framework/templates/agents/security-reviewer.md`
> Load the base template first, then layer this project-specific context on top.

## Project Context

**Repo:** `abofs/stonyx-oauth`
**Framework:** Authentication module for the Stonyx ecosystem
**Domain:** OAuth2 Authorization Code flow handling sensitive operations — client secret management, token exchange, session creation, and binding the OAuth2 `state` value to the user agent that started the flow (RFC 6749 §10.12, RFC 9700). Note the framing: `state` is CSRF protection **only** when it is bound to the requesting client; an unbound one-time token with a TTL is replay-window limiting, and treating it as CSRF protection was the defect fixed in #36.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (ES Modules) |
| Token Exchange | Native `fetch` (POST to provider token endpoints with client secrets) |
| Session Storage | In-memory `Map` (keyed by UUID session IDs) |
| CSRF Protection | **Requirement (RFC 6749 §10.12, RFC 9700):** the `state` value MUST be bound to the requesting user agent's authenticated state. A one-time token with a TTL and no binding is replay-window limiting, **not** CSRF protection. **Current implementation:** `oauth_state` `HttpOnly` cookie carrying a 32-byte `randomBytes` binding value; SHA-256 digest held server-side; constant-time compare; consumed on first presentation regardless of outcome. **Verify the binding, not the token.** |
| Auth Provider | Discord (built-in), extensible via `OAuthFlow` base class |

## Architecture Patterns

- **Client secret handling:** `clientSecret` is passed through provider config and sent in token exchange POST bodies — it is never logged but lives in memory for the lifetime of the process
- **State binding is the CSRF control — review the binding, not the token:** **Requirement (RFC 6749 §10.12, RFC 9700):** the `state` presented on the callback must prove that the callback came from the same user agent that started the flow. Single-use plus a 10-minute TTL does *not* establish that — it bounds the replay window only, and presenting it as CSRF protection is precisely the login-CSRF defect fixed in #36 (see the rationale comment at `src/main.ts:150-158`). **Current implementation:** `getAuthorizationUrl()` issues a `randomUUID()` state *and* a 32-byte `randomBytes(BINDING_VALUE_BYTES)` binding value, storing only `{ bindingHash, createdAt }` — never the binding value itself; `/login/:provider` sets that value as the `HttpOnly`, `SameSite=Lax`, `Path=/` `oauth_state` cookie (`Secure` derived from the configured redirect-URI scheme) and **fails closed** — the state is withdrawn via `discardState()` and the login rejected with 500 if the cookie cannot be set; `handleCallback()` deletes the record on recognition, *before* the TTL and binding checks, so the endpoint is not a repeatable oracle, rejects an empty candidate list rather than skipping the check, and constant-time compares every presented candidate via `OAuth.digestsMatch`. **A review that confirms only single-use and TTL passes a vulnerable design.**
- **Session ID is a live bearer credential — check how it is *delivered*, not only how it is validated:** After a successful OAuth callback a UUID session id authenticates every subsequent request via the `session-id` header (`src/auth-request.ts:94`), and the session manager validates it against the in-memory `Map` with a TTL check. **Open defect — do not read the delivery path as settled design:** when `frontendCallbackUrl` is configured the id is handed to the frontend as a **URL query parameter** (`src/auth-request.ts:157-162`), which leaks a live credential into browser history, the `Referer` header of any outbound link from the landing page, proxy/CDN/server access logs, and any third-party script reading `location.search`. That is **#45** — open, `priority-high`, unresolved as of this template revision. **Requirement:** a bearer credential must never travel in a URL. Report it while it is still present.
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
