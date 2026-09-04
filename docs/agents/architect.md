# SME Template: Architect — Stonyx OAuth

> **Inherits from:** `beatrix-shared/docs/framework/templates/agents/architect.md`
> Load the base template first, then layer this project-specific context on top.

## Project Context

**Repo:** `abofs/stonyx-oauth`
**Framework:** Authentication module for the Stonyx ecosystem
**Domain:** OAuth2 Authorization Code flow with a provider pattern, in-memory session management, token lifecycle handling, and REST route self-registration for login/callback/logout/validate endpoints

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (ES Modules) |
| Framework Integration | Stonyx (auto-discovered as `@stonyx/oauth` module) |
| HTTP | `@stonyx/rest-server` (peer dependency — routes mount onto the shared server) |
| Events | `@stonyx/events` (emits `authenticate` event on successful login) |
| Session Storage | In-memory `Map` (lost on restart) |
| Token Exchange | Native `fetch` API |
| State Tokens | `crypto.randomUUID()` state, plus a 32-byte `randomBytes(BINDING_VALUE_BYTES).toString('base64url')` client binding value (`src/main.ts:163-164`) delivered as the `oauth_state` `HttpOnly` cookie; `pendingStates` stores `{ bindingHash, createdAt }` — the SHA-256 digest, never the binding value (`src/main.ts:166-168`) |
| Built-in Provider | Discord |
| Testing | QUnit + Sinon |

## Architecture Patterns

- **Singleton OAuth orchestrator:** `OAuth` class enforces single instance; holds provider registry, pending state tokens, and session manager — accessed by the auth request handler
- **Provider pattern:** Each OAuth2 provider extends `OAuthFlow` base class, overriding `exchangeCode()`, `normalizeUser()`, and optionally `revokeToken()` — providers are dynamically imported from `src/providers/{name}.js` or a custom module path
- **Three-class separation:** `OAuthFlow` handles protocol-level OAuth2 (authorization URLs, token exchange, user info fetch), `TokenManager` wraps token lifecycle (exchange, refresh, expiry checks), `SessionManager` handles session CRUD with TTL expiration
- **Self-registering routes:** During `init()`, the module waits for `@stonyx/rest-server` via `waitForModule()`, then calls `RestServer.instance.mountRoute(AuthRequest, ...)` to register all auth endpoints at `/auth/*`
- **State binding, not state validation, is the CSRF control:** **Requirement (RFC 6749 §10.12, RFC 9700):** the `state` returned on the callback must be bound to the user agent that started the flow. A `pendingStates` entry that is single-use and expires after 10 minutes satisfies neither — it bounds the replay window only, and treating it as CSRF protection was the login-CSRF defect fixed in #36. **Current implementation:** `getAuthorizationUrl()` issues the state alongside a per-client binding value and stores only its digest; `/login/:provider` sets the binding value as the `oauth_state` cookie and fails closed if it cannot, withdrawing the state via `discardState()`; `handleCallback()` consumes the record on recognition before any check, then constant-time compares the presented candidates against `bindingHash`. Any design change here must preserve the binding — the TTL and the single-use delete are secondary properties.
- **Event-driven authentication:** After successful token exchange and user normalization, an `authenticate` event is emitted via `@stonyx/events` — downstream modules can subscribe to react to logins (e.g., create ORM records, sync Discord roles)

## Live Knowledge

- Sessions are in-memory only (`Map<sessionId, SessionData>`) — server restart loses all sessions; production deployments need external session storage or accept re-authentication
- The `frontendCallbackUrl` config option redirects the OAuth callback to a frontend URL **with the session id in the query string** — if not set, the callback returns JSON directly. **Do not treat the query-string delivery as intended design:** the session id is the live bearer credential (`session-id` header), and putting it in a URL leaks it to history, `Referer`, and access logs. That is **#45**, open and `priority-high`. Any architecture work touching the callback response should resolve it rather than build on it.
- Token refresh is implemented in `TokenManager` but not automatically triggered — consumers must call `refresh()` when `isExpired()` returns true; there is no background refresh loop
- The 10-minute pending-state expiry (`STATE_TTL_MS`, `src/main.ts:15`, applied at `src/main.ts:202` and reused as the binding cookie's `Max-Age`) is hardcoded — long authorization flows (e.g., a user creating a new provider account) may time out. This is a **replay-window** bound and a usability limit, not the CSRF control; widening it lengthens the window in which a bound state stays live, and does not weaken the binding itself.
- Custom providers can be loaded from arbitrary paths via the `module` config key — this dynamic import is relative to `config.rootPath`, so path resolution depends on the project's working directory
- The `normalizeUser()` base implementation returns `{ raw: rawUser }` — providers that don't override this expose the raw API response, which may contain unexpected fields
