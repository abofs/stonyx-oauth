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
| State Tokens | `crypto.randomUUID()` |
| Built-in Provider | Discord |
| Testing | QUnit + Sinon |

## Architecture Patterns

- **Singleton OAuth orchestrator:** `OAuth` class enforces single instance; holds provider registry, `StateStore`, and session manager — accessed by the auth request handler
- **Provider pattern:** Each OAuth2 provider extends `OAuthFlow` base class, overriding `exchangeCode()`, `normalizeUser()`, and optionally `revokeToken()` — providers are dynamically imported from `src/providers/{name}.js` or a custom module path
- **Three-class separation:** `OAuthFlow` handles protocol-level OAuth2 (authorization URLs, token exchange, user info fetch), `TokenManager` wraps token lifecycle (exchange, refresh, expiry checks), `SessionManager` handles session CRUD with TTL expiration
- **Self-registering routes:** During `init()`, the module waits for `@stonyx/rest-server` via `waitForModule()`, then calls `RestServer.instance.mountRoute(AuthRequest, ...)` to register all auth endpoints at `/auth/*`
- **State token validation (#36):** CSRF protection via `StateStore` — a `crypto.randomUUID()` state bound to a 32-byte client-held binding value. `StateStore.pending` maps the state to `{ provider, bindingHash, createdAt }`; the plaintext binding value is held only by the client, as an HttpOnly cookie. A callback is accepted only when the presented binding value hashes to `bindingHash`, for the same provider, within `STATE_TTL_MS`. States are single-use and are consumed on any callback that presents a recognised state, successful or not
- **Event-driven authentication:** After successful token exchange and user normalization, an `authenticate` event is emitted via `@stonyx/events` — downstream modules can subscribe to react to logins (e.g., create ORM records, sync Discord roles)

## Live Knowledge

- Sessions are in-memory only (`Map<sessionId, SessionData>`) — server restart loses all sessions; production deployments need external session storage or accept re-authentication
- The `frontendCallbackUrl` config option allows redirecting the OAuth callback to a frontend URL with the session ID — if not set, the callback returns JSON directly
- Token refresh is implemented in `TokenManager` but not automatically triggered — consumers must call `refresh()` when `isExpired()` returns true; there is no background refresh loop
- The 10-minute state token expiry lives on `StateStore.ttl`, defaulting to `STATE_TTL_MS` in `src/constants.ts` — long authorization flows (e.g., user creating a new provider account) may time out
- Custom providers can be loaded from arbitrary paths via the `module` config key — this dynamic import is relative to `config.rootPath`, so path resolution depends on the project's working directory
- The `normalizeUser()` base implementation returns `{ raw: rawUser }` — providers that don't override this expose the raw API response, which may contain unexpected fields
