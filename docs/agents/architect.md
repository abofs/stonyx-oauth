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
| State Tokens | `crypto.randomUUID()` state, plus a 32-byte `randomBytes(BINDING_VALUE_BYTES).toString('base64url')` client binding value (`src/main.ts:167-168`) delivered as the `oauth_state` `HttpOnly` cookie; `pendingStates` stores `{ bindingHash, createdAt }` — the SHA-256 digest, never the binding value (`src/main.ts:170-174`) |
| Exchange Tickets | 32-byte `randomBytes(TICKET_BYTES).toString('base64url')`, minted per successful callback by `TicketStore` (`src/ticket-store.ts:112-116`), independent entropy never derived from the session id; keyed in the `Map` by its **SHA-256 digest, never by the ticket** (`src/ticket-store.ts:114`) — the same digest-only discipline as `pendingStates`' `bindingHash`, not a divergence from it |
| Built-in Provider | Discord |
| Testing | QUnit + Sinon |

## Architecture Patterns

- **Singleton OAuth orchestrator:** `OAuth` class enforces single instance; holds provider registry, pending state tokens, and session manager — accessed by the auth request handler
- **Provider pattern:** Each OAuth2 provider extends `OAuthFlow` base class, overriding `exchangeCode()`, `normalizeUser()`, and optionally `revokeToken()` — providers are dynamically imported from `src/providers/{name}.js` or a custom module path
- **Four-class separation:** `OAuthFlow` handles protocol-level OAuth2 (authorization URLs, token exchange, user info fetch), `TokenManager` wraps token lifecycle (exchange, refresh, expiry checks), `SessionManager` handles session CRUD with TTL expiration, and `TicketStore` (`src/ticket-store.ts`) holds the single-use, 60-second exchange tickets that stand in for a session id on the wire (#45). `OAuth` delegates to the last of these through `issueExchangeTicket` / `redeemExchangeTicket` (`src/main.ts:243-250`) rather than exposing the store
- **Self-registering routes:** During `init()`, the module waits for `@stonyx/rest-server` via `waitForModule()`, then calls `RestServer.instance.mountRoute(AuthRequest, ...)` to register all auth endpoints at `/auth/*`. `AuthRequest.handlers` carries a `get` map and, since #45, a `post` map — `POST /auth/session` (`src/auth-request.ts:222-257`) is the module's only non-`GET` route. That makes the module dependent on `config.restServer.methods` including `POST`: a deployment pinned to `REST_CORS_METHODS=GET` served every route before #45 and has no working login after it
- **Session delivery is a two-step exchange, not a redirect payload:** the callback mints the session, then hands the browser a single-use ticket in the URL **fragment** (`src/auth-request.ts:195-199`), which the landing page redeems once at `POST /auth/session`. A fragment reaches no server, so the ticket is absent from access logs, CDNs and `Referer`; history and page scripts are why it is still single-use and 60-second. Two architectural consequences: delivery now requires a **second request that must land on the same process** (the ticket store is per-instance and in-memory, so this adds worker affinity to a step that used to be a single response), and it requires a **browser-side** callback handler (a server-side reader cannot see a fragment at all)
- **State binding, not state validation, is the CSRF control:** **Requirement (RFC 6749 §10.12, RFC 9700):** the `state` returned on the callback must be bound to the user agent that started the flow. A `pendingStates` entry that is single-use and expires after 10 minutes satisfies neither — it bounds the replay window only, and treating it as CSRF protection was the login-CSRF defect fixed in #36. **Current implementation:** `getAuthorizationUrl()` issues the state alongside a per-client binding value and stores only its digest; `/login/:provider` sets the binding value as the `oauth_state` cookie and fails closed if it cannot, withdrawing the state via `discardState()`; `handleCallback()` consumes the record on recognition before any check, then constant-time compares the presented candidates against `bindingHash`. Any design change here must preserve the binding — the TTL and the single-use delete are secondary properties.
- **Event-driven authentication:** After successful token exchange and user normalization, an `authenticate` event is emitted via `@stonyx/events` — downstream modules can subscribe to react to logins (e.g., create ORM records, sync Discord roles)

## Live Knowledge

- Sessions are in-memory only (`Map<sessionId, SessionData>`) — server restart loses all sessions; production deployments need external session storage or accept re-authentication
- The `frontendCallbackUrl` config option redirects the OAuth callback to a frontend URL carrying a **single-use 60-second exchange ticket in the fragment** — if not set, the callback returns `{ sessionId, expiresAt }` as a JSON body directly. **#45 is fixed; the session id no longer appears in a URL under any name.** The invariant to preserve in any architecture work touching the callback response: the session id is the live bearer credential (`session-id` header), so it must never be written into a URL, and neither must anything that authenticates or redeems on its behalf beyond one short-lived single use. **Known residual, disclosed and tracked, not a defect to re-report:** nothing binds a ticket to the client that started the flow; binding needs a cookie the cross-origin exchange cannot carry, blocked on `abofs/stonyx-rest-server#63` (CORS `credentials` unsupported).
- Token refresh is implemented in `TokenManager` but not automatically triggered — consumers must call `refresh()` when `isExpired()` returns true; there is no background refresh loop
- The 10-minute pending-state expiry (`STATE_TTL_MS`, `src/main.ts:18`, applied at `src/main.ts:206` and reused as the binding cookie's `Max-Age`) is hardcoded — long authorization flows (e.g., a user creating a new provider account) may time out. This is a **replay-window** bound and a usability limit, not the CSRF control; widening it lengthens the window in which a bound state stays live, and does not weaken the binding itself.
- Custom providers can be loaded from arbitrary paths via the `module` config key — this dynamic import is relative to `config.rootPath`, so path resolution depends on the project's working directory
- The `normalizeUser()` base implementation returns `{ raw: rawUser }` — providers that don't override this expose the raw API response, which may contain unexpected fields
