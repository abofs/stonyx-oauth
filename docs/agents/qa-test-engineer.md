# SME Template: QA Test Engineer — Stonyx OAuth

> **Inherits from:** `beatrix-shared/docs/framework/templates/agents/qa-test-engineer.md`
> Load the base template first, then layer this project-specific context on top.

## Project Context

**Repo:** `abofs/stonyx-oauth`
**Framework:** Authentication module for the Stonyx ecosystem
**Domain:** OAuth2 Authorization Code flow, session management, token handling, and provider integration

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Test Runner | QUnit (via `stonyx test`) |
| Mocking | Sinon |
| Build (tests) | `tsc -p tsconfig.test.json` (outputs to `dist-test/`) |
| Test Command | `npm run build && npm run build:test && stonyx test 'dist-test/test/**/*-test.js'` |
| Test Fixtures | `test/sample/` with mock providers and config |
| Test Config | `test/config/environment.js` with test provider credentials |

## Architecture Patterns

- **Three test tiers:** `test/unit/` for individual class logic (SessionManager, TokenManager, OAuthFlow), `test/integration/` for full auth flow with REST endpoints, `test/sample/` for mock providers
- **External API mocking:** Token exchange and user info fetch use native `fetch` — tests must stub `global.fetch` or use Sinon to intercept HTTP calls to provider endpoints
- **Singleton cleanup:** Tests must reset `OAuth.instance` to `null` between runs; the session manager and pending states Map accumulate state across tests

## Live Knowledge

- **SessionManager tests:** Verify session creation returns a UUID, TTL-based expiration works (test with time manipulation via Sinon fake timers), `validate()` returns `null` for expired sessions and auto-destroys them, and `destroy()` removes the session from the Map
- **TokenManager tests:** Test `getTokens()` calls `flow.exchangeCode()` and adds `expiresAt` timestamp, `refresh()` calls `flow.refreshAccessToken()`, and `isExpired()` correctly compares `Date.now()` against `expiresAt` — use Sinon clock for deterministic time
- **State token tests — the binding is the assertion that matters:** Verify that `getAuthorizationUrl()` returns a unique state token **and** a fresh per-client binding value, and that `pendingStates` stores only `{ bindingHash, createdAt }` — never the binding value in plaintext. For `handleCallback()`, cover: the record is consumed on recognition so a *rejected* state is still burned (the endpoint must not be a repeatable oracle against the binding value); expired records (>10 min) are rejected; a missing or unknown state throws; and — the cases this brief previously omitted — a callback presenting **no** binding value, **only empty** binding values, or **another client's** binding value is rejected, while a callback presenting the real binding value among several same-named candidates is accepted. Note *why* the binding cases are enumerated here rather than left to "edge cases": a suite written from the pre-#36 brief (unique token, single-use delete, TTL, missing/invalid throws) passes in full against a design with no client binding at all, which is exactly the defect #36 filed and #47 fixed.
- **OAuthFlow tests:** Test `buildAuthorizationUrl()` produces correct URL with all query params (client_id, redirect_uri, response_type, scope, state), `exchangeCode()` sends correct POST body and parses the response, and `normalizeUser()` base implementation wraps raw data in `{ raw }`
- **Integration tests:** The full callback flow (authorization URL -> code exchange -> user normalization -> session creation -> event emission) should be tested end-to-end with mocked HTTP responses; verify the `authenticate` event fires via `@stonyx/events`
- **Provider override tests:** Custom providers that override `exchangeCode()` (e.g., for providers requiring form-encoded token exchange) and `normalizeUser()` should be tested with their specific response formats
- **Edge cases:** Concurrent callback requests with the same state token (the second must fail — the first consumed it); a callback with an expired state token; a valid state with a failed token exchange; a valid state presented by a **different** client (the attacker-delivered-link case — the victim's browser carries no matching `oauth_state` cookie, so it must be rejected); a callback where the binding cookie was never set at all; a candidate list consisting only of decoys; `/login/:provider` failing closed when the binding cookie cannot be set (the state must be withdrawn via `discardState()`, not issued unbindable); and session validation after a server-simulated restart (cleared Map).
