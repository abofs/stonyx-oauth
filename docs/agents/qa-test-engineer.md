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
- **State token tests:** Verify that `getAuthorizationUrl()` generates a unique state token and stores it in `pendingStates`, `handleCallback()` validates and deletes the state token (single-use), expired tokens (>10 min) are rejected, and missing/invalid tokens throw
- **OAuthFlow tests:** Test `buildAuthorizationUrl()` produces correct URL with all query params (client_id, redirect_uri, response_type, scope, state), `exchangeCode()` sends correct POST body and parses the response, and `normalizeUser()` base implementation wraps raw data in `{ raw }`
- **Integration tests:** The full callback flow (authorization URL -> code exchange -> user normalization -> session creation -> event emission) should be tested end-to-end with mocked HTTP responses; verify the `authenticate` event fires via `@stonyx/events`
- **Provider override tests:** Custom providers that override `exchangeCode()` (e.g., for providers requiring form-encoded token exchange) and `normalizeUser()` should be tested with their specific response formats
- **Edge cases:** Test concurrent callback requests with the same state token (second should fail), callback with an expired state token, callback with a valid state but failed token exchange, and session validation after server-simulated restart (cleared Map)
