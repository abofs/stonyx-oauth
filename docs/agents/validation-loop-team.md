# SME Template: Validation Loop Team — Stonyx OAuth

> **Inherits from:** `beatrix-shared/docs/framework/templates/agents/validation-loop-team.md`
> Load the base template first, then layer this project-specific context on top.

## Project Context

**Repo:** `abofs/stonyx-oauth`
**Framework:** Authentication module for the Stonyx ecosystem
**Domain:** OAuth2 Authorization Code flow with provider pattern, session management, token lifecycle, and REST endpoint self-registration

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | TypeScript (ES Modules) |
| Runtime | Node.js |
| Testing | QUnit + Sinon |
| CI | GitHub Actions (`ci.yml`) |
| Peer Dependencies | `@stonyx/rest-server` (required for route mounting) |

## Architecture Patterns

- **Cross-module dependency:** OAuth depends on rest-server being initialized first (uses `waitForModule('rest-server')`) — validation must confirm this ordering works and that missing rest-server produces a clear error
- **Provider dynamic import:** Providers are loaded via `import()` at runtime from either `./providers/{name}.js` or a custom `module` path — validation must cover both built-in and custom provider resolution
- **Stateful singleton with multiple concerns:** The `OAuth` instance holds providers, pending states, and session manager — all three are independent subsystems that share the singleton lifecycle

## Live Knowledge

- **Module integration contract:** OAuth calls `RestServer.instance.mountRoute(AuthRequest, { name: 'auth', options: this })` — the `options` parameter passes the OAuth instance to the AuthRequest constructor; changes to either side break the integration
- **Event contract:** The `authenticate` event name is registered via `setup(['authenticate'])` at module load time — any subscriber must use the exact string `'authenticate'`; the emitted payload is the normalized user object from the provider
- **Provider config surface:** Each provider config requires `clientId`, `clientSecret`, `redirectUri`, and optionally `scopes` and `module` — missing required fields cause runtime errors during `init()`, not at config parse time
- **Session duration default:** `sessionDuration` defaults to `86400` (24 hours) from the module's `config/environment.js` — this can be overridden in the project's `environment.js` but is not validated (negative or zero values create immediately-expiring sessions)
- **Published package includes `src/`** (per `files` in package.json) — validate that source files don't contain hardcoded credentials, test-only code, or debug logging
- **Exports surface:** The package exports five subpaths (`oauth-flow`, `auth-request`, `session-manager`, `token-manager`, `providers/discord`) — each is a public API contract; changes to any exported class signature are breaking changes for consumer projects
- **No persistent session storage:** All sessions live in a `Map` — validation for production readiness should flag this limitation and verify that session loss on restart is acceptable for the deployment context
