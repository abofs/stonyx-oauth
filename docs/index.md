# @stonyx/oauth — Architecture

OAuth2 authentication module for the Stonyx framework. It implements a generic OAuth2
Authorization Code flow (RFC 6749) behind a pluggable provider pattern: a provider only has to
supply its authorization/token/user-info URLs and, where its wire format diverges from the
default JSON POST body, override a handful of hooks. The module ships one officially supported
provider, Discord. Like `@stonyx/rest-server`, this is a library, not a standalone service: it
registers its own routes (`/auth/*`) onto a host application's `RestServer` instance and keeps
all of its own state — pending OAuth `state` records, exchange tickets, and sessions — in process
memory.

## Areas

- **The `OAuthFlow` base class and provider pattern.** `src/oauth-flow.ts` defines the
  protocol-level mechanics shared by every provider: `buildAuthorizationUrl()`, `exchangeCode()`,
  `refreshAccessToken()`, `fetchUserInfo()`, and the identity hook `normalizeUser()` (default:
  `{ raw: rawUser }`). A provider extends it, passes its three endpoint URLs to `super()`, and
  overrides whichever hooks its wire format requires — `src/providers/discord.ts` overrides
  `exchangeCode()` (Discord requires `application/x-www-form-urlencoded`, not the base class's
  JSON) and `normalizeUser()`. Discord is the only officially supported provider; see the
  README's [Officially Supported Providers](../README.md#officially-supported-providers) and
  [Custom Providers](../README.md#custom-providers) sections for how to add another. Full class
  table and lifecycle: [architecture.md](architecture.md#classes).

- **The `authenticate` event.** `src/main.ts` registers the event name with
  `setup(['authenticate'])` (from `@stonyx/events`) at module load. After a successful callback,
  `OAuth.handleCallback()` normalizes the user and `await emit('authenticate', user)`s it —
  awaited before the session is created, so a subscriber's failure propagates into the callback's
  own error path. See [architecture.md](architecture.md#login-flow) for the full four-step
  sequence (`getTokens` -> `fetchUserInfo` -> `normalizeUser` -> `emit` -> `sessionManager.create`).

- **Token handling.** `src/token-manager.ts`'s `TokenManager` wraps one provider flow and adds an
  absolute `expiresAt` to whatever `exchangeCode()`/`refreshAccessToken()` return. Refresh is
  **not automatic** — `refresh()` exists but nothing calls it; a consumer checks `isExpired()`
  itself and refreshes on demand. There is no background refresh loop. Detail:
  [architecture.md](architecture.md#tokens-and-sessions).

- **In-memory session management.** `src/session-manager.ts`'s `SessionManager` holds sessions in
  a plain `Map<sessionId, { user, tokens, expiresAt }>` with TTL expiry checked on read
  (`validate()`); nothing sweeps a session that is never read again, and a process restart loses
  every session. The session id is a bearer credential presented via the `session-id` header on
  `GET /auth` and `GET /auth/logout`. See [security.md](security.md#the-session-id-is-a-bearer-credential)
  for what that implies and [architecture.md](architecture.md#tokens-and-sessions) for the rest of
  the lifecycle gaps (no cap, no sweep, `logout()` does not revoke the provider token).

- **The exchange-ticket / session-delivery mechanism.** `GET /auth/callback/:provider` never puts
  the session id in a URL. With `frontendCallbackUrl` configured, it mints a single-use,
  60-second exchange ticket (`src/ticket-store.ts`, keyed by the ticket's SHA-256 digest, never by
  the ticket itself) and redirects to `` `${frontendCallbackUrl}#ticket=...&expiresAt=...` `` —
  **in the URL fragment**, not the query string, so the ticket never reaches any server-side log
  (breaking change [#45](../README.md#breaking-changes-45)). The landing page redeems it with
  `POST /auth/session` (`application/json`, `{ "ticket": "..." }`), which returns
  `{ sessionId, expiresAt }` exactly once. Without `frontendCallbackUrl`, the callback instead
  returns the session object directly as its response body — there is no URL involved, so #45
  does not apply to that deployment shape. Full HTTP contract, migration snippet, and the
  `REST_CORS_METHODS`/`REST_CORS_ORIGIN` prerequisites this depends on:
  [README.md#session-delivery--the-exchange-ticket](../README.md#session-delivery--the-exchange-ticket);
  internals and residual risk: [security.md](security.md#the-session-id-is-a-bearer-credential).

- **CSRF protection — the `oauth_state` cookie.** `GET /auth/login/:provider` issues an
  OAuth2 `state` plus a separate, client-held binding value, sets the binding value as an
  `HttpOnly`, `SameSite=Lax` cookie named `oauth_state`, and stores only its SHA-256 digest
  server-side (`OAuth.pendingStates`, `src/main.ts`). `GET /auth/callback/:provider` accepts the
  `state` only when the caller also presents a cookie value matching that digest
  (`OAuth.anyCandidateMatches`), and fails closed (`500`) if the cookie could not be set at login
  time. This closed the login-CSRF defect in breaking change
  [#36](../README.md#breaking-changes-36) — a plain `state`-membership check alone verifies replay
  window, not origin, so without the binding an attacker could harvest their own `state`/`code`
  and hand them to a victim. Verified against the current source for this review: `getAuthorizationUrl()`
  returns `{ url, stateToken, bindingValue }`, `handleCallback(providerName, code, stateToken,
  bindingValues: readonly string[])` takes the four-argument shape the README documents, and
  `pendingStates` values are `{ bindingHash, createdAt }` — the README's two "Breaking changes"
  sections (#36 and #45) match the code as it stands today; see
  [security.md](security.md#state-binding-is-the-csrf-control) for the full control and the
  regression cases the test suite pins.

## Build, Run, Test

Prerequisites: Node v24.13.0, pnpm 10.23.0.

```bash
pnpm install --frozen-lockfile   # verified: installs clean, no lockfile changes
pnpm build                       # tsc -> dist/ (src/ only)
pnpm test                        # pnpm build, then QUnit over test/**/*-test.ts via tsx (NODE_ENV=test)
```

Verified in this environment on 2026-11-02: `pnpm install --frozen-lockfile` completed with no
lockfile changes. `pnpm test` passed all 90 assertions with zero failures.

There is **no script literally named `typecheck`**. The closest thing, `build:test`
(`tsc -p tsconfig.test.json`, which additionally type-checks `test/` and `config/`), is **not**
invoked by `pnpm test` and fails as run standalone in this environment:

```
test/setup.ts(14,31): error TS2307: Cannot find module 'url' or its corresponding type declarations.
test/setup.ts(16,13): error TS2580: Cannot find name 'process'. ...
test/zz-exit-test.ts(14,22): error TS2580: Cannot find name 'process'. ...
(and more of the same shape, all in test/ files)
```

This repo deliberately does not depend on `@types/node` (see `src/types/node.d.ts`'s own
comment: "this repo declares its own node shims rather than depending on `@types/node`, so only
the surface actually used is typed"). `src/` only imports `node:crypto`, which has a hand-written
shim, so `pnpm build` (plain `tsc -p tsconfig.json`, `src/` only) is clean. `test/` and `config/`
import `node:fs`, `node:path`, `node:child_process`, `node:url`, and reference ambient globals
(`process`, `setImmediate`) that have no shim, so `build:test`'s wider `include` fails
type-checking on those files. Since `pnpm test` runs tests through `tsx` (which transpiles, not
type-checks) rather than through `build:test`, this does not affect `pnpm test`'s outcome, but
`build:test` as a standalone script does not currently work.

## Delivery

`@stonyx/oauth` is published to npm as a library and consumed inside a Node.js backend process —
there is no web, iOS, or Android surface of its own. It depends on `@stonyx/rest-server` (as a
peer dependency) to expose any HTTP surface at all: on `init()`, it waits for the `rest-server`
module (`waitForModule('rest-server')`) and then calls
`RestServer.instance.mountRoute(AuthRequest, { name: 'auth', options: this })` to register its
`/auth/*` routes onto the host application's single Express instance. Those routes become part
of *the consuming application's* HTTP API surface, the same way any other `@stonyx/rest-server`
route file would — `@stonyx/oauth` is not itself a deployed service and has no listener of its
own.

## Dependencies

- **`stonyx`** — the framework core: module lifecycle, `stonyx/config`, `stonyx/log`,
  `waitForModule()`. Not owned by this package.
- **`@stonyx/events`** — owns the pub/sub mechanism (`setup()`/`emit()`) this module uses to
  publish the `authenticate` event after a successful login; subscribing and reacting to that
  event is entirely the consumer's responsibility, not this module's.
- **`@stonyx/rest-server`** (peer dependency, `>=0.2.1-beta.11`) — owns HTTP routing/dispatch,
  CORS, and JSON body parsing; this module mounts its routes through
  `RestServer.instance.mountRoute()` and otherwise has no HTTP machinery of its own. Per that
  module's own [docs/index.md](../../stonyx-rest-server/docs/index.md) (read directly from its
  repo path for this review — it exists and matches): `RestServer` wraps one Express 5 instance,
  provides CORS/JSON middleware and dynamic route mounting, and `mountRoute()`'s contract
  (instantiate, call `registerCalls()`, mount at `/<name>`) is the exact integration point this
  module uses. One concrete coupling worth noting here: the exchange-ticket mechanism above
  depends on `@stonyx/rest-server` answering `POST /auth/session`'s CORS preflight with `POST`
  included in `REST_CORS_METHODS` — see the README's
  [deployment prerequisites](../README.md#deployment-prerequisites--the-servers-own-cors-configuration).

**Provider wire protocols are out of this module's scope.** Discord's own OAuth2 endpoints
(`https://discord.com/oauth2/authorize`, `/api/oauth2/token`, `/api/users/@me`) and their request
formats are owned and versioned by Discord, not by `stonyx-oauth` — this module only encodes how
to talk to them inside `src/providers/discord.ts`. Testing against a real provider's live
endpoints is out of scope for this module's test suite: `test/unit/providers/discord-test.ts` and
`test/unit/oauth-flow-test.ts` stub `fetch` directly, and `test/sample/providers/mock.ts` is a
full mock provider used by the integration suite (`test/integration/oauth-test.ts`) to exercise
the login/callback/exchange flow end-to-end without any network call. A provider's actual
compliance with its vendor's documented OAuth2 behaviour is verified by that vendor's own
contract, not by this repository.
