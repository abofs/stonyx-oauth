# Architecture

How `@stonyx/oauth` is put together. Consumer-facing setup, routes and migration notes are in the [README](../README.md); security properties are in [security.md](security.md).

## Classes

| Class | Source | Import | Role |
|---|---|---|---|
| `OAuth` | `src/main.ts` | `@stonyx/oauth` | Singleton orchestrator: provider registry, pending states, session manager, ticket store |
| `OAuthFlow` | `src/oauth-flow.ts` | `@stonyx/oauth/oauth-flow` | Protocol-level OAuth2: authorization URL, code exchange, refresh, user info. Base class for providers |
| `TokenManager` | `src/token-manager.ts` | `@stonyx/oauth/token-manager` | Token lifecycle over one flow: `getTokens()`, `refresh()`, `revoke()`, `isExpired()` |
| `SessionManager` | `src/session-manager.ts` | `@stonyx/oauth/session-manager` | Session create / validate / destroy with TTL expiry |
| `TicketStore` | `src/ticket-store.ts` | not exported | Single-use, 60-second exchange tickets that stand in for the session id on the wire. `OAuth` reaches it only through `issueExchangeTicket()` / `redeemExchangeTicket()` |
| `AuthRequest` | `src/auth-request.ts` | `@stonyx/oauth/auth-request` | The `/auth/*` route handlers |
| `DiscordProvider` | `src/providers/discord.ts` | `@stonyx/oauth/providers/discord` | Built-in Discord provider |

Every exported class signature above is public API: a change to one is a breaking change for consumers.

## Lifecycle

`OAuth` is a singleton (`OAuth.instance`); a second `new OAuth()` returns the first instance. `init()`:

1. Defines the `oauth` log type (config `logColor`, default `magenta`; `logMethod`, default `oauth`).
2. For each key in `config.oauth.providers`, imports the provider: from `` `${config.rootPath}/${module}` `` when the provider config has a `module` key, otherwise from the module's own `./providers/<name>.js` (built-in providers only). The default export is constructed with the provider config, and a `TokenManager` is created for it.
3. Creates the `SessionManager` with `sessionDuration` (seconds; default `86400` from the module's `config/environment.js`).
4. Waits for `@stonyx/rest-server` with `waitForModule('rest-server')`, then calls `RestServer.instance.mountRoute(AuthRequest, { name: 'auth', options: this })`. The `options` object is the `OAuth` instance the route handlers call into, so a change on either side of that call breaks the integration.

Because the routes include `POST /auth/session`, the rest server's CORS methods must include `POST` (README: Deployment prerequisites).

## Login flow

`handleCallback(provider, code, state, bindingValues)` consumes and checks the state (see [security.md](security.md#state-binding-is-the-csrf-control)), then:

1. `tokenManager.getTokens(code)`: `flow.exchangeCode(code)` plus an absolute `expiresAt`.
2. `flow.fetchUserInfo(accessToken)` and `flow.normalizeUser(rawUser)`.
3. `emit('authenticate', user)` through `@stonyx/events`. The event name is registered with `setup(['authenticate'])` when `src/main.ts` loads; subscribers must use exactly `'authenticate'` and receive the normalized user. The emit is awaited before the session is created.
4. `sessionManager.create(user, tokens)` returns `{ sessionId, user, expiresAt }`.

## Providers

- A provider extends `OAuthFlow` and supplies `authorizationUrl`, `tokenUrl` and `userInfoUrl` to `super()`. It can override `exchangeCode()`, `normalizeUser()` and `revokeToken()` (README: Custom Providers).
- The base `exchangeCode()` and `refreshAccessToken()` POST `application/json`. A provider that requires `application/x-www-form-urlencoded` (Discord does) overrides `exchangeCode()`.
- The base `normalizeUser()` returns `{ raw: rawUser }`, so a provider that does not override it hands the raw provider response to `authenticate` subscribers and into the session.
- The base `revokeToken()` is a no-op.
- `clientId`, `clientSecret` and `redirectUri` are not validated. A missing value is stringified into the request (for example `client_id=undefined` in the authorization URL) and fails at the provider, not at `init()`.

## Tokens and sessions

- Token refresh is not automatic. `TokenManager.refresh()` exists, but nothing calls it; a consumer checks `isExpired()` and refreshes itself. There is no background refresh loop.
- `isExpired()` treats missing `expiresAt` as expired.
- Sessions live in an in-memory `Map<sessionId, { user, tokens, expiresAt }>`. A restart loses every session; there is no external session store.
- `validate()` returns `null` for an unknown or expired session and deletes an expired one when it is read. Nothing sweeps sessions that are never read again.
- `sessionDuration` is not validated: zero or a negative value creates sessions that are already expired.
- `logout()` destroys the session only. It does not call `revokeToken()`, so the provider access token stays valid until the provider expires it.

## Testing notes

- Tests reset `OAuth.instance = null` between runs, because the singleton's pending states and session map persist across tests otherwise.
- Provider HTTP calls use the global `fetch`; tests replace `globalThis.fetch` or stub with Sinon.
- `test/sample/providers/mock.ts` is the mock provider; `test/config/environment.ts` loads it through the `module` key.
