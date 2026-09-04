[![CI](https://github.com/abofs/stonyx-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/abofs/stonyx-oauth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@stonyx/oauth.svg)](https://www.npmjs.com/package/@stonyx/oauth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# @stonyx/oauth

OAuth2 authentication module for the Stonyx framework. Provides a generic OAuth2 Authorization Code flow with a provider pattern — ship with Discord support, extensible to any OAuth2 provider.

## Setup

Add as a devDependency to your Stonyx project:

```bash
npm install @stonyx/oauth
```

Requires `@stonyx/rest-server` as a peer dependency.

The module auto-discovers and initializes via the Stonyx module loader — no changes needed in `app.js`.

## Configuration

Add an `oauth` section to your project's `config/environment.js`:

```javascript
export default {
  // ... other config

  oauth: {
    providers: {
      discord: {
        clientId: process.env.DISCORD_OAUTH_CLIENT_ID,
        clientSecret: process.env.DISCORD_OAUTH_CLIENT_SECRET,
        redirectUri: process.env.DISCORD_OAUTH_REDIRECT_URI || 'http://localhost:4200/auth/callback/discord',
        scopes: ['identify'],
      }
    }
  }
};
```

By default no providers are enabled. Add providers as keys in the `providers` object.

### Config Options

| Option | Default | Description |
|--------|---------|-------------|
| `providers` | `{}` | Map of provider name to config |
| `sessionDuration` | `86400` | Session TTL in seconds (default: 24h) |
| `frontendCallbackUrl` | `null` | Where `GET /auth/callback/:provider` sends the browser after a successful login. **Setting this changes the callback's response shape**: unset, the callback returns `{ sessionId, expiresAt }` as a JSON body; set, it issues a `302` to this URL carrying a single-use exchange ticket in the fragment, which the landing page redeems at `POST /auth/session`. See [Session delivery](#session-delivery--the-exchange-ticket). |

`TICKET_TTL_MS` (60s, the exchange ticket's lifetime) and `STATE_TTL_MS` (600s, the `oauth_state` lifetime) are module constants with no config key today. If your landing page cannot reach its earliest hook inside 60 seconds on a cold boot, the exchange returns `400` and the login dies — see [stonyx-oauth#59](https://github.com/abofs/stonyx-oauth/issues/59).

## Routes

The module self-registers the following routes on the rest server:

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/auth` | Validate session — send `session-id` header, returns user or 401 |
| `GET` | `/auth/login/:provider` | Redirects to provider's OAuth2 authorization page |
| `GET` | `/auth/callback/:provider` | OAuth2 callback — exchanges code for tokens, creates session, redirects with a single-use `ticket` in the URL **fragment** |
| `POST` | `/auth/session` | Redeems the `ticket` for the session id — `application/json`, `{ "ticket": "..." }` |
| `GET` | `/auth/logout` | Destroys session (send `session-id` header) |

## Officially Supported Providers

### Discord

1. Create a Discord application at https://discord.com/developers/applications
2. Under OAuth2, add a redirect URL matching your `redirectUri` config
3. Copy the Client ID and Client Secret to your environment variables
4. Available scopes: `identify`, `email`, `guilds` (see Discord docs)

## Custom Providers

Create a provider by extending `OAuthFlow`:

```javascript
import OAuthFlow from '@stonyx/oauth/oauth-flow';

export default class MyProvider extends OAuthFlow {
  constructor(config) {
    super({
      ...config,
      authorizationUrl: 'https://my-provider.com/oauth/authorize',
      tokenUrl: 'https://my-provider.com/oauth/token',
      userInfoUrl: 'https://my-provider.com/api/me',
    });
  }

  // Override if the provider uses a different content type for token exchange
  async exchangeCode(code) { ... }

  // Map provider-specific user data to a standard shape
  normalizeUser(rawUser) {
    return {
      id: rawUser.id,
      username: rawUser.login,
      displayName: rawUser.name,
      avatar: rawUser.avatar_url,
      email: rawUser.email,
      raw: rawUser,
    };
  }
}
```

Place the file at `src/providers/<name>.js` where `<name>` matches the key in your config's `providers` object.

Alternatively, specify a custom module path in the provider config:

```javascript
providers: {
  custom: {
    clientId: '...',
    clientSecret: '...',
    module: './lib/my-custom-provider.js',
  }
}
```

## Login CSRF protection — the `oauth_state` cookie

### Breaking changes (#36)

**As of the fix for [#36](https://github.com/abofs/stonyx-oauth/issues/36).** Two separate breaks — an integration can hit either one independently.

**1. The login flow now requires a cookie jar.** A client that cannot hold a cookie between `/auth/login/:provider` and `/auth/callback/:provider` can no longer complete a login. That is the point of the change — see [Migration](#migration-from-a-cookie-less-client) below.

**2. The JS API changed shape.** This one is invisible to anyone who only reads the cookie disclosure above. If you import the module's default export and call it directly — wrapping it, monkeypatching it, or driving it in tests — three things changed:

| | Before | After |
|---|--------|-------|
| `getAuthorizationUrl(provider)` | returns the authorization URL as a `string` | returns `{ url, stateToken, bindingValue }` |
| `handleCallback(provider, code, state)` | three arguments | requires a fourth, `bindingValues: readonly string[]` — every value the caller presented under the `oauth_state` cookie name |
| `pendingStates` values | `number` (a creation timestamp) | `{ bindingHash, createdAt }` |

None of these throws at import time, and a `typeof … === 'function'` surface check passes on all three: the arity and the return type change, not the presence. Callers must be updated by inspection.

The HTTP contract is otherwise unchanged — the [route table](#routes) is the same, no config key was added or changed, and both routes still `302` on their success paths. One status is new: `/auth/login/:provider` returns `500` when the binding cookie cannot be set, which it never did before (see below).

`GET /auth/login/:provider` issues an `oauth_state` cookie carrying a per-flow binding value, and keeps only its SHA-256 server-side. `GET /auth/callback/:provider` accepts an OAuth2 `state` only from a caller that also presents the matching cookie value.

Without it, `state` was verified by membership in a server-side map plus an age bound, and nothing else. There was no value the browser that started the flow carried that another browser did not, so an attacker could start a login, harvest their own `state` and `code`, deliver them to a victim over a plain link, and log that victim into the *attacker's* account (RFC 6749 §10.12, RFC 9700). The victim's own account and data are not exposed; what is at risk is whatever they author afterwards, believing the session is theirs.

### Cookie attributes

| Attribute | Value | Why |
|-----------|-------|-----|
| Name | `oauth_state` | Issued at login, cleared on a successful callback. The *state* is single-use; the cookie name is fixed, so it is not — see [Concurrent logins](#concurrent-logins-in-the-same-browser) |
| `HttpOnly` | always | Script must not be able to read or forge the binding value |
| `SameSite` | `Lax` | **Required.** The callback is a cross-site, top-level GET navigation from the provider. `Strict` withholds the cookie on exactly that request and breaks every login |
| `Path` | `/` | Routing is case-insensitive; RFC 6265 `Path` matching is not. A narrower path silently drops the cookie on a case-varied callback |
| `Secure` | when the provider's `redirectUri` is not `http:` | Derived from your configured redirect URI, so plaintext local development works and a TLS deployment behind a terminating proxy still gets `Secure` |
| `Max-Age` | 600 seconds | Matches the server-side state TTL |

If the runtime cannot set the cookie, `/auth/login/:provider` returns `500` and issues no state, rather than issuing one that cannot be bound.

### Requirements for consumers

- **Start the login as a top-level navigation** (`window.location = '/auth/login/discord'`, or a plain link). This is the documented pattern and it avoids CORS entirely.
- **Serve login and callback from the same host.** The cookie is host-scoped and carries no `Domain` attribute. A **different port on the same host is fine** — port is not part of cookie scope (RFC 6265 §8.5) — but a different *hostname* is not: the cookie is never sent and the login fails. Both routes are mounted on the same `AuthRequest`, so this only bites when something in front of the app splits them across hostnames (a proxy split, or `app.example.com` for login and `example.com` for the callback).
- **Keep your configured `redirectUri` on the same scheme the login endpoint is served over.** `Secure` is derived from `redirectUri`, so an `https` `redirectUri` behind a plaintext login endpoint issues a `Secure` cookie that the browser silently discards. Every login then fails the binding check **with no server-side signal** — the callback simply reports `error=auth_failed` if `frontendCallbackUrl` is configured, or a bare `500` if it is not. Check this first if logins start failing after a TLS or proxy change.
- An XHR-initiated login will not work: `@stonyx/rest-server` never passes `credentials: true` to CORS, so the browser will neither store nor send the cookie on a cross-origin XHR. Narrowing `REST_CORS_ORIGIN` from its `*` default does not change this.

### Migration from a cookie-less client

Scripted and server-to-server logins break. If you drive the flow yourself, carry the `Set-Cookie` from the login response back as a `Cookie` header on the callback:

```javascript
const login = await fetch(`${host}/auth/login/discord`, { redirect: 'manual' });
const cookie = login.headers.getSetCookie().map(header => header.split(';')[0]).join('; ');
const state = new URL(login.headers.get('location')).searchParams.get('state');

// ...provider redirects back with `code`...
await fetch(`${host}/auth/callback/discord?code=${code}&state=${state}`, {
  redirect: 'manual',
  headers: { cookie },
});
```

That callback now answers `302` with an exchange ticket in the `Location` fragment rather than a session id. A scripted client continues by reading the ticket out of the fragment and redeeming it — see [Migration](#migration) under Session delivery for the exchange step. A server-to-server client can do this perfectly well; the "cannot complete a login at all" row in the #45 break table is about clients that cannot issue a cross-origin `POST` from a browser, not about scripted ones.

In a browser, `fetch` needs `credentials: 'include'` for a cross-origin request — but see the CORS caveat above; a top-level navigation is the supported path.

### Concurrent logins in the same browser

The cookie name is fixed and its `Path` is `/`, so a second login started in the same browser overwrites the first tab's binding value. The first tab's callback then presents the second tab's value and fails the binding check — redirecting with `error=auth_failed` if `frontendCallbackUrl` is configured, or returning `500` if it is not.

This fails closed — no session is minted for the wrong flow, and it is not a way past the binding — but it is an availability regression against the previous behaviour, where two concurrent logins both completed. A user who opens two login tabs has to finish in the one they started last, or retry.

## Session delivery — the exchange ticket

### Breaking changes (#45)

**As of the fix for [#45](https://github.com/abofs/stonyx-oauth/issues/45).** This is a break in the **HTTP contract**, not in the JS API.

`GET /auth/callback/:provider` no longer redirects with `?sessionId=`. It redirects with a single-use, 60-second ticket in the URL **fragment**, which is exchanged for the session id over a JSON `POST`:

```
GET  /auth/callback/:provider  ->  302 <frontendCallbackUrl>#ticket=<opaque>&expiresAt=<ts>
POST /auth/session             <-  {"ticket":"<opaque>"}     Content-Type: application/json
                               ->  200 {"sessionId":"<uuid>","expiresAt":<ts>}
                               ->  400 on an unknown, spent, expired or unparseable ticket
```

The success redirect carries **no query string at all**. Read the ticket from `location.hash`, not `location.search`. The failure redirect is unchanged and still uses the query (`?error=auth_failed`) — an error code is not a credential.

**Who this breaks, and how:**

| Party | What breaks |
|---|---|
| **Any client reading `?sessionId=` off the callback redirect** | Gets `undefined`. The redirect no longer carries a session id under any name, in the query or the fragment. |
| **Any client reading the callback redirect's query at all** | Gets an empty query on success. Both the ticket and `expiresAt` are in the fragment. A server-side reader **cannot** see either — that is the point, and it is why a browser-side handler is required. |
| **Any client that cannot issue a cross-origin `POST`** | Cannot complete a login at all. The exchange is the only way to obtain a session id when `frontendCallbackUrl` is configured. |
| **Form-encoded callers** | `@stonyx/rest-server` installs `express.json()` only, so a form-encoded body arrives unparsed and the exchange returns `400`. The request **must** be `application/json`. |
| [`abofs/stonyx-dashboard`](https://github.com/abofs/stonyx-dashboard) | `demo-app/routes/auth/discord-callback.js` reads `?sessionId=`. Tracked at [stonyx-dashboard#103](https://github.com/abofs/stonyx-dashboard/issues/103), which must land before that consumer bumps. |
| `lynxury/backend` | `test/integration/05-oauth-bypass-test.js` reads `?sessionId=` from the callback redirect. Reds when it bumps off `@stonyx/oauth@0.1.1-beta.157`. |
| `lynxury/dashboard` | Bumps its `@stonyx/dashboard` commit pin after #103 lands. |

### Deployment prerequisites — the server's own CORS configuration

This is the half that breaks on the **server** rather than in the consumer's code, and it fails as a browser console CORS error against a server that logs nothing.

Before #45 this module served only `GET`. A deployment that had hardened `REST_CORS_METHODS=GET` was correct and lost nothing. After #45 that same deployment has **no working login at all**: the browser refuses the preflight for `POST /auth/session` and never sends the exchange, and with the session id no longer in the URL there is no fallback path.

| Setting | Required value | Why |
|---|---|---|
| `REST_CORS_METHODS` | must include `POST` | Default is `GET,POST,PATCH,PUT,DELETE`, which is fine. A narrowed value that omits `POST` kills every login. `@stonyx/rest-server` answers the preflight in middleware before routing, so the server returns `204` either way — the failure is visible only in `Access-Control-Allow-Methods`. |
| `REST_CORS_ORIGIN` | the frontend origin | Default is `*`. `POST /auth/session` hands out a session id, so under `*` any origin holding a ticket can redeem it and read the result from script. Pin it to the origin serving your `frontendCallbackUrl`. |

`test/integration/oauth-test.ts` AC5 asserts both the preflight's `access-control-allow-methods` and the real cross-origin `POST`, so a regression here reds rather than passing silently.

**Unaffected.** The `session-id` **header** contract is unchanged: `GET /auth` and `GET /auth/logout` still authenticate from it, and everything in the [`oauth_state` binding](#login-csrf-protection--the-oauth_state-cookie) is untouched. What changed is how the session id is *delivered once*, not how it is *used afterwards*. The JS API is unchanged — `handleCallback` still returns `{ sessionId, expiresAt }`, and a deployment with **no** `frontendCallbackUrl` configured still gets the session object as the callback's response body, because that is a direct response rather than a value written into a URL.

### Why

The session id is the bearer credential — `GET /auth` authenticates from exactly that value. Delivering it as a query parameter wrote a live 24-hour credential into:

- browser history and the address bar,
- the `Referer` header on any outbound link from the landing page,
- proxy, CDN and server access logs,
- `location.search`, readable by every script on the landing page.

Putting the ticket in the **fragment** rather than the query removes the middle two outright, for every deployment, with no configuration. A fragment is never transmitted to any server by any user agent: it does not appear in the frontend's own access logs, in any reverse proxy or CDN in front of the landing page, or in `Referer` under any referrer policy.

What the fragment does **not** remove is browser history and readability by page scripts (`location.hash` instead of `location.search`). Those are the app's own to close and nothing in front of the app can close them — no proxy can unwrite a URL the app chose. They are why the ticket is still single-use and 60-second rather than a long-lived value, and why the migration below scrubs it with `history.replaceState`.

### Ticket properties

| Property | Value | Why |
|---|---|---|
| Lifetime | **60 seconds** | One redirect plus one page load. Two orders of magnitude tighter than the 600s state TTL, because unlike the state this value travels in a URL — in the fragment, so not to any server, but still into history and into page scripts. |
| Uses | **exactly one** | Consumed on recognition, before the TTL is checked, so every ticket gets one attempt whatever the outcome and the route is not a repeatable oracle. |
| Entropy | 32 random bytes, base64url | Independent of the session id, never derived from it. |
| Authenticates | **nothing** | `GET /auth` validates against the session store, which has never heard of the ticket. A ticket in a `session-id` header is a `401`. |
| Failure modes | one indistinguishable `400` | Unknown, spent, expired and unparseable are not told apart. |

### Known residual risk

**This is a reduction, not an elimination.** A ticket observed in the sub-second window *before* the landing page redeems it is redeemable by the observer. What the change buys is the difference between a live 24-hour credential permanently written into history and a one-shot token that is already spent by the time the page renders.

Closing the window means binding the ticket to the client that started the flow, the way [#36](https://github.com/abofs/stonyx-oauth/issues/36) bound the `state`. That binding has to travel on a cookie, and the exchange is cross-origin, so the cookie cannot be sent without `credentials: 'include'`.

The blocker is [**`abofs/stonyx-rest-server#63`**](https://github.com/abofs/stonyx-rest-server/issues/63) — `@stonyx/rest-server` calls `cors({ origin, methods })` and has no `credentials` support at all: no `credentials: true`, no `REST_CORS_CREDENTIALS`. A cookie-bound exchange is impossible until that lands, and it will also require pinning `REST_CORS_ORIGIN`, since `*` with credentials is spec-forbidden.

It is **not** blocked on [`abofs/stonyx-rest-server#45`](https://github.com/abofs/stonyx-rest-server/issues/45) (*"no supported way for a route handler to set a response header"*). That gap is real but is an ergonomics dependency, and it is already worked around in this very file — `setBindingCookie`/`clearBindingCookie` set and clear cookies on a redirect today by reaching through `req.res`. Closing #45 would not make this residual closeable. **That risk belongs to the rest-server layer.** Revisit when #63 lands.

An abandoned ticket is never garbage-collected, the same pre-existing limitation `pendingStates` has. It is bounded by a 60-second TTL rather than a 600-second one. Both maps are tracked at [stonyx-oauth#43](https://github.com/abofs/stonyx-oauth/issues/43), which names each site so a fix cannot sweep one and leave the other.

### Migration

Read the `ticket`, exchange it, and scrub the URL:

```javascript
// On the landing page at your `frontendCallbackUrl`, before first paint.
// The ticket is in the fragment, not the query — `location.hash`, not
// `location.search`. `.slice(1)` drops the leading `#`.
const params = new URLSearchParams(location.hash.slice(1));
const ticket = params.get('ticket');

const response = await fetch(`${host}/auth/session`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },  // form-encoded will 400
  body: JSON.stringify({ ticket }),
});

if (!response.ok) throw new Error('login failed');  // unknown, spent or expired

const { sessionId, expiresAt } = await response.json();

// The ticket is spent, but do not leave it in the address bar or in history.
// The fragment kept it away from every server; `replaceState` is what keeps it
// out of this browser's history and away from later scripts on the page.
history.replaceState({}, '', location.pathname);
```

Then send `sessionId` as a `session-id` header exactly as before.

Exchange promptly — the ticket is valid for 60 seconds. Do it in the earliest hook your framework offers (`beforeModel` in Ember, a loader in Remix or React Router), not after the page has rendered.

## Session Management

Sessions are stored in-memory using a `Map`. Sessions are lost on server restart.

Clients obtain the `sessionId` by redeeming the callback's exchange ticket at `POST /auth/session` — see [Session delivery](#session-delivery--the-exchange-ticket) — and send it as a `session-id` header on subsequent requests. It is never delivered in a URL.

## License

Apache-2.0
