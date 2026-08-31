[![CI](https://github.com/abofs/stonyx-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/abofs/stonyx-oauth/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@stonyx/oauth.svg)](https://www.npmjs.com/package/@stonyx/oauth)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# @stonyx/oauth

OAuth2 authentication module for the Stonyx framework. Provides a generic OAuth2 Authorization Code flow with a provider pattern — ship with Discord support, extensible to any OAuth2 provider.

## Setup

Add as a devDependency to your Stonyx project:

```bash
pnpm add @stonyx/oauth
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

## Routes

The module self-registers the following routes on the rest server:

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/auth` | Validate session — send `session-id` header, returns user or 401 |
| `GET` | `/auth/login/:provider` | Redirects to provider's OAuth2 authorization page, and sets the state binding cookie |
| `GET` | `/auth/callback/:provider` | OAuth2 callback — verifies the state binding, exchanges code for tokens, creates session |
| `GET` | `/auth/logout` | Destroys session (send `session-id` header) |

### Starting the flow

Send the browser to `/auth/login/:provider` as a **top-level navigation**:

```javascript
window.location.href = 'https://api.example.com/auth/login/discord';
```

Do not start the flow with `fetch()` or `XMLHttpRequest`. The login response
sets the state binding cookie described below, and the browser must be holding
that cookie when the provider redirects it back to `/auth/callback/:provider`.

## State Binding (CSRF Protection)

The OAuth2 `state` parameter only protects against login CSRF if it is bound to
the client that started the flow. This module binds it with a cookie.

On `GET /auth/login/:provider` the module issues a random 32-byte binding value,
stores only a SHA-256 digest of it server-side alongside the provider name and
issue time, and sends the plaintext to the client as a cookie:

| Attribute | Value | Why |
|-----------|-------|-----|
| Name | `stonyx_oauth_state` | |
| `HttpOnly` | set | script must not be able to read or forge the binding value |
| `SameSite` | `Lax` | **required.** The callback is a cross-site, top-level `GET` navigation from the provider. `SameSite=Strict` withholds the cookie on exactly that request and breaks login outright; `SameSite=None` requires `Secure` and widens exposure for no benefit |
| `Path` | `/auth` | the cookie is only ever read by the callback route |
| `Secure` | set on every host except loopback | deriving it from `req.secure` would omit it in the standard production topology: behind a TLS-terminating proxy Express reports the request as plaintext unless `trust proxy` is enabled, and `@stonyx/rest-server` leaves that off by default. A non-loopback plaintext deployment therefore cannot store this cookie — that failure is loud and deliberate, in preference to a silently insecure production cookie. The exemption rule is exact; see below |
| `Max-Age` | 600 (10 minutes) | matches the pending state's lifetime |

#### Which hosts are exempt from `Secure`

The exemption is decided by parsing the `Host` header and testing the result for
membership. It is never a prefix or suffix match on the raw header value,
because `Host` is attacker-controllable from any non-browser client.

Exempt, and nothing else:

- `localhost` (case-insensitive)
- any address in `127.0.0.0/8` — a dotted quad of four decimal octets whose
  first is `127`, so `127.0.0.2` is exempt and `127.evil.com` is not
- `::1` (and its expanded form), and the IPv4-mapped loopback spellings
  `::ffff:127.0.0.1` and `::ffff:7f00:1`
- the wildcard bind addresses `0.0.0.0` and `::`

Everything else gets `Secure`, including:

- **`*.localhost`.** A `.localhost` suffix was exempt in an earlier draft of
  this module and is not any more: a split-horizon vhost under that zone would
  have shipped the binding value in cleartext. Develop against `localhost` or
  `127.0.0.1`, which reach the same server.
- any `Host` that is not a well-formed `host[:port]` — a non-numeric port, a
  userinfo segment (`localhost:80@evil.com`), a comma-joined multi-value, or a
  character a registered name may not contain
- a request carrying **more than one `Host` header**. Node collapses repeats
  into the first value, so an upstream component that prepends rather than
  replaces a `Host:` line could otherwise downgrade the cookie on a response to
  someone else. RFC 9112 section 3.2 makes such a request invalid; this module
  treats it as unattributable.
- a request carrying **no `Host` header** at all

`X-Forwarded-Host` is deliberately **not** consulted.

`GET /auth/callback/:provider` accepts the callback only when all of the
following hold, and mints no session otherwise:

- the `state` is one this server issued and has not already been used
- it was issued for **this** provider
- it was issued less than 10 minutes ago
- the request carries a binding cookie whose value hashes to the stored digest

A client can hold more than one cookie of that name — a sibling subdomain can
set one on the parent domain, and the browser sends every applicable cookie in
a single header. **Every** value carrying the name is tried, up to eight, and
the callback is accepted if any of them matches. Reading only the first would
let anyone who can plant a cookie on the victim's domain deny them login
permanently: RFC 6265 section 5.4 sorts a planted cookie ahead of the real one
on equal paths, and the state is burned on every recognised callback, so
retrying does not help. Trying all of them concedes nothing, because the
attacker would still have to present the victim's own binding value.

The state and the cookie are both single-use: the pending record is consumed on
any callback that presents a recognised `state` — successful or not — and that
same response clears the cookie, scoped to `Path=/auth` so the deletion actually
reaches the cookie that was set.

A callback that consumes **nothing** — an unrecognised or absent `state`, a
provider `error`, a missing `code` — leaves the cookie alone. That is not
tidiness: `/auth/callback/:provider?code=1` is a request any attacker can induce
as a top-level navigation while a victim is still at the provider's consent
screen, and clearing on it would delete the victim's binding cookie without
touching anything the server could later notice.

Two distinct failure modes surface on two different routes. They are unrelated,
and the route is the fastest way to tell them apart:

- **The cookie cannot be set at all.** `GET /auth/login/:provider` responds
  `500` rather than issuing a state it cannot bind, and logs
  `OAuth: unable to set the state binding cookie; login rejected`. This is a
  framework-wiring condition — the response object the module reaches for is
  not there — not a network or proxy one.
- **`Set-Cookie` is stripped in transit** by a reverse proxy or CDN.
  `GET /auth/login/:provider` **succeeds and redirects normally**; the module
  never learns the header was dropped. The failure surfaces one hop later, at
  `GET /auth/callback/:provider`, as `?error=auth_failed` on
  `frontendCallbackUrl` (or a bare `500` when it is unset), with
  `OAuth: callback rejected — Missing state binding value` in the log. First
  thing to check: does the login response reach the browser carrying
  `Set-Cookie: stonyx_oauth_state`.

Every callback rejection is logged server-side with its reason
(`OAuth: callback rejected — ...`), which distinguishes an unknown state, a
wrong provider, an expired state, a missing binding value and a wrong binding
value. The client-facing `auth_failed` stays deliberately opaque.

A failed callback **cannot be retried**: the pending record is consumed on any
callback presenting a recognised `state`, so refreshing the error page or going
back and forward produces a second `auth_failed`. The user must restart at
`GET /auth/login/:provider`. Only one login can be in flight per browser at a
time, for the same reason — the binding cookie has one fixed name, so starting
a second login overwrites the first flow's binding value and the earlier flow
will fail at its callback.

### Custom flow drivers

Consumers that drive the flow themselves instead of using the routes above must
carry the binding value between the two calls:

```javascript
const { url, bindingValue } = oauth.getAuthorizationUrl('discord');
// hand bindingValue to the client, then on the callback:
const session = await oauth.handleCallback('discord', code, state, [bindingValue]);
```

The fourth argument is an **array** — every value the client presented under the
binding cookie's name. A driver that holds exactly one value passes
`[bindingValue]`; one that holds none passes `[]`.

> **Changed in the release that fixes [#36](https://github.com/abofs/stonyx-oauth/issues/36):**
> `getAuthorizationUrl(provider)` returned a URL string and now returns
> `{ url, bindingValue }`; `handleCallback(provider, code, state)` takes a
> required fourth argument, the client's binding values, as an array.
> Applications using the self-registering `/auth` routes need no changes.

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

## Session Management

Sessions are stored in-memory using a `Map`. Sessions are lost on server restart.
Pending OAuth states are held in-memory too, so a restart mid-login, or more
than one instance behind a load balancer, will reject the callback. Pending
records are removed when a callback consumes them, not swept on a timer — the
ten-minute age bound is only evaluated when a matching callback arrives, so an
abandoned flow's record persists until the process restarts. See
[#38](https://github.com/abofs/stonyx-oauth/issues/38).

Clients should store the `sessionId` returned from the callback and send it as a `session-id` header on subsequent requests.

## License

Apache-2.0
