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

## Routes

The module self-registers the following routes on the rest server:

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/auth` | Validate session — send `session-id` header, returns user or 401 |
| `GET` | `/auth/login/:provider` | Redirects to provider's OAuth2 authorization page |
| `GET` | `/auth/callback/:provider` | OAuth2 callback — exchanges code for tokens, creates session |
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

**Breaking, as of the fix for [#36](https://github.com/abofs/stonyx-oauth/issues/36): the login flow now requires a cookie jar.** A client that cannot hold a cookie between `/auth/login/:provider` and `/auth/callback/:provider` can no longer complete a login. That is the point of the change — see [Migration](#migration-from-a-cookie-less-client) below.

`GET /auth/login/:provider` issues a single-use `oauth_state` cookie and keeps only its SHA-256 server-side. `GET /auth/callback/:provider` accepts an OAuth2 `state` only from a caller that also presents the matching cookie value.

Without it, `state` was verified by membership in a server-side map plus an age bound, and nothing else. There was no value the browser that started the flow carried that another browser did not, so an attacker could start a login, harvest their own `state` and `code`, deliver them to a victim over a plain link, and log that victim into the *attacker's* account (RFC 6749 §10.12, RFC 9700). The victim's own account and data are not exposed; what is at risk is whatever they author afterwards, believing the session is theirs.

### Cookie attributes

| Attribute | Value | Why |
|-----------|-------|-----|
| Name | `oauth_state` | Single-use; issued at login, cleared on a successful callback |
| `HttpOnly` | always | Script must not be able to read or forge the binding value |
| `SameSite` | `Lax` | **Required.** The callback is a cross-site, top-level GET navigation from the provider. `Strict` withholds the cookie on exactly that request and breaks every login |
| `Path` | `/` | Routing is case-insensitive; RFC 6265 `Path` matching is not. A narrower path silently drops the cookie on a case-varied callback |
| `Secure` | when the provider's `redirectUri` is not `http:` | Derived from your configured redirect URI, so plaintext local development works and a TLS deployment behind a terminating proxy still gets `Secure` |
| `Max-Age` | 600 seconds | Matches the server-side state TTL |

If the runtime cannot set the cookie, `/auth/login/:provider` returns `500` and issues no state, rather than issuing one that cannot be bound.

### Requirements for consumers

- **Start the login as a top-level navigation** (`window.location = '/auth/login/discord'`, or a plain link). This is the documented pattern and it avoids CORS entirely.
- **Serve login and callback from the same origin.** A cookie set on the login origin is not sent to a different callback origin, and the login fails.
- An XHR-initiated login will not work: `@stonyx/rest-server` sets `origin: '*'` without `credentials: true`, so the browser will neither store nor send the cookie on a cross-origin XHR.

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

In a browser, `fetch` needs `credentials: 'include'` for a cross-origin request — but see the CORS caveat above; a top-level navigation is the supported path.

## Session Management

Sessions are stored in-memory using a `Map`. Sessions are lost on server restart.

Clients should store the `sessionId` returned from the callback and send it as a `session-id` header on subsequent requests.

## License

Apache-2.0
