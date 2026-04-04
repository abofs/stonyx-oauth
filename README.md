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

## Session Management

Sessions are stored in-memory using a `Map`. Sessions are lost on server restart.

Clients should store the `sessionId` returned from the callback and send it as a `session-id` header on subsequent requests.

## License

Apache-2.0
