import QUnit from 'qunit';
import DiscordProvider from '../../../src/providers/discord.js';

const { module, test } = QUnit;

const defaultConfig = {
  clientId: 'discord-client-id',
  clientSecret: 'discord-client-secret',
  redirectUri: 'http://localhost/auth/callback/discord',
  scopes: ['identify', 'email'],
};

module('[Unit] DiscordProvider', function() {
  module('constructor', function() {
    test('sets correct Discord OAuth2 URLs', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      assert.equal(provider.authorizationUrl, 'https://discord.com/oauth2/authorize');
      assert.equal(provider.tokenUrl, 'https://discord.com/api/oauth2/token');
      assert.equal(provider.userInfoUrl, 'https://discord.com/api/users/@me');
    });

    test('preserves client config', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      assert.equal(provider.clientId, 'discord-client-id');
      assert.equal(provider.clientSecret, 'discord-client-secret');
      assert.deepEqual(provider.scopes, ['identify', 'email']);
    });
  });

  module('exchangeCode', function() {
    test('uses form-encoded body for Discord token exchange', async function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);
      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (url: string | URL | Request, options?: RequestInit) => {
        assert.equal(url, 'https://discord.com/api/oauth2/token');
        assert.equal((options?.headers as Record<string, string>)?.['Content-Type'], 'application/x-www-form-urlencoded');
        assert.ok(options?.body instanceof URLSearchParams);

        const params = Object.fromEntries(options!.body as URLSearchParams);
        assert.equal(params.grant_type, 'authorization_code');
        assert.equal(params.code, 'discord-auth-code');
        assert.equal(params.client_id, 'discord-client-id');

        return {
          ok: true,
          json: async () => ({ access_token: 'discord-token', refresh_token: 'refresh', expires_in: 604800 }),
        };
      }) as typeof fetch;

      const result = await provider.exchangeCode('discord-auth-code');

      assert.equal(result.accessToken, 'discord-token');
      assert.equal(result.refreshToken, 'refresh');
      assert.equal(result.expiresIn, 604800);

      globalThis.fetch = originalFetch;
    });
  });

  module('normalizeUser', function() {
    test('maps Discord user fields correctly', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      const discordUser = {
        id: '123456789',
        username: 'testuser',
        global_name: 'Test User',
        avatar: 'abc123',
        email: 'test@example.com',
      };

      const result = provider.normalizeUser(discordUser);

      assert.equal(result.id, '123456789');
      assert.equal(result.username, 'testuser');
      assert.equal(result.displayName, 'Test User');
      assert.equal(result.avatar, 'https://cdn.discordapp.com/avatars/123456789/abc123.png');
      assert.equal(result.email, 'test@example.com');
      assert.deepEqual(result.raw, discordUser);
    });

    test('handles missing avatar', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      const result = provider.normalizeUser({
        id: '1', username: 'user', global_name: 'User', avatar: null, email: null,
      });

      assert.equal(result.avatar, null);
    });

    test('falls back to username when global_name is missing', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      const result = provider.normalizeUser({
        id: '1', username: 'myuser', avatar: null, email: null,
      });

      assert.equal(result.displayName, 'myuser');
    });

    test('handles missing email', function(assert: Assert) {
      const provider = new DiscordProvider(defaultConfig);

      const result = provider.normalizeUser({
        id: '1', username: 'user', global_name: 'User', avatar: null,
      });

      assert.equal(result.email, null);
    });
  });
});
