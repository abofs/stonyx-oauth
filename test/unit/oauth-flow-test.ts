import QUnit from 'qunit';
import OAuthFlow from '../../src/oauth-flow.js';
import type { OAuthConfig } from '../../src/oauth-flow.js';

const { module, test } = QUnit;

const defaultConfig: OAuthConfig = {
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirectUri: 'http://localhost/callback',
  scopes: ['read', 'write'],
  authorizationUrl: 'https://provider.com/oauth/authorize',
  tokenUrl: 'https://provider.com/oauth/token',
  userInfoUrl: 'https://provider.com/api/me',
};

module('[Unit] OAuthFlow', function() {
  module('buildAuthorizationUrl', function() {
    test('generates a valid authorization URL with all params', function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const url = flow.buildAuthorizationUrl('test-state-123');

      assert.ok(url.startsWith('https://provider.com/oauth/authorize?'));
      assert.ok(url.includes('client_id=test-client'));
      assert.ok(url.includes('redirect_uri='));
      assert.ok(url.includes('response_type=code'));
      assert.ok(url.includes('scope=read+write'));
      assert.ok(url.includes('state=test-state-123'));
    });

    test('handles empty scopes', function(assert: Assert) {
      const flow = new OAuthFlow({ ...defaultConfig, scopes: [] });
      const url = flow.buildAuthorizationUrl('state');

      assert.ok(url.includes('scope='));
    });
  });

  module('exchangeCode', function() {
    test('makes a POST request to the token URL', async function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (url: string | URL | Request, options?: RequestInit) => {
        assert.equal(url, 'https://provider.com/oauth/token');
        assert.equal(options?.method, 'POST');
        assert.equal((options?.headers as Record<string, string>)?.['Content-Type'], 'application/json');

        const body = JSON.parse(options?.body as string);
        assert.equal(body.grant_type, 'authorization_code');
        assert.equal(body.code, 'test-code');
        assert.equal(body.client_id, 'test-client');

        return {
          ok: true,
          json: async () => ({ access_token: 'abc', refresh_token: 'def', expires_in: 3600 }),
        };
      }) as typeof fetch;

      const result = await flow.exchangeCode('test-code');

      assert.equal(result.accessToken, 'abc');
      assert.equal(result.refreshToken, 'def');
      assert.equal(result.expiresIn, 3600);

      globalThis.fetch = originalFetch;
    });

    test('throws on failed token exchange', async function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async () => ({ ok: false, status: 400 })) as unknown as typeof fetch;

      await assert.rejects(flow.exchangeCode('bad-code'), /Token exchange failed: 400/);

      globalThis.fetch = originalFetch;
    });
  });

  module('refreshAccessToken', function() {
    test('makes a refresh grant request', async function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (_url: string | URL | Request, options?: RequestInit) => {
        const body = JSON.parse(options?.body as string);
        assert.equal(body.grant_type, 'refresh_token');
        assert.equal(body.refresh_token, 'old-refresh');

        return {
          ok: true,
          json: async () => ({ access_token: 'new-access', expires_in: 7200 }),
        };
      }) as typeof fetch;

      const result = await flow.refreshAccessToken('old-refresh');

      assert.equal(result.accessToken, 'new-access');
      assert.equal(result.refreshToken, 'old-refresh', 'falls back to original refresh token');
      assert.equal(result.expiresIn, 7200);

      globalThis.fetch = originalFetch;
    });
  });

  module('fetchUserInfo', function() {
    test('sends a Bearer token in the Authorization header', async function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const originalFetch = globalThis.fetch;

      globalThis.fetch = (async (url: string | URL | Request, options?: RequestInit) => {
        assert.equal(url, 'https://provider.com/api/me');
        assert.equal((options?.headers as Record<string, string>)?.Authorization, 'Bearer my-token');

        return {
          ok: true,
          json: async () => ({ id: '1', name: 'Test' }),
        };
      }) as typeof fetch;

      const result = await flow.fetchUserInfo('my-token');
      assert.deepEqual(result, { id: '1', name: 'Test' });

      globalThis.fetch = originalFetch;
    });
  });

  module('normalizeUser', function() {
    test('returns raw user by default', function(assert: Assert) {
      const flow = new OAuthFlow(defaultConfig);
      const raw = { id: '1', name: 'Test' };
      const result = flow.normalizeUser(raw);

      assert.deepEqual(result, { raw });
    });
  });
});
