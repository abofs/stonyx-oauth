import QUnit from 'qunit';
import TokenManager from '../../src/token-manager.js';

const { module, test } = QUnit;

function createMockFlow() {
  return {
    exchangeCode: async (code) => ({
      accessToken: `token-for-${code}`,
      refreshToken: 'refresh-123',
      expiresIn: 3600,
    }),
    refreshAccessToken: async (refreshToken) => ({
      accessToken: 'new-access',
      refreshToken,
      expiresIn: 7200,
    }),
    revokeToken: async () => {},
  };
}

module('[Unit] TokenManager', function() {
  module('getTokens', function() {
    test('delegates to flow.exchangeCode and sets expiresAt', async function(assert) {
      const manager = new TokenManager(createMockFlow());
      const before = Date.now();
      const result = await manager.getTokens('my-code');

      assert.equal(result.accessToken, 'token-for-my-code');
      assert.equal(result.refreshToken, 'refresh-123');
      assert.ok(result.expiresAt >= before + 3600 * 1000);
    });
  });

  module('refresh', function() {
    test('delegates to flow.refreshAccessToken and sets expiresAt', async function(assert) {
      const manager = new TokenManager(createMockFlow());
      const result = await manager.refresh('refresh-123');

      assert.equal(result.accessToken, 'new-access');
      assert.ok(result.expiresAt > Date.now());
    });
  });

  module('revoke', function() {
    test('delegates to flow.revokeToken', async function(assert) {
      let revoked = false;
      const flow = { ...createMockFlow(), revokeToken: async () => { revoked = true; } };
      const manager = new TokenManager(flow);

      await manager.revoke('some-token');
      assert.ok(revoked);
    });
  });

  module('isExpired', function() {
    test('returns true if expiresAt is in the past', function(assert) {
      const manager = new TokenManager(createMockFlow());

      assert.true(manager.isExpired({ expiresAt: Date.now() - 1000 }));
    });

    test('returns false if expiresAt is in the future', function(assert) {
      const manager = new TokenManager(createMockFlow());

      assert.false(manager.isExpired({ expiresAt: Date.now() + 60000 }));
    });

    test('returns true if tokenData is null or missing expiresAt', function(assert) {
      const manager = new TokenManager(createMockFlow());

      assert.true(manager.isExpired(null));
      assert.true(manager.isExpired({}));
    });
  });
});
