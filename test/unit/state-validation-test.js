import QUnit from 'qunit';

const { module, test } = QUnit;

/**
 * Tests for OAuth state token validation logic.
 *
 * These tests exercise the pendingStates map and validation directly,
 * mirroring the logic in OAuth.handleCallback without requiring the
 * full module initialization (which depends on stonyx config/modules).
 */

const TEN_MINUTES = 10 * 60 * 1000;

function validateState(pendingStates, stateToken) {
  if (!stateToken || !pendingStates.has(stateToken)) {
    throw new Error('Invalid or missing state token');
  }

  const stateCreatedAt = pendingStates.get(stateToken);
  pendingStates.delete(stateToken);

  if (Date.now() - stateCreatedAt > TEN_MINUTES) {
    throw new Error('State token has expired');
  }
}

module('[Unit] State Validation', function() {
  test('accepts a valid pending state token', function(assert) {
    const pendingStates = new Map();
    pendingStates.set('valid-token', Date.now());

    validateState(pendingStates, 'valid-token');
    assert.ok(true, 'did not throw');
  });

  test('consumes the state token after validation', function(assert) {
    const pendingStates = new Map();
    pendingStates.set('one-time-token', Date.now());

    validateState(pendingStates, 'one-time-token');
    assert.false(pendingStates.has('one-time-token'), 'token removed from pending states');
  });

  test('rejects a missing state token', function(assert) {
    const pendingStates = new Map();

    assert.throws(
      () => validateState(pendingStates, undefined),
      /Invalid or missing state token/,
    );
  });

  test('rejects an empty string state token', function(assert) {
    const pendingStates = new Map();

    assert.throws(
      () => validateState(pendingStates, ''),
      /Invalid or missing state token/,
    );
  });

  test('rejects an unknown state token', function(assert) {
    const pendingStates = new Map();
    pendingStates.set('known-token', Date.now());

    assert.throws(
      () => validateState(pendingStates, 'unknown-token'),
      /Invalid or missing state token/,
    );
  });

  test('rejects an expired state token (older than 10 minutes)', function(assert) {
    const pendingStates = new Map();
    const elevenMinutesAgo = Date.now() - (11 * 60 * 1000);
    pendingStates.set('expired-token', elevenMinutesAgo);

    assert.throws(
      () => validateState(pendingStates, 'expired-token'),
      /State token has expired/,
    );
  });

  test('expired state token is still consumed', function(assert) {
    const pendingStates = new Map();
    const elevenMinutesAgo = Date.now() - (11 * 60 * 1000);
    pendingStates.set('expired-token', elevenMinutesAgo);

    try {
      validateState(pendingStates, 'expired-token');
    } catch {
      // expected
    }

    assert.false(pendingStates.has('expired-token'), 'expired token removed from map');
  });

  test('accepts a token just under 10 minutes old', function(assert) {
    const pendingStates = new Map();
    const nineMinutesAgo = Date.now() - (9 * 60 * 1000);
    pendingStates.set('fresh-token', nineMinutesAgo);

    validateState(pendingStates, 'fresh-token');
    assert.ok(true, 'did not throw');
  });

  test('rejects reuse of a previously valid token', function(assert) {
    const pendingStates = new Map();
    pendingStates.set('use-once', Date.now());

    validateState(pendingStates, 'use-once');

    assert.throws(
      () => validateState(pendingStates, 'use-once'),
      /Invalid or missing state token/,
    );
  });
});
