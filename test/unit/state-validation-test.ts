// Tests for OAuth state token validation and client binding.
//
// These drive the real `OAuth` instance. The previous version of this file
// defined a *local copy* of the validation logic and tested the copy, which
// made all nine of its tests vacuous: deleting the production check in
// `OAuth.handleCallback` outright left every one of them green. Proven by
// mutation, not by reading — the recorded fail counts are in the PR body.
import QUnit from 'qunit';
import OAuth from '../../src/main.js';
import SessionManager from '../../src/session-manager.js';
import TokenManager from '../../src/token-manager.js';
import MockProvider from '../sample/providers/mock.js';

const { module, test } = QUnit;

const TEN_MINUTES = 10 * 60 * 1000;

/**
 * A real `OAuth` with a real provider entry and a real `SessionManager`,
 * assembled without `init()` — which needs stonyx config and a live
 * rest-server that the unit harness does not have.
 */
function buildOAuth(): OAuth {
  OAuth.instance = null;

  const oauth = new OAuth();
  const flow = new MockProvider({
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri: 'http://localhost:2666/auth/callback/mock',
    scopes: ['identify'],
  });

  oauth.providers.set('mock', { flow, tokenManager: new TokenManager(flow) });
  oauth.sessionManager = new SessionManager(3600);
  oauth.frontendCallbackUrl = 'http://localhost:4200/auth/callback';

  return oauth;
}

/** Backdates an already-issued state without reaching around the record shape. */
function backdate(oauth: OAuth, stateToken: string, age: number): void {
  const record = oauth.pendingStates.get(stateToken)!;
  oauth.pendingStates.set(stateToken, { ...record, createdAt: record.createdAt - age });
}

module('[Unit] State Validation', function(hooks) {
  let oauth: OAuth;

  hooks.beforeEach(function() {
    oauth = buildOAuth();
  });

  hooks.afterEach(function() {
    OAuth.instance = null;
  });

  test('accepts a valid pending state token presented with its binding value', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');

    const session = await oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]);

    assert.ok(session.sessionId, 'a session is issued');
    assert.equal(oauth.sessionManager.sessions.size, 1, 'and recorded server-side');
  });

  test('consumes the state token after validation', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');

    await oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]);

    assert.false(oauth.pendingStates.has(stateToken), 'token removed from pending states');
  });

  test('rejects a missing state token', async function(assert) {
    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', undefined as unknown as string, []),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an empty string state token', async function(assert) {
    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', '', []),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an unknown state token', async function(assert) {
    const { bindingValue } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', 'unknown-token', [bindingValue]),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an expired state token (older than 10 minutes)', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    backdate(oauth, stateToken, TEN_MINUTES + 60_000);

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]),
      /State token has expired/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('expired state token is still consumed', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    backdate(oauth, stateToken, TEN_MINUTES + 60_000);

    try {
      await oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]);
    } catch {
      // expected
    }

    assert.false(oauth.pendingStates.has(stateToken), 'expired token removed from the map');
  });

  test('accepts a token just under 10 minutes old', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    backdate(oauth, stateToken, TEN_MINUTES - 60_000);

    const session = await oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]);

    assert.ok(session.sessionId, 'a session is issued');
  });

  test('rejects reuse of a previously valid token', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');

    await oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]);

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken, [bindingValue]),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 1, 'the replay minted no second session');
  });

  // ---------------------------------------------------------------------------
  // #36 — client binding.
  // ---------------------------------------------------------------------------

  test('rejects a valid state presented with no binding value at all', async function(assert) {
    const { stateToken } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken, []),
      /Missing state binding value/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects a valid state presented with only empty binding values', async function(assert) {
    const { stateToken } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken, ['', '']),
      /Missing state binding value/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test("rejects a valid state presented with another client's binding value", async function(assert) {
    const victim = oauth.getAuthorizationUrl('mock');
    const attacker = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', victim.stateToken, [attacker.bindingValue]),
      /State token is not bound to this client/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('a state rejected for its binding is still consumed, so the endpoint is not an oracle', async function(assert) {
    const victim = oauth.getAuthorizationUrl('mock');
    const attacker = oauth.getAuthorizationUrl('mock');

    try {
      await oauth.handleCallback('mock', 'test-code', victim.stateToken, [attacker.bindingValue]);
    } catch {
      // expected
    }

    assert.false(oauth.pendingStates.has(victim.stateToken), 'the state was burned on the failed attempt');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', victim.stateToken, [victim.bindingValue]),
      /Invalid or missing state token/,
      'and re-presenting it with the correct binding value does not work either',
    );
  });

  test('accepts when the real binding value is one of several same-named candidates', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    // RFC 6265 section 5.4 orders the Cookie header by path length then
    // creation time, so a planted same-named cookie sorts ahead of the real
    // one. Stopping at the first candidate would make that a permanent,
    // unauthenticated denial of login for the victim.
    const candidates = ['planted-one', 'planted-two', bindingValue];

    const session = await oauth.handleCallback('mock', 'test-code', stateToken, candidates);

    assert.ok(session.sessionId, 'the shadowed client still logs in');
  });

  test('accepts with many shadow candidates — the candidate list is deliberately uncapped', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    const candidates = [...Array(64).keys()].map(index => `planted-${index}`).concat(bindingValue);

    const session = await oauth.handleCallback('mock', 'test-code', stateToken, candidates);

    assert.ok(session.sessionId, 'a cap would reinstate the denial above its own threshold');
  });

  test('rejects when every candidate is a decoy', async function(assert) {
    const { stateToken } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken, ['planted-one', 'planted-two']),
      /State token is not bound to this client/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('the pending record stores a digest, never the binding value itself', async function(assert) {
    const { stateToken, bindingValue } = oauth.getAuthorizationUrl('mock');
    const record = oauth.pendingStates.get(stateToken)!;

    assert.notEqual(record.bindingHash, bindingValue, 'the value is not stored in the clear');
    assert.equal(record.bindingHash, OAuth.hash(bindingValue), 'the record holds its SHA-256');
  });
});
