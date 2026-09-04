// Tests for OAuth state token validation.
//
// These drive the real `OAuth` instance. The previous version of this file
// defined a *local copy* of the validation logic and tested the copy, which
// made all nine of its tests vacuous: deleting the production check in
// `OAuth.handleCallback` outright left every one of them green. Proven by
// mutation, not by reading — see the PR body for the recorded fail counts.
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

/** Mints a state through the production path and returns its token. */
function issueState(oauth: OAuth): string {
  oauth.getAuthorizationUrl('mock');
  return [...oauth.pendingStates.keys()].at(-1)!;
}

/** Backdates an already-issued state without reaching around the record shape. */
function backdate(oauth: OAuth, stateToken: string, age: number): void {
  const record = oauth.pendingStates.get(stateToken)!;
  oauth.pendingStates.set(stateToken, record - age);
}

module('[Unit] State Validation', function(hooks) {
  let oauth: OAuth;

  hooks.beforeEach(function() {
    oauth = buildOAuth();
  });

  hooks.afterEach(function() {
    OAuth.instance = null;
  });

  test('accepts a valid pending state token', async function(assert) {
    const stateToken = issueState(oauth);

    const session = await oauth.handleCallback('mock', 'test-code', stateToken);

    assert.ok(session.sessionId, 'a session is issued');
    assert.equal(oauth.sessionManager.sessions.size, 1, 'and recorded server-side');
  });

  test('consumes the state token after validation', async function(assert) {
    const stateToken = issueState(oauth);

    await oauth.handleCallback('mock', 'test-code', stateToken);

    assert.false(oauth.pendingStates.has(stateToken), 'token removed from pending states');
  });

  test('rejects a missing state token', async function(assert) {
    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', undefined as unknown as string),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an empty string state token', async function(assert) {
    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', ''),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an unknown state token', async function(assert) {
    issueState(oauth);

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', 'unknown-token'),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('rejects an expired state token (older than 10 minutes)', async function(assert) {
    const stateToken = issueState(oauth);
    backdate(oauth, stateToken, TEN_MINUTES + 60_000);

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken),
      /State token has expired/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session minted');
  });

  test('expired state token is still consumed', async function(assert) {
    const stateToken = issueState(oauth);
    backdate(oauth, stateToken, TEN_MINUTES + 60_000);

    try {
      await oauth.handleCallback('mock', 'test-code', stateToken);
    } catch {
      // expected
    }

    assert.false(oauth.pendingStates.has(stateToken), 'expired token removed from the map');
  });

  test('accepts a token just under 10 minutes old', async function(assert) {
    const stateToken = issueState(oauth);
    backdate(oauth, stateToken, TEN_MINUTES - 60_000);

    const session = await oauth.handleCallback('mock', 'test-code', stateToken);

    assert.ok(session.sessionId, 'a session is issued');
  });

  test('rejects reuse of a previously valid token', async function(assert) {
    const stateToken = issueState(oauth);

    await oauth.handleCallback('mock', 'test-code', stateToken);

    await assert.rejects(
      oauth.handleCallback('mock', 'test-code', stateToken),
      /Invalid or missing state token/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 1, 'the replay minted no second session');
  });
});
