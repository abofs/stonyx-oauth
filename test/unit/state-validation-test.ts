import QUnit from 'qunit';
import OAuth from '../../src/main.js';
import OAuthFlow from '../../src/oauth-flow.js';
import TokenManager from '../../src/token-manager.js';
import SessionManager from '../../src/session-manager.js';
import StateStore from '../../src/state-store.js';
import { BINDING_VALUE_BYTES, STATE_TTL_MS } from '../../src/constants.js';

const { module, test } = QUnit;

/**
 * State + client-binding validation (#36).
 *
 * These tests drive the real `OAuth` instance from `src/main.ts`. The previous
 * version of this file re-implemented `handleCallback`'s state logic as a local
 * function and tested the copy — measured worthless: deleting the entire
 * production state check failed 0 of its 9 tests.
 *
 * Measured on this file at its current 13 tests: deleting
 * `this.stateStore.consume(...)` from `OAuth.handleCallback` fails 10 of them
 * (74 pass / 0 fail -> 56 pass / 18 fail across the whole suite). Three are
 * expected to survive that mutation and are labelled GUARD or noted here —
 * the happy-path acceptance test, and the two that pin the TTL magnitude and
 * the lower bound of the window, neither of which exercises the check being
 * deleted. Re-run the delete-the-implementation measurement on any rewrite of
 * this file; do not carry this count forward on trust.
 *
 * No network: the provider stub below overrides every method that would talk to
 * a remote endpoint.
 */

class StubProvider extends OAuthFlow {
  constructor() {
    super({
      clientId: 'unit-client-id',
      clientSecret: 'unit-client-secret',
      redirectUri: 'http://localhost:2666/auth/callback/mock',
      scopes: ['identify'],
      authorizationUrl: 'https://stub.provider/oauth/authorize',
      tokenUrl: 'https://stub.provider/oauth/token',
      userInfoUrl: 'https://stub.provider/api/me',
    });
  }

  async exchangeCode() {
    return { accessToken: 'stub-access-token', refreshToken: null, expiresIn: 3600 };
  }

  async fetchUserInfo() {
    return { id: 'stub-user-1' };
  }

  normalizeUser(rawUser: unknown) {
    return rawUser;
  }
}

function buildOAuth(): OAuth {
  OAuth.instance = null;

  const oauth = new OAuth();
  for (const name of ['mock', 'mock2']) {
    const flow = new StubProvider();
    oauth.providers.set(name, { flow, tokenManager: new TokenManager(flow) });
  }
  oauth.sessionManager = new SessionManager(3600);

  return oauth;
}

function stateOf(url: string): string {
  return new URL(url).searchParams.get('state')!;
}

module('[Unit] State Validation', function(hooks) {
  hooks.afterEach(function() {
    OAuth.instance = null;
  });

  test('a state issued with a binding value is accepted when both are presented', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');

    const session = await oauth.handleCallback('mock', 'code', stateOf(url), bindingValue);

    assert.ok(session.sessionId, 'a session is minted for the client that started the flow');
    // `length` counts base64url *characters*, so `>= 32` pinned a 24-byte
    // floor, not the 32 bytes the README advertises. 32 bytes is 43 chars.
    assert.equal(BINDING_VALUE_BYTES, 32, 'the binding value is 32 bytes of CSPRNG output');
    assert.equal(bindingValue.length, 43, 'and 32 bytes is what actually reaches the client');
  });

  test('rejects a callback that presents no binding value', async function(assert) {
    const oauth = buildOAuth();
    const { url } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateOf(url), undefined),
      /binding|state/i,
      'a state alone is not sufficient to mint a session',
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session was created');
  });

  test('rejects a binding value belonging to a different client', async function(assert) {
    const oauth = buildOAuth();
    const clientA = oauth.getAuthorizationUrl('mock');
    const clientB = oauth.getAuthorizationUrl('mock');

    assert.notEqual(clientA.bindingValue, clientB.bindingValue, 'each flow gets its own binding value');

    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateOf(clientA.url), clientB.bindingValue),
      /binding|state/i,
      "another client's binding value does not unlock this state",
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session was created');
  });

  test('rejects a state issued for a different provider', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock2', 'code', stateOf(url), bindingValue),
      /provider|state/i,
      'state is bound to the provider it was issued for',
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session was created');
  });

  test('rejects an unknown state token', async function(assert) {
    const oauth = buildOAuth();
    const { bindingValue } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'code', 'never-issued', bindingValue),
      /Invalid or missing state token/,
    );
  });

  test('rejects a missing or empty state token', async function(assert) {
    const oauth = buildOAuth();
    const { bindingValue } = oauth.getAuthorizationUrl('mock');

    await assert.rejects(
      oauth.handleCallback('mock', 'code', '', bindingValue),
      /Invalid or missing state token/,
    );
    await assert.rejects(
      oauth.handleCallback('mock', 'code', undefined as unknown as string, bindingValue),
      /Invalid or missing state token/,
    );
  });

  // The offset is a literal, deliberately. Deriving it from STATE_TTL_MS — as
  // this test previously did — makes it green for every possible value of the
  // constant it is testing, including one second.
  test('rejects a state token older than ten minutes', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(url);

    const record = oauth.stateStore.pending.get(stateToken)!;
    record.createdAt = Date.now() - 11 * 60 * 1000;

    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateToken, bindingValue),
      /expired/,
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session was created');

    // The expiry path must consume too. If the record survives rejection,
    // expired entries accumulate permanently in a map an unauthenticated
    // endpoint fills — #38's defect, made worse, in #38's own file.
    assert.false(
      oauth.stateStore.pending.has(stateToken),
      'an expired record does not survive the callback that rejected it',
    );
  });

  // GUARD — passes on current head. The lower bound of the window: without it
  // the TTL can be cut to a second and every test above stays green.
  test('GUARD accepts a state token just under ten minutes old', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(url);

    const record = oauth.stateStore.pending.get(stateToken)!;
    record.createdAt = Date.now() - 9 * 60 * 1000;

    const session = await oauth.handleCallback('mock', 'code', stateToken, bindingValue);
    assert.ok(session.sessionId, 'a user who reads the consent screen slowly can still log in');
  });

  // GUARD — passes on current head. The README promises ten minutes and the
  // binding cookie's Max-Age is derived from this constant, so its magnitude is
  // consumer-visible and belongs pinned against a literal.
  test('GUARD the state TTL is ten minutes', function(assert) {
    assert.equal(STATE_TTL_MS, 600000, 'STATE_TTL_MS is 600000ms');
    assert.equal(new StateStore().ttl, 600000, 'a default StateStore uses it');
  });

  test('a successful callback consumes the state — replay is rejected', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(url);

    await oauth.handleCallback('mock', 'code', stateToken, bindingValue);

    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateToken, bindingValue),
      /Invalid or missing state token/,
      'the same state cannot be used twice',
    );
    assert.equal(oauth.sessionManager.sessions.size, 1, 'exactly one session across both attempts');
  });

  test('a rejected callback consumes the state too — the correct binding cannot follow it', async function(assert) {
    const oauth = buildOAuth();
    const clientA = oauth.getAuthorizationUrl('mock');
    const clientB = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(clientA.url);

    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateToken, clientB.bindingValue),
      /binding|state/i,
    );

    // A failed attempt burns the state: every state gets exactly one attempt,
    // whatever the outcome. Not an anti-brute-force measure — guessing 32
    // CSPRNG bytes is infeasible either way — but the reason the callback is
    // never a repeatable oracle of any kind.
    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateToken, clientA.bindingValue),
      /Invalid or missing state token/,
      'the state did not survive the failed attempt',
    );
    assert.equal(oauth.sessionManager.sessions.size, 0, 'no session was created');
  });

  // Assertion 7
  test('the server-side pending record does not hold the binding value in plaintext', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(url);

    const record = oauth.stateStore.pending.get(stateToken);
    assert.ok(record, 'an in-flight state has a pending record');

    const serialized = JSON.stringify([...oauth.stateStore.pending.entries()]);
    assert.notOk(
      serialized.includes(bindingValue),
      'the binding value does not appear in the serialized pending state',
    );

    // ...and the stored form alone does not unlock the callback.
    await assert.rejects(
      oauth.handleCallback('mock', 'code', stateToken, record!.bindingHash),
      /binding|state/i,
      'presenting the stored record value is not sufficient',
    );
  });

  test('a consumed state leaves no pending record behind', async function(assert) {
    const oauth = buildOAuth();
    const { url, bindingValue } = oauth.getAuthorizationUrl('mock');
    const stateToken = stateOf(url);

    assert.true(oauth.stateStore.pending.has(stateToken), 'record exists while in flight');

    await oauth.handleCallback('mock', 'code', stateToken, bindingValue);

    assert.false(oauth.stateStore.pending.has(stateToken), 'record removed once consumed');
  });
});
