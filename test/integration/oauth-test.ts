import QUnit from 'qunit';
import RestServer from '@stonyx/rest-server';
import config from 'stonyx/config';
import { setupIntegrationTests } from 'stonyx/test-helpers';
import sinon from 'sinon';
// The built entry the stonyx module loader instantiated. `../../src/main.js`
// is a second, never-initialized module instance and reports nothing.
import OAuth from '@stonyx/oauth';

const { module, test } = QUnit;
let endpoint: string;


/**
 * The cookie the login redirect must issue, and that the callback must
 * require. Pinned here as a wire contract rather than imported from `src/`,
 * so a rename shows up as a deliberate breaking change (#36).
 */
const STATE_COOKIE_NAME = 'oauth_state';

interface ParsedCookie {
  name: string;
  value: string;
  attributes: Map<string, string>;
}

function parseSetCookie(header: string): ParsedCookie {
  const [pair, ...rest] = header.split(';').map(part => part.trim());
  const separator = pair.indexOf('=');
  const attributes = new Map<string, string>();

  for (const attribute of rest) {
    const index = attribute.indexOf('=');
    if (index === -1) attributes.set(attribute.toLowerCase(), '');
    else attributes.set(attribute.slice(0, index).toLowerCase(), attribute.slice(index + 1));
  }

  return { name: pair.slice(0, separator), value: pair.slice(separator + 1), attributes };
}

interface LoginResult {
  /** The OAuth2 `state` parameter handed to the provider. */
  state: string;
  /** Every `Set-Cookie` the login response issued, verbatim. */
  setCookie: string[];
  /** Those cookies folded into a `Cookie` request header, as a browser would. */
  cookie: string;
}

/**
 * Starts a login the way a browser does, and keeps the cookie jar.
 *
 * This replaces the bare-`fetch` `getValidState` helper, which is itself the
 * attack in #36: it mints a state with one client and redeems it with another.
 */
async function login(endpoint: string, provider = 'mock'): Promise<LoginResult> {
  const response = await fetch(`${endpoint}/auth/login/${provider}`, { redirect: 'manual' });
  const setCookie = response.headers.getSetCookie();
  const cookie = setCookie.map(header => header.split(';')[0]).join('; ');
  const state = new URL(response.headers.get('location')!).searchParams.get('state')!;

  return { state, setCookie, cookie };
}

function callbackUrl(endpoint: string, stateToken: string, code = 'test-auth-code'): string {
  return `${endpoint}/auth/callback/mock?code=${code}&state=${encodeURIComponent(stateToken)}`;
}

module('[Integration] OAuth', function(hooks: NestedHooks) {
  setupIntegrationTests(hooks);

  hooks.before(function() {
    endpoint = `http://localhost:${(config as Record<string, Record<string, unknown>>).restServer.port}`;
  });

  hooks.after(function() {
    RestServer.close();
  });

  test('GET /auth/login/mock redirects to provider auth URL', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/login/mock`, { redirect: 'manual' });

    assert.equal(response.status, 302);

    const location = response.headers.get('location')!;
    assert.ok(location.startsWith('https://mock.provider/oauth/authorize?'));
    assert.ok(location.includes('client_id=test-client-id'));
    assert.ok(location.includes('response_type=code'));
  });

  test('GET /auth/login/nonexistent returns 404', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/login/nonexistent`, { redirect: 'manual' });

    assert.equal(response.status, 404);
  });

  test('GET /auth/callback/mock with valid state redirects to frontend with session', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);
    const response = await fetch(callbackUrl(endpoint, state), { redirect: 'manual', headers: { cookie } });

    assert.equal(response.status, 302);

    const location = response.headers.get('location')!;
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'http://localhost:4200/auth/callback');
    assert.ok(redirectUrl.searchParams.get('sessionId'), 'redirect includes sessionId');
    assert.ok(redirectUrl.searchParams.get('expiresAt'), 'redirect includes expiresAt');
  });

  test('GET /auth with valid session returns user', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);
    const callbackResponse = await fetch(callbackUrl(endpoint, state, 'test-code'), { redirect: 'manual', headers: { cookie } });
    const location = callbackResponse.headers.get('location')!;
    const sessionId = new URL(location).searchParams.get('sessionId')!;

    const response = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': sessionId },
    });
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.id, 'mock-user-123');
  });

  test('GET /auth without session returns 401', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth`);

    assert.equal(response.status, 401);
  });

  test('GET /auth with invalid session returns 401', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': 'invalid-session' },
    });

    assert.equal(response.status, 401);
  });

  test('GET /auth/logout invalidates session', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);
    const callbackResponse = await fetch(callbackUrl(endpoint, state, 'test-code'), { redirect: 'manual', headers: { cookie } });
    const location = callbackResponse.headers.get('location')!;
    const sessionId = new URL(location).searchParams.get('sessionId')!;

    // Logout
    const logoutResponse = await fetch(`${endpoint}/auth/logout`, {
      headers: { 'session-id': sessionId },
    });
    assert.equal(logoutResponse.status, 200);

    // Verify session is invalid
    const authResponse = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': sessionId },
    });
    assert.equal(authResponse.status, 401);
  });

  test('GET /auth/callback/mock rejects missing state token', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location')!;
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.searchParams.get('error'), 'auth_failed');
  });

  test('GET /auth/callback/mock rejects invalid state token', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code&state=bogus-state`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location')!;
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.searchParams.get('error'), 'auth_failed');
  });

  test('GET /auth/callback/mock with error param redirects with error', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?error=access_denied`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location')!;
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'http://localhost:4200/auth/callback');
    assert.equal(redirectUrl.searchParams.get('error'), 'access_denied');
  });

  test('GET /auth/callback/mock state token cannot be reused', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);

    // First use succeeds
    const first = await fetch(callbackUrl(endpoint, state, 'test-code'), { redirect: 'manual', headers: { cookie } });
    assert.equal(first.status, 302);
    const firstLocation = new URL(first.headers.get('location')!);
    assert.ok(firstLocation.searchParams.get('sessionId'), 'first use succeeds');

    // Second use fails
    const second = await fetch(callbackUrl(endpoint, state, 'test-code'), { redirect: 'manual', headers: { cookie } });
    assert.equal(second.status, 302);
    const secondLocation = new URL(second.headers.get('location')!);
    assert.equal(secondLocation.searchParams.get('error'), 'auth_failed', 'reuse is rejected');
  });

  // ===========================================================================
  // #36 — `state` must be bound to the client that requested it.
  //
  // These live inside this module deliberately: `hooks.after` calls
  // `RestServer.close()`, so an integration test in a file sorting after this
  // one gets a dead server and `TypeError: fetch failed`.
  // ===========================================================================

  test('AC1: login issues a binding cookie (HttpOnly, SameSite=Lax, Path=/, no Secure on loopback)', async function(assert: Assert) {
    const response = await fetch(`${endpoint}/auth/login/mock`, { redirect: 'manual' });
    const setCookie = response.headers.getSetCookie();

    // Unconditionally required. `if (cookie) assert(...)` passes vacuously on a
    // tree that issues no cookie at all, which is exactly the pre-fix tree.
    assert.equal(setCookie.length, 1, 'login issues exactly one Set-Cookie');

    const cookie = parseSetCookie(setCookie[0] ?? '');
    assert.equal(cookie.name, STATE_COOKIE_NAME, `the cookie is named ${STATE_COOKIE_NAME}`);
    assert.ok(cookie.value.length >= 32, 'the binding value carries real entropy');
    assert.true(cookie.attributes.has('httponly'), 'HttpOnly — script must not read or forge the binding value');
    assert.equal(
      (cookie.attributes.get('samesite') ?? '').toLowerCase(),
      'lax',
      'SameSite=Lax — Strict is withheld on the provider callback and breaks every login',
    );
    assert.equal(
      cookie.attributes.get('path'),
      '/',
      'Path=/ — routing is case-insensitive but RFC 6265 Path matching is not',
    );
    assert.false(
      cookie.attributes.has('secure'),
      'Secure is absent when the configured redirect URI is plaintext loopback',
    );
  });

  test('AC2: an unbound or cross-client callback mints no session', async function(assert: Assert) {
    const oauth = OAuth.instance!;
    const { sessions } = oauth.sessionManager;
    const exchangeCode = sinon.spy(oauth.getProvider('mock').flow, 'exchangeCode');

    try {
      const foreign = await login(endpoint);

      const cases: Array<[string, Record<string, string>]> = [
        ['no cookie at all', {}],
        ['an empty binding cookie', { cookie: `${STATE_COOKIE_NAME}=` }],
        ['a malformed Cookie header', { cookie: `${STATE_COOKIE_NAME}` }],
        ["a different client's cookie", { cookie: foreign.cookie || 'placeholder=1' }],
      ];

      for (const [label, headers] of cases) {
        const { state } = await login(endpoint);
        const before = sessions.size;

        const response = await fetch(callbackUrl(endpoint, state), { redirect: 'manual', headers });
        const redirect = new URL(response.headers.get('location')!);

        assert.equal(redirect.searchParams.get('error'), 'auth_failed', `${label}: callback rejected`);
        assert.notOk(redirect.searchParams.get('sessionId'), `${label}: no sessionId handed to the caller`);
        assert.equal(sessions.size, before, `${label}: no session minted server-side`);
      }
    } finally {
      exchangeCode.restore();
    }

    // Reds any implementation that binds *after* the token exchange: rejecting
    // once a live authorization code has been burned still leaks a token.
    assert.equal(exchangeCode.callCount, 0, 'exchangeCode is never invoked for an unbound callback');
  });

  test('AC3: state is consumed on first presentation regardless of the binding outcome', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;
    const victim = await login(endpoint);
    const foreign = await login(endpoint);
    const before = sessions.size;

    const first = await fetch(callbackUrl(endpoint, victim.state), {
      redirect: 'manual',
      headers: { cookie: foreign.cookie || 'placeholder=1' },
    });
    assert.equal(
      new URL(first.headers.get('location')!).searchParams.get('error'),
      'auth_failed',
      'the mis-bound presentation is rejected',
    );

    // If the binding is checked before the state is consumed, the endpoint is a
    // repeatable oracle against the binding value. It must not be.
    const second = await fetch(callbackUrl(endpoint, victim.state), {
      redirect: 'manual',
      headers: victim.cookie ? { cookie: victim.cookie } : {},
    });
    assert.equal(
      new URL(second.headers.get('location')!).searchParams.get('error'),
      'auth_failed',
      're-presenting the burned state with the correct cookie is also rejected',
    );

    assert.equal(sessions.size, before, 'neither presentation minted a session');
  });

  test('AC4: cookies present but no binding cookie is a rejection, never a bypass', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;
    const { state } = await login(endpoint);
    const before = sessions.size;

    const response = await fetch(callbackUrl(endpoint, state), {
      redirect: 'manual',
      headers: { cookie: 'unrelated=1; another=2' },
    });
    const redirect = new URL(response.headers.get('location')!);

    assert.equal(redirect.searchParams.get('error'), 'auth_failed', 'callback rejected');
    assert.notOk(redirect.searchParams.get('sessionId'), 'no sessionId handed to the caller');
    assert.equal(sessions.size, before, 'no session minted server-side');
  });

  test('AC6 (GUARD — passes with the fix reverted; not evidence of the fix): the same-client flow still works', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);

    const response = await fetch(callbackUrl(endpoint, state), {
      redirect: 'manual',
      headers: cookie ? { cookie } : {},
    });
    const sessionId = new URL(response.headers.get('location')!).searchParams.get('sessionId');
    assert.ok(sessionId, 'the client that started the flow receives a session');

    const authenticated = await fetch(`${endpoint}/auth`, { headers: { 'session-id': sessionId! } });
    const user = await authenticated.json();

    assert.equal(authenticated.status, 200, 'the issued session validates at GET /auth');
    assert.equal(user.id, 'mock-user-123', 'and resolves to the authenticated user');
  });
});
