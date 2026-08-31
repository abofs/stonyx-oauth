import QUnit from 'qunit';
import RestServer from '@stonyx/rest-server';
import config from 'stonyx/config';
import { setupIntegrationTests } from 'stonyx/test-helpers';
// NOTE (#36): the live singleton the running server uses is the *built* entry
// point loaded by the stonyx module loader. Importing `../../src/main.js` here
// yields a second, never-initialized module instance whose `OAuth.instance` is
// `undefined` — reaching for `sessionManager` through it throws rather than
// observing anything. Session-count assertions must go through the package
// entry point, which is the instance the HTTP server is actually serving from.
import OAuth from '@stonyx/oauth';
import { STATE_COOKIE_NAME } from '@stonyx/oauth/constants';

const { module, test } = QUnit;
let endpoint: string;

interface LoginResult {
  status: number;
  setCookie: string[];
  bindingCookie: string | undefined;
  /** Ready-to-send `cookie` request header value, or '' when none was issued. */
  cookieHeader: string;
  state: string;
}

/**
 * Drives GET /auth/login/:provider and captures both halves of the flow —
 * the `state` handed to the provider and the client-held binding cookie.
 *
 * `fetch` has no cookie jar, so every caller of this helper is a genuinely
 * independent client: cookies are only ever sent when a test passes them
 * explicitly.
 */
async function login(provider = 'mock'): Promise<LoginResult> {
  const response = await fetch(`${endpoint}/auth/login/${provider}`, { redirect: 'manual' });
  const setCookie = response.headers.getSetCookie();
  const bindingCookie = setCookie.find(cookie => cookie.startsWith(`${STATE_COOKIE_NAME}=`));
  const location = response.headers.get('location');
  const state = location ? new URL(location).searchParams.get('state') ?? '' : '';

  return {
    status: response.status,
    setCookie,
    bindingCookie,
    cookieHeader: bindingCookie ? bindingCookie.split(';')[0] : '',
    state,
  };
}

/** Omits the header entirely when the client holds no binding cookie. */
function cookieHeaders(cookieHeader: string): Record<string, string> {
  return cookieHeader ? { cookie: cookieHeader } : {};
}

async function callback(
  { provider = 'mock', state = '', code = 'test-auth-code', cookieHeader = '' } = {}
) {
  const query = new URLSearchParams({ code, state });
  const response = await fetch(`${endpoint}/auth/callback/${provider}?${query}`, {
    redirect: 'manual',
    headers: cookieHeaders(cookieHeader),
  });
  const location = response.headers.get('location');

  return {
    status: response.status,
    location,
    redirectUrl: location ? new URL(location) : null,
    sessionId: location ? new URL(location).searchParams.get('sessionId') : null,
    error: location ? new URL(location).searchParams.get('error') : null,
  };
}

/** Live session count, read off the singleton the server is actually using. */
function sessionCount(): number {
  return OAuth.instance!.sessionManager.sessions.size;
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

  // ---------------------------------------------------------------------------
  // #36 — state is bound to the client that initiated the flow
  // ---------------------------------------------------------------------------

  // Assertion 1
  test('#36 login issues an HttpOnly, SameSite=Lax, Path=/auth binding cookie', async function(assert: Assert) {
    const { status, bindingCookie } = await login();

    assert.equal(status, 302, 'login still redirects');
    assert.ok(bindingCookie, `login response carries a ${STATE_COOKIE_NAME} cookie`);

    const cookie = bindingCookie ?? '';
    assert.ok(/;\s*HttpOnly/i.test(cookie), 'binding cookie is HttpOnly');
    assert.ok(/;\s*SameSite=Lax/i.test(cookie), 'binding cookie is SameSite=Lax');
    assert.ok(/;\s*Path=\/auth/i.test(cookie), 'binding cookie is scoped to Path=/auth');
    // SameSite=Strict withholds the cookie on the provider's top-level callback
    // navigation and breaks login outright; SameSite=None needs Secure and
    // widens exposure. Both are pinned out so a later "hardening" pass cannot
    // silently break the flow.
    assert.notOk(/SameSite=Strict/i.test(cookie), 'binding cookie is not SameSite=Strict');
    assert.notOk(/SameSite=None/i.test(cookie), 'binding cookie is not SameSite=None');
  });

  // Assertion 2
  test('#36 callback with a valid state but no binding cookie mints no session', async function(assert: Assert) {
    const clientA = await login();
    const before = sessionCount();

    const result = await callback({ state: clientA.state });

    assert.equal(result.status, 302);
    assert.notOk(result.sessionId, 'redirect carries no sessionId');
    assert.equal(result.error, 'auth_failed', 'callback is rejected');
    assert.equal(sessionCount(), before, 'no session was created server-side');
  });

  // Assertion 3
  test('#36 callback with client A state and client B binding cookie mints no session', async function(assert: Assert) {
    const clientA = await login();
    const clientB = await login();
    const before = sessionCount();

    assert.notEqual(clientA.state, clientB.state, 'the two clients hold distinct states');

    const result = await callback({ state: clientA.state, cookieHeader: clientB.cookieHeader });

    assert.equal(result.status, 302);
    assert.notOk(result.sessionId, 'redirect carries no sessionId');
    assert.equal(result.error, 'auth_failed', 'callback is rejected');
    assert.equal(sessionCount(), before, 'no session was created server-side');
  });

  // Assertion 4 — GUARD. This also passes against pre-fix code (which ignores
  // cookies entirely). It exists to prove the binding did not break the happy
  // path: an over-strict cookie would fail here while assertions 1-3 stayed green.
  test('#36 GUARD callback with matching state and binding cookie completes the flow', async function(assert: Assert) {
    const clientA = await login();

    const result = await callback({ state: clientA.state, cookieHeader: clientA.cookieHeader });

    assert.equal(result.status, 302);
    assert.equal(
      result.redirectUrl!.origin + result.redirectUrl!.pathname,
      'http://localhost:4200/auth/callback',
      'redirects to the configured frontend callback'
    );
    assert.ok(result.sessionId, 'redirect includes sessionId');
    assert.ok(result.redirectUrl!.searchParams.get('expiresAt'), 'redirect includes expiresAt');

    const authResponse = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': result.sessionId! },
    });
    assert.equal(authResponse.status, 200, 'the minted session validates');
  });

  // Assertion 5
  test('#36 a state issued for mock is rejected at the mock2 callback', async function(assert: Assert) {
    const clientA = await login('mock');
    const before = sessionCount();

    // Client A's own binding cookie is sent, so the *only* thing wrong with
    // this request is the provider it is presented to.
    const result = await callback({
      provider: 'mock2',
      state: clientA.state,
      cookieHeader: clientA.cookieHeader,
    });

    assert.equal(result.status, 302);
    assert.notOk(result.sessionId, 'redirect carries no sessionId');
    assert.equal(result.error, 'auth_failed', 'cross-provider replay is rejected');
    assert.equal(sessionCount(), before, 'no session was created server-side');
  });

  // Assertion 6
  test('#36 a consumed state and its binding cookie cannot be replayed', async function(assert: Assert) {
    const clientA = await login();

    const first = await callback({ state: clientA.state, cookieHeader: clientA.cookieHeader });
    assert.ok(first.sessionId, 'first use succeeds');

    const afterFirst = sessionCount();

    const replay = await callback({ state: clientA.state, cookieHeader: clientA.cookieHeader });
    assert.notOk(replay.sessionId, 'replay of state + cookie mints no session');
    assert.equal(replay.error, 'auth_failed', 'replay is rejected');

    // The binding cookie is consumed too: presenting it against a state issued
    // by a *later* login must not work either.
    const fresh = await login();
    const crossed = await callback({ state: fresh.state, cookieHeader: clientA.cookieHeader });
    assert.notOk(crossed.sessionId, 'consumed cookie against a fresh state mints no session');
    assert.equal(crossed.error, 'auth_failed', 'consumed cookie is rejected');

    assert.equal(sessionCount(), afterFirst, 'neither replay created a session');
  });

  test('#36 callback clears the binding cookie', async function(assert: Assert) {
    const clientA = await login();

    const response = await fetch(
      `${endpoint}/auth/callback/mock?code=test-auth-code&state=${clientA.state}`,
      { redirect: 'manual', headers: cookieHeaders(clientA.cookieHeader) }
    );

    const cleared = response.headers.getSetCookie()
      .find(cookie => cookie.startsWith(`${STATE_COOKIE_NAME}=`));

    assert.ok(cleared, 'callback re-sets the binding cookie');
    assert.ok(
      /Expires=Thu, 01 Jan 1970/i.test(cleared ?? '') || /Max-Age=0/i.test(cleared ?? ''),
      'binding cookie is expired at the client'
    );
  });

  // ---------------------------------------------------------------------------

  test('GET /auth with valid session returns user', async function(assert: Assert) {
    const clientA = await login();
    const { sessionId } = await callback({ state: clientA.state, cookieHeader: clientA.cookieHeader });

    const response = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': sessionId! },
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
    const clientA = await login();
    const { sessionId } = await callback({ state: clientA.state, cookieHeader: clientA.cookieHeader });

    const logoutResponse = await fetch(`${endpoint}/auth/logout`, {
      headers: { 'session-id': sessionId! },
    });
    assert.equal(logoutResponse.status, 200);

    const authResponse = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': sessionId! },
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
});
