import QUnit from 'qunit';
import log from 'stonyx/log';
import AuthRequest from '../../src/auth-request.js';
import { STATE_COOKIE_NAME } from '../../src/constants.js';

const { module, test } = QUnit;

/**
 * Route-level unit coverage for the #36 binding mechanism.
 *
 * These cover the branches the integration suite structurally cannot reach: it
 * always speaks HTTP to loopback through a real `@stonyx/rest-server`, so it
 * can never present a request whose response cannot set a cookie, and never a
 * non-loopback host. Both are behaviours this PR's README promotes to
 * deployment-relevant properties.
 */

/** Mirrors `CookieOptions` in src/auth-request.ts, which is not exported. */
interface FakeCookieOptions {
  httpOnly: boolean;
  sameSite: string;
  path: string;
  secure: boolean;
  maxAge?: number;
}

interface CookieCall {
  name: string;
  value: string;
  options: FakeCookieOptions;
}

interface FakeRequestOptions {
  cookie?: string;
  /** `null` omits the Host header entirely. */
  host?: string | null;
  secure?: boolean;
  /** Simulates a deployment where `req.res` is not an Express response. */
  withRes?: boolean;
}

function buildRequest({ cookie, host = 'api.example.com', secure, withRes = true }: FakeRequestOptions = {}) {
  const cookies: CookieCall[] = [];
  const cleared: CookieCall[] = [];

  const res = {
    cookie(name: string, value: string, options: FakeCookieOptions) {
      cookies.push({ name, value, options });
    },
    clearCookie(name: string, options: FakeCookieOptions) {
      cleared.push({ name, value: '', options });
    },
  };

  const req = {
    headers: {
      ...(host === null ? {} : { host }),
      ...(cookie === undefined ? {} : { cookie }),
    } as Record<string, string | undefined>,
    params: { provider: 'mock' } as Record<string, string>,
    query: {} as Record<string, string>,
    secure,
    res: withRes ? res : undefined,
  };

  return { req, cookies, cleared };
}

const stubOAuth = {
  frontendCallbackUrl: 'http://localhost:4200/auth/callback',
  getSession: () => undefined,
  getAuthorizationUrl: () => ({
    url: 'https://stub.provider/oauth/authorize?state=stub-state',
    bindingValue: 'stub-binding-value',
  }),
  handleCallback: async () => ({ sessionId: 'stub-session', expiresAt: 0 }),
  logout: () => {},
};

function buildAuthRequest(): AuthRequest {
  return new AuthRequest(stubOAuth);
}

module('[Unit] AuthRequest binding cookie', function() {
  // GUARD — passes on current head. It pins the fail-closed login path, which
  // `abofs/stonyx-rest-server#45` is explicitly intended to be migrated onto:
  // if `req.res` goes away and this guard is tidied out with it, login silently
  // resumes issuing states it cannot bind, which is #36 reopened.
  test('GUARD #36 login fails closed with 500 and issues no redirect when the binding cookie cannot be set', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ withRes: false });
    const state: { redirect?: string } = {};

    const result = authRequest.handlers.get['/login/:provider'](req, state);

    assert.equal(result, 500, 'login refuses rather than issuing an unbindable state');
    assert.equal(state.redirect, undefined, 'no authorization URL is handed to the client');
  });

  test('#36 the binding cookie is Secure on a non-loopback host even when Express reports the request as plaintext', function(assert) {
    const authRequest = buildAuthRequest();

    // The standard production topology: TLS terminated at a proxy, plaintext to
    // the origin, and `@stonyx/rest-server` leaves `trustProxy` off by default —
    // so `req.secure` is false on every request to an HTTPS site.
    const { req, cookies } = buildRequest({ host: 'api.example.com', secure: false });
    authRequest.handlers.get['/login/:provider'](req, {});

    assert.equal(cookies.length, 1, 'a binding cookie was issued');
    assert.true(
      cookies[0].options.secure,
      'the binding value is not permitted to travel over plaintext on a public host',
    );
  });

  test('#36 the binding cookie is Secure when a forwarded-proto header is honoured', function(assert) {
    const authRequest = buildAuthRequest();
    const { req, cookies } = buildRequest({ host: 'api.example.com', secure: true });

    authRequest.handlers.get['/login/:provider'](req, {});

    assert.true(cookies[0].options.secure, 'an https request still yields a Secure cookie');
  });

  // GUARD — passes on current head. Pins the one exemption, so a later
  // "always Secure" simplification cannot silently break plaintext local dev.
  test('GUARD #36 the binding cookie is not Secure on a loopback host', function(assert) {
    const authRequest = buildAuthRequest();

    for (const host of ['localhost:2666', '127.0.0.1:2666', '[::1]:2666']) {
      const { req, cookies } = buildRequest({ host, secure: false });
      authRequest.handlers.get['/login/:provider'](req, {});

      assert.false(cookies[0].options.secure, `${host} is treated as a development origin`);
    }
  });

  test('#36 the binding cookie is Secure when the request carries no Host header', function(assert) {
    const authRequest = buildAuthRequest();
    const { req, cookies } = buildRequest({ host: null, secure: false });

    authRequest.handlers.get['/login/:provider'](req, {});

    assert.true(
      cookies[0].options.secure,
      'an unattributable origin is not granted the development exemption',
    );
  });

  test('#36 a malformed percent-encoded binding cookie does not throw', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ cookie: `${STATE_COOKIE_NAME}=%` });

    // Before the fix this raised URIError out of the callback handler, which
    // Express answers with a 500 carrying a full stack trace to an
    // unauthenticated caller.
    const value = authRequest.readBindingCookie(req);

    assert.equal(value, '%', 'the raw cookie value is returned for the binding check to reject');
  });

  // GUARD — passes on current head. Every committed HTTP test sends exactly one
  // cookie; a real browser sends every applicable cookie in one header.
  test('GUARD #36 the binding cookie is found in a realistic multi-cookie header', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({
      cookie: `_ga=GA1.1.9999; sid=abc; ${STATE_COOKIE_NAME}=the-binding-value; theme=dark`,
    });

    assert.equal(authRequest.readBindingCookie(req), 'the-binding-value');
  });

  // GUARD — passes on current head. Pins the `separator === -1` skip branch.
  test('GUARD #36 a valueless cookie segment is skipped rather than matched', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ cookie: `flagged; ${STATE_COOKIE_NAME}=the-binding-value` });

    assert.equal(authRequest.readBindingCookie(req), 'the-binding-value');
    assert.equal(
      authRequest.readBindingCookie(buildRequest({ cookie: 'flagged' }).req),
      undefined,
      'a header with no name=value pair yields no binding value',
    );

    // Without the skip, `indexOf('=')` is -1 and `slice(0, -1)` drops the last
    // character — so a *valueless* cookie one character longer than ours parses
    // as a name match and its whole text is handed back as a binding value.
    assert.equal(
      authRequest.readBindingCookie(buildRequest({ cookie: `${STATE_COOKIE_NAME}1` }).req),
      undefined,
      'a longer valueless cookie name is not misread as the binding cookie',
    );
  });

  test('#36 a rejected callback logs the reason server-side', async function(assert) {
    const rejecting = {
      ...stubOAuth,
      handleCallback: async () => {
        throw new Error('State token is not bound to this client');
      },
    };
    const authRequest = new AuthRequest(rejecting);
    const { req } = buildRequest();
    req.query = { code: 'a-code', state: 'a-state' };

    const logged: string[] = [];
    const original = log.error;
    log.error = (message: string) => { logged.push(message); };

    try {
      await authRequest.handlers.get['/callback/:provider'](req, {});
    } finally {
      log.error = original;
    }

    assert.equal(logged.length, 1, 'exactly one rejection line is logged');
    assert.ok(
      logged[0].includes('State token is not bound to this client'),
      'the distinguishing reason reaches the server log, not just the opaque auth_failed',
    );
  });

  // GUARD — passes on current head. Pins the `clearCookie` absence branch: the
  // clear must not throw on the same deployment the 500 guard above exists for.
  test('GUARD #36 clearing the binding cookie is a no-op when the response cannot clear cookies', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ withRes: false });

    authRequest.clearBindingCookie(req);

    assert.ok(true, 'no throw when req.res is not an Express response');
  });
});
