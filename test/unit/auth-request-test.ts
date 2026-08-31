import QUnit from 'qunit';
import log from 'stonyx/log';
import AuthRequest from '../../src/auth-request.js';
import { MAX_BINDING_COOKIE_CANDIDATES, STATE_COOKIE_NAME } from '../../src/constants.js';
import { StateRejection } from '../../src/state-store.js';

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
  /**
   * Every `Host` line the request carried, in order. Node collapses repeats
   * into `headers.host` (the first), so the duplicate is only visible here.
   */
  hostLines?: string[];
}

function buildRequest({ cookie, host = 'api.example.com', secure, withRes = true, hostLines }: FakeRequestOptions = {}) {
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

  const lines = hostLines ?? (host === null ? [] : [host]);
  const rawHeaders = lines.flatMap(value => ['Host', value]);

  const req = {
    headers: {
      // Node keeps the first Host and discards the rest.
      ...(lines.length === 0 ? {} : { host: lines[0] }),
      ...(cookie === undefined ? {} : { cookie }),
    } as Record<string, string | undefined>,
    rawHeaders,
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

  // GUARD — passes on current head. Evidenced by mutation: removing the
  // `log.error` in `setBindingCookie` was 74/0. The `500` is pinned by the
  // guard above; the operator-facing line that says *why* was not, and it is
  // the only signal for a framework-wiring failure that produces no exception.
  test('GUARD #36 the fail-closed login path logs why it refused', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ withRes: false });

    const logged: string[] = [];
    const original = log.error;
    log.error = (message: string) => { logged.push(message); };

    try {
      authRequest.handlers.get['/login/:provider'](req, {});
    } finally {
      log.error = original;
    }

    assert.deepEqual(
      logged,
      ['OAuth: unable to set the state binding cookie; login rejected'],
      'the README documents this exact line as the first thing to grep for',
    );
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
  //
  // The list is wider than the three hosts it used to hold. `127.0.0.1` and
  // `localhost` are both in the exact-match set, so a suite that only ever
  // presents those two cannot see the `127.0.0.0/8` test, the IPv6-mapped
  // forms, or the `.toLowerCase()` — each of which was individually removable
  // at 74/0. `127.0.0.2` kills the /8 test, `LOCALHOST` kills the lowercasing,
  // and the two `::ffff:` spellings kill the mapped-IPv4 branch.
  test('GUARD #36 the binding cookie is not Secure on a loopback host', function(assert) {
    const authRequest = buildAuthRequest();

    const loopback = [
      'localhost:2666',
      'LOCALHOST:2666',
      'localhost',
      '127.0.0.1:2666',
      '127.0.0.2:2666',
      '127.255.255.254',
      '[::1]:2666',
      '[::ffff:127.0.0.1]:8080',
      '[::ffff:7f00:1]',
      '0.0.0.0:2666',
    ];

    for (const host of loopback) {
      const { req, cookies } = buildRequest({ host, secure: false });
      authRequest.handlers.get['/login/:provider'](req, {});

      assert.false(cookies[0].options.secure, `${host} is treated as a development origin`);
    }
  });

  // DEFECT — fails against the pre-fix tree, where the loopback predicate was
  // `startsWith('127.')`, `endsWith('.localhost')` and `split(':')[0]`. Each of
  // the hosts below satisfied one of those three and shipped the binding value
  // without `Secure` on a deployment that is not loopback in any sense.
  test('#36 a non-loopback host that merely resembles loopback still gets Secure', function(assert) {
    const authRequest = buildAuthRequest();

    const spoofs = [
      // `startsWith('127.')` is a string prefix, not 127.0.0.0/8 membership.
      // RFC 1123 permits a leading digit in a label, so this is registerable.
      '127.evil.com',
      '127.0.0.1.evil.com',
      '127.0.0.1.nip.io',
      // `endsWith('.localhost')` exempted an entire suffix.
      'evil.localhost',
      'app.localhost',
      'localhost.evil.com',
      // `split(':')[0]` truncates at the first colon, so userinfo defeated it.
      'localhost:80@evil.com',
      '127.0.0.1:80@evil.com',
      // Not the documented rule. The README says a dotted quad of four decimal
      // octets; `127.1` and `127.0.0` are resolver shorthands for loopback, but
      // exempting them would mean the membership test is a length-agnostic
      // "starts with 127" again. Fail secure and stay inside the documentation.
      '127.1',
      '127.0.0',
      '127',
      // Not a bare host[:port] at all — fail secure rather than guess.
      'localhost, api.example.com',
      'localhost/../api.example.com',
      '[::1',
      '127.0.0.256',
    ];

    for (const host of spoofs) {
      const { req, cookies } = buildRequest({ host, secure: false });
      authRequest.handlers.get['/login/:provider'](req, {});

      assert.true(cookies[0].options.secure, `${host} is not granted the development exemption`);
    }
  });

  // GUARD — passes on current head. Evidenced by mutation: loosening
  // `HOSTNAME_PATTERN` to "anything without whitespace" is invisible through
  // the `secure` boolean, because the membership tests are exact and a
  // malformed value fails them anyway. It is not invisible here, and the
  // property being pinned is the one the README states: a `Host` that is not a
  // well-formed `host[:port]` is *rejected*, not silently reinterpreted. The
  // rejection is what keeps the exemption decidable as the loopback set grows.
  test('GUARD #36 the Host parser rejects anything that is not a bare host[:port]', function(assert) {
    const parse = AuthRequest.parseHostname;

    assert.equal(parse('api.example.com'), 'api.example.com');
    assert.equal(parse('API.Example.COM:8443'), 'api.example.com', 'port stripped, name lowercased');
    assert.equal(parse('[::1]:2666'), '::1');
    assert.equal(parse('[::FFFF:127.0.0.1]'), '::ffff:127.0.0.1');

    for (const malformed of [
      'localhost:80@evil.com',
      'localhost:notaport',
      'localhost:80:90',
      'localhost, api.example.com',
      'localhost,api.example.com',
      'localhost/../api.example.com',
      'localhost ',
      '[::1',
      '[::1]junk',
      '[not:an:address!]',
    ]) {
      assert.equal(parse(malformed), undefined, `${JSON.stringify(malformed)} is not a hostname`);
    }
  });

  // DEFECT — fails against the pre-fix tree. Node collapses repeated `Host`
  // headers into the first value, so an upstream component that prepends a
  // `Host:` line rather than replacing it downgrades the cookie on a victim's
  // response. RFC 9112 section 3.2 makes the request invalid; treat it as
  // unattributable.
  test('#36 a request carrying more than one Host header gets Secure', function(assert) {
    const authRequest = buildAuthRequest();

    const { req, cookies } = buildRequest({
      hostLines: ['localhost', 'api.example.com'],
      secure: false,
    });
    authRequest.handlers.get['/login/:provider'](req, {});

    assert.equal(req.headers.host, 'localhost', 'Node exposes only the first Host');
    assert.true(cookies[0].options.secure, 'an ambiguous origin is not granted the exemption');
  });

  // GUARD — passes on current head. Pins the `req.secure === true` early
  // return, which is the only leg of `isSecureContext` that fails *unsafe* when
  // removed. It is invisible on a non-loopback host, because the host test
  // reaches the same answer; only HTTPS-on-loopback separates them.
  test('GUARD #36 an https request on a loopback host still gets Secure', function(assert) {
    const authRequest = buildAuthRequest();
    const { req, cookies } = buildRequest({ host: 'localhost:2666', secure: true });

    authRequest.handlers.get['/login/:provider'](req, {});

    assert.true(cookies[0].options.secure, 'a TLS request is never downgraded by the dev exemption');
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
    const values = authRequest.readBindingCookies(req);

    assert.deepEqual(values, ['%'], 'the raw cookie value is returned for the binding check to reject');
  });

  // GUARD — passes on current head. Every committed HTTP test sends exactly one
  // cookie; a real browser sends every applicable cookie in one header.
  test('GUARD #36 the binding cookie is found in a realistic multi-cookie header', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({
      cookie: `_ga=GA1.1.9999; sid=abc; ${STATE_COOKIE_NAME}=the-binding-value; theme=dark`,
    });

    assert.deepEqual(authRequest.readBindingCookies(req), ['the-binding-value']);
  });

  // GUARD — passes on current head. Pins the `separator === -1` skip branch.
  test('GUARD #36 a valueless cookie segment is skipped rather than matched', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ cookie: `flagged; ${STATE_COOKIE_NAME}=the-binding-value` });

    assert.deepEqual(authRequest.readBindingCookies(req), ['the-binding-value']);
    assert.deepEqual(
      authRequest.readBindingCookies(buildRequest({ cookie: 'flagged' }).req),
      [],
      'a header with no name=value pair yields no binding value',
    );

    // Without the skip, `indexOf('=')` is -1 and `slice(0, -1)` drops the last
    // character — so a *valueless* cookie one character longer than ours parses
    // as a name match and its whole text is handed back as a binding value.
    assert.deepEqual(
      authRequest.readBindingCookies(buildRequest({ cookie: `${STATE_COOKIE_NAME}1` }).req),
      [],
      'a longer valueless cookie name is not misread as the binding cookie',
    );
  });

  // DEFECT — fails against the pre-fix tree, where `readBindingCookie` returned
  // on the first name match. A browser sends every applicable cookie of that
  // name in one header, and a sibling subdomain can plant one that RFC 6265
  // section 5.4 orders ahead of the real one.
  test('#36 every value carrying the binding cookie name is returned, in header order', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({
      cookie: `${STATE_COOKIE_NAME}=planted; _ga=GA1.1.9999; ${STATE_COOKIE_NAME}=the-real-value`,
    });

    assert.deepEqual(
      authRequest.readBindingCookies(req),
      ['planted', 'the-real-value'],
      'a shadow cookie does not hide the one behind it',
    );

    const { req: reversed } = buildRequest({
      cookie: `${STATE_COOKIE_NAME}=the-real-value; ${STATE_COOKIE_NAME}=planted`,
    });

    assert.deepEqual(
      authRequest.readBindingCookies(reversed),
      ['the-real-value', 'planted'],
      'order is preserved rather than decided by the parser',
    );
  });

  // GUARD — passes on current head. The candidate list an unauthenticated
  // caller can ask the binding check to hash is bounded.
  test('GUARD #36 the binding cookie candidate list is capped', function(assert) {
    const authRequest = buildAuthRequest();
    const flood = Array.from({ length: 40 }, (_unused, index) => `${STATE_COOKIE_NAME}=v${index}`).join('; ');
    const { req } = buildRequest({ cookie: flood });

    const values = authRequest.readBindingCookies(req);

    assert.equal(values.length, 8, 'no more than eight candidates are collected');
    assert.equal(MAX_BINDING_COOKIE_CANDIDATES, 8, 'and eight is the documented cap');
    assert.deepEqual(values[0], 'v0', 'the cap truncates the tail, not the head');
  });

  /** Drives the callback route with a stubbed rejection and captures the log. */
  async function loggedRejection(thrown: unknown): Promise<string[]> {
    const rejecting = {
      ...stubOAuth,
      handleCallback: async () => { throw thrown; },
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

    return logged;
  }

  test('#36 a rejected callback logs the reason server-side', async function(assert) {
    const logged = await loggedRejection(
      new StateRejection('State token is not bound to this client', true),
    );

    assert.equal(logged.length, 1, 'exactly one rejection line is logged');
    assert.ok(
      logged[0].includes('State token is not bound to this client'),
      'the distinguishing reason reaches the server log, not just the opaque auth_failed',
    );
  });

  // DEFECT — fails against the pre-fix tree, where the `try` spanned the whole
  // flow and every `Error.message` in it was logged verbatim. Three of the
  // calls it covers are consumer-overridable through the documented
  // `providers.<name>.module` extension point, so a provider that puts request
  // context in its error — ordinary practice — put a `clientSecret` and the
  // caller-supplied `code` into the log. `@stonyx/logs` appends content raw
  // when `logToFile` is on, which makes an echoed `code` a CRLF log-forging
  // primitive too. Before this PR added the log, all of it was swallowed.
  test('#36 an error thrown below the state check does not reach the log', async function(assert) {
    const logged = await loggedRejection(
      new Error(
        'upstream 400 for code=ATTACKER-SUPPLIED-CODE-CANARY '
        + 'client_secret=SUPER-SECRET-CANARY-9931\r\nINJECTED-LOG-LINE',
      ),
    );

    assert.equal(logged.length, 1, 'exactly one line is logged');
    assert.equal(
      logged[0],
      'OAuth: callback failed after state validation',
      'a fixed discriminator, with none of the provider error text',
    );
    assert.notOk(logged[0].includes('SUPER-SECRET-CANARY-9931'), 'no consumer secret in the log');
    assert.notOk(logged[0].includes('ATTACKER-SUPPLIED-CODE-CANARY'), 'no caller-supplied code in the log');
    assert.notOk(/[\r\n]/.test(logged[0]), 'no CRLF reaches the log line');
  });

  // DEFECT — fails against the pre-fix tree. A thrown non-Error reached the log
  // through `String(rejection)`, so a provider throwing an object with a
  // `toString` leaked through the same channel as an `Error.message`.
  test('#36 a non-Error rejection logs the fixed discriminator', async function(assert) {
    const logged = await loggedRejection({ toString: () => 'client_secret=LEAKED-VIA-TOSTRING' });

    assert.deepEqual(logged, ['OAuth: callback failed after state validation']);
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
