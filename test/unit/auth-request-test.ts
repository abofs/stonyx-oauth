import QUnit from 'qunit';
import log from 'stonyx/log';
import AuthRequest from '../../src/auth-request.js';
import { maxHeaderSize } from 'node:http';
import { STATE_COOKIE_NAME, STATE_COOKIE_PATH, STATE_COOKIE_SAME_SITE } from '../../src/constants.js';
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

  // DEFECT — fails against the tree that capped this list at 8. The cap
  // truncated from the *head*, and RFC 6265 section 5.4 sorts an attacker's
  // planted cookies first, so it reinstated the exact denial this parser
  // exists to close: measured on that tree, 7 shadow cookies still reached the
  // real value and 8 hid it permanently, turning a 1-cookie attack into an
  // 8-cookie one rather than closing it. A 4-label API host with a foothold
  // beneath it yields 3 settable parent domains x 3 usable paths = 9.
  test('#36 a shadow-cookie flood past any cap does not hide the real binding value', function(assert) {
    const authRequest = buildAuthRequest();

    // 7 and 8 straddle the withdrawn cap; 9 is the reachable count; 64 is well past.
    for (const shadows of [7, 8, 9, 64]) {
      const planted = Array.from({ length: shadows }, (_unused, index) => `${STATE_COOKIE_NAME}=planted${index}`);
      const { req } = buildRequest({ cookie: [...planted, `${STATE_COOKIE_NAME}=the-real-value`].join('; ') });

      const values = authRequest.readBindingCookies(req);

      assert.equal(values.length, shadows + 1, `${shadows} shadow cookies do not truncate the list`);
      assert.ok(values.includes('the-real-value'), `the real value survives ${shadows} shadow cookies`);
    }
  });

  // GUARD — passes on current head. Evidenced by mutation: reintroducing any
  // cap — `if (values.length >= 8) break;`, or 256, or 778 — is killed here.
  // This pins the argument for having removed the cap, which is that the work
  // an unauthenticated caller can ask for is *already* bounded, structurally
  // and for free: Node caps the whole header block at `maxHeaderSize`, and the
  // shortest segment that can reach the hash is `stonyx_oauth_state=x` at 20
  // bytes. The bound is a consequence of the header limit, so it is computed
  // from `maxHeaderSize` here rather than hard-coded.
  test('GUARD #36 the candidate list is bounded by the header size limit, not by a cap', function(assert) {
    const authRequest = buildAuthRequest();

    assert.equal(maxHeaderSize, 16384, 'the structural bound is Node\'s default 16 KB header limit');

    const segment = `${STATE_COOKIE_NAME}=x`;
    assert.equal(segment.length, 20, 'the shortest segment that can reach the hash is 20 bytes');

    // Every segment but the first also costs a ';', so budget name=value+1 each.
    const reachable = Math.floor((maxHeaderSize - 'Cookie: '.length + 1) / (segment.length + 1));
    assert.equal(reachable, 779, 'a request cannot present more than 779 hashable candidates');

    const { req } = buildRequest({ cookie: Array.from({ length: reachable }, () => segment).join(';') });

    assert.equal(
      authRequest.readBindingCookies(req).length,
      reachable,
      'and all 779 are returned rather than truncated — 0.32 ms to parse and hash, versus a permanent denial',
    );
  });

  // GUARD — passes on current head. Evidenced by mutation: giving the clear a
  // `path` of its own — `{ ...this.cookieOptions(req), path: '/' }` — left the
  // whole suite green, and a clear on `/` does not clear a cookie set on
  // `/auth`. The rest of this file pins *when* the clear happens and *whether*
  // a record was burned; nothing pinned whether it works. A clear that never
  // clears is indistinguishable from a correct one unless the attributes the
  // browser matches on are compared against the ones the cookie was set with.
  test('GUARD #36 the clear targets the same Path the cookie was set on', function(assert) {
    const authRequest = buildAuthRequest();
    const { req, cookies, cleared } = buildRequest();

    authRequest.setBindingCookie(req, 'a-binding-value');
    authRequest.clearBindingCookie(req);

    assert.equal(cookies.length, 1, 'the cookie was set');
    assert.equal(cleared.length, 1, 'and cleared');

    assert.equal(cookies[0].options.path, STATE_COOKIE_PATH, 'set on the constant path');
    assert.equal(cleared[0].options.path, STATE_COOKIE_PATH, 'and cleared on it too');
    assert.equal(STATE_COOKIE_PATH, '/auth', 'which is /auth, written as a literal so the constant cannot satisfy itself');

    // The browser matches a clear to a stored cookie on name + domain + path,
    // so a divergence in any of those is a clear that silently does nothing.
    assert.equal(cleared[0].name, cookies[0].name, 'same cookie name');
    assert.equal(cleared[0].options.path, cookies[0].options.path, 'same path as the set — the clear can actually match');
    assert.equal(cleared[0].options.secure, cookies[0].options.secure, 'same Secure');
    assert.equal(cleared[0].options.sameSite, cookies[0].options.sameSite, 'same SameSite');
    assert.equal(cleared[0].options.httpOnly, cookies[0].options.httpOnly, 'same HttpOnly');
  });

  // GUARD — passes on current head. Evidenced by mutation: flipping
  // `httpOnly` to `false`, or `sameSite` to `'strict'`, was green. All three
  // attributes are argued as load-bearing in `constants.ts` — `Strict`
  // withholds the cookie on the provider's cross-site top-level GET and breaks
  // login outright, and `HttpOnly` is what stops script forging the value.
  test('GUARD #36 the binding cookie carries the load-bearing attributes', function(assert) {
    const authRequest = buildAuthRequest();
    const { req, cookies } = buildRequest();

    authRequest.setBindingCookie(req, 'a-binding-value');

    assert.true(cookies[0].options.httpOnly, 'HttpOnly, so script cannot read or forge the binding value');
    assert.equal(cookies[0].options.sameSite, 'lax', 'SameSite=Lax — Strict breaks the provider callback outright');
    assert.equal(STATE_COOKIE_SAME_SITE, 'lax', 'and lax is what the constant says');
    assert.equal(cookies[0].name, STATE_COOKIE_NAME, 'under the documented cookie name');
    assert.equal(cookies[0].value, 'a-binding-value', 'carrying the value it was handed');
  });

  // GUARD — passes on current head. Evidenced by mutation: `index += 2` ->
  // `index += 1` in `hasAmbiguousHost` was 96/0. The flat `rawHeaders` list is
  // `[name, value, name, value, ...]`, so a stride of 1 counts header *values*
  // as if they were names: any request carrying a header whose value happens to
  // be the word `host` — a `Referer`, a `Vary: host`, a proxy hint — would be
  // declared ambiguous. That fails secure rather than open, so nothing broke,
  // but it makes the duplicate-Host detector fire on requests that carry
  // exactly one Host, and the test that pins the detector must therefore also
  // pin that it reads names only.
  test('GUARD #36 the duplicate-Host scan reads header names, not header values', function(assert) {
    const authRequest = buildAuthRequest();
    const { req } = buildRequest({ host: '127.0.0.1' });

    // One Host header, plus another header whose *value* is the word "host".
    req.rawHeaders = ['Host', '127.0.0.1', 'Vary', 'host', 'X-Forwarded-For', 'host'];

    assert.false(AuthRequest.hasAmbiguousHost(req), 'a header value of "host" is not a second Host header');
    assert.false(authRequest.isSecureContext(req), 'so a genuine single-Host loopback request is still exempt');

    req.rawHeaders = ['Host', '127.0.0.1', 'host', 'evil.example.com'];
    assert.true(AuthRequest.hasAmbiguousHost(req), 'two Host *names* are still ambiguous, in any case');
  });

  // GUARD — passes on current head. Evidenced by mutation: dropping
  // `HOSTNAME_PATTERN.test(name)` from the ported branch was 96/0, and widening
  // `HOSTNAME_PATTERN` to admit `@` was 96/0. The existing parser guard covers
  // the *bare* branch; the branch taken when a port is present had nothing
  // pinning the charset, so `parseHostname` could return a value that is not a
  // registered name at all while still satisfying its documented contract test.
  // Neither mutation flips a Secure decision today — no illegal-charset name is
  // a member of the loopback set — but `parseHostname` is a `static` whose
  // contract is "undefined unless this is a well-formed host[:port]", and the
  // whole Secure decision is built on trusting that.
  test('GUARD #36 the Host parser enforces the hostname charset on the ported branch too', function(assert) {
    for (const host of ['localhost:80@evil.com', 'local@host:8080', 'a,b:80', 'has space:80', 'x/y:80']) {
      assert.equal(AuthRequest.parseHostname(host), undefined, `${host} is not a bare host[:port]`);
    }

    assert.equal(AuthRequest.parseHostname('localhost@evil.com'), undefined, 'nor is an @ without a port');
    assert.equal(AuthRequest.parseHostname('api.example.com:8080'), 'api.example.com', 'a real host[:port] still parses');
    assert.equal(AuthRequest.parseHostname('LOCALHOST:3000'), 'localhost', 'and is lowercased');
  });

  // GUARD — passes on current head. Evidenced by mutation: `octets.length !== 4`
  // -> `octets.length < 4` was 96/0. This one does flip a Secure decision.
  // `127.0.0.1.5` is five numeric labels, every one of them a legal DNS label
  // and every one <= 255, so the relaxed check reads it as loopback and the
  // binding cookie ships without `Secure` — to a name that is registerable and
  // resolvable to anything. Dotted-quad membership means exactly four octets.
  test('GUARD #36 only a four-octet dotted quad is loopback', function(assert) {
    const authRequest = buildAuthRequest();

    for (const host of ['127.0.0.1.5', '127.0.0.1.1.1', '127.0.0', '127.0.0.1.evil.com']) {
      assert.false(AuthRequest.isLoopbackHost(host), `${host} is not 127.0.0.0/8`);
      assert.true(authRequest.isSecureContext(buildRequest({ host }).req), `and ${host} gets Secure`);
    }

    assert.true(AuthRequest.isLoopbackHost('127.0.0.1'), 'the real four-octet form still is');
    assert.true(AuthRequest.isLoopbackHost('127.13.9.200'), 'anywhere in 127.0.0.0/8');
  });

  // GUARD — passes on current head. Evidenced by mutation: unanchoring the
  // mapped-IPv6 prefix — `/^::ffff:(.+)$/` -> `/::ffff:(.+)$/` — was 96/0, and
  // it is a genuine hole rather than a tidy-up. `dead::ffff:127.0.0.1` is a
  // routable global-unicast address whose textual form is all hex and colons,
  // so it survives the bracketed-literal charset check and reaches
  // `isLoopbackIpv6`; unanchored, the suffix matches and a public address is
  // handed the loopback exemption, shipping the binding value in cleartext.
  // The exemption is for `::ffff:0:0/96` and nothing that merely ends like it.
  test('GUARD #36 only a genuinely mapped IPv6 loopback is exempt', function(assert) {
    const authRequest = buildAuthRequest();

    for (const literal of ['dead::ffff:127.0.0.1', 'dead::ffff:7f00:1', '2001:db8::ffff:127.0.0.1']) {
      assert.false(AuthRequest.isLoopbackHost(literal), `${literal} is not ::ffff:127.0.0.0/8`);
      assert.true(
        authRequest.isSecureContext(buildRequest({ host: `[${literal}]` }).req),
        `and [${literal}] gets Secure`,
      );
    }

    // The two spellings a dual-stack listener actually produces still are.
    assert.true(AuthRequest.isLoopbackHost('::ffff:127.0.0.1'), 'the dotted-quad mapped spelling is loopback');
    assert.true(AuthRequest.isLoopbackHost('::ffff:7f00:1'), 'and so is the hextet spelling');
    assert.false(authRequest.isSecureContext(buildRequest({ host: '[::ffff:127.0.0.1]:3000' }).req), 'exempt on loopback');
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

  /** Drives the callback route with a stubbed rejection and reports whether the cookie was cleared. */
  async function clearedAfter(thrown: unknown): Promise<boolean> {
    const authRequest = new AuthRequest({ ...stubOAuth, handleCallback: async () => { throw thrown; } });
    const { req, cleared } = buildRequest();
    req.query = { code: 'a-code', state: 'a-state' };

    const original = log.error;
    log.error = () => {};
    try {
      await authRequest.handlers.get['/callback/:provider'](req, {});
    } finally {
      log.error = original;
    }

    return cleared.length > 0;
  }

  // GUARD — passes on current head. Evidenced by mutation: narrowing the clear
  // condition to `rejection instanceof StateRejection && rejection.consumed`
  // was 96/0 — the whole non-`StateRejection` arm was untested. Anything that
  // is not a `StateRejection` was thrown *below* the state check, which means
  // the record was already burned and the cookie is spent; leaving it behind
  // strands a value the client will present again on a state that no longer
  // exists. The complementary mutation, clearing unconditionally, is the
  // round-two defect and is already killed — this pins the other side, so the
  // condition is fixed from both directions rather than just one.
  test('GUARD #36 the rejection clear fires exactly when the cookie was spent', async function(assert) {
    assert.true(
      await clearedAfter(new StateRejection('State token is not bound to this client', true)),
      'a rejection that burned the record clears the cookie',
    );
    assert.false(
      await clearedAfter(new StateRejection('Invalid or missing state token', false)),
      'a rejection that touched nothing leaves the client\'s cookie alone',
    );
    assert.true(
      await clearedAfter(new Error('provider exchange failed')),
      'an error from below the state check clears it — the record was already burned',
    );
    assert.true(
      await clearedAfter({ toString: () => 'a thrown non-Error' }),
      'and so does a thrown non-Error, which is also from below the state check',
    );
  });

  // GUARD — passes on current head. Evidenced by three mutations, each 96/0:
  // matching the cookie name with `startsWith` instead of `!==`; dropping the
  // `.trim()` from the value; and returning `['']` rather than `[]` when the
  // request carries no `Cookie` header at all. None of them changes today's
  // accept/reject outcome — a wrongly collected candidate still has to hash to
  // the stored digest, and an empty candidate is filtered out in `consume` —
  // which is why they survived. They are pinned because this parser's output is
  // the entire input to the binding check: `startsWith` lets any caller add
  // attacker-named cookies to the candidate set, an untrimmed value silently
  // fails to match a correctly delivered binding value, and `['']` reports a
  // candidate the client never presented.
  test('GUARD #36 the cookie parser collects this cookie, by name, trimmed', function(assert) {
    const authRequest = buildAuthRequest();

    const { req: prefixed } = buildRequest({
      cookie: `${STATE_COOKIE_NAME}_shadow=attacker; ${STATE_COOKIE_NAME}x=also-not-ours; ${STATE_COOKIE_NAME}=ours`,
    });
    assert.deepEqual(
      authRequest.readBindingCookies(prefixed),
      ['ours'],
      'a cookie whose name merely starts with ours is a different cookie',
    );

    const { req: spaced } = buildRequest({ cookie: `_ga=1;  ${STATE_COOKIE_NAME} =  the-value  ; other=2` });
    assert.deepEqual(
      authRequest.readBindingCookies(spaced),
      ['the-value'],
      'surrounding whitespace is stripped from the name and the value',
    );

    const { req: bare } = buildRequest();
    assert.deepEqual(authRequest.readBindingCookies(bare), [], 'no Cookie header means no candidates, not one empty one');

    const { req: empty } = buildRequest({ cookie: '' });
    assert.deepEqual(authRequest.readBindingCookies(empty), [], 'and neither does an empty Cookie header');
  });
});
