import QUnit from 'qunit';
import RestServer from '@stonyx/rest-server';
import config from 'stonyx/config';
import { setupIntegrationTests } from 'stonyx/test-helpers';
import sinon from 'sinon';
// The built entry the stonyx module loader instantiated. `../../src/main.js`
// is a second, never-initialized module instance and reports nothing.
import OAuth from '@stonyx/oauth';
import { TICKET_TTL_MS } from '../../src/ticket-store.js';

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

/**
 * The fragment key the callback redirect is allowed to carry, and the route
 * that redeems it. Pinned here as a wire contract rather than imported from
 * `src/`, so a rename shows up as a deliberate breaking change (#45), exactly
 * as `STATE_COOKIE_NAME` does for #36.
 */
const TICKET_PARAM = 'ticket';
const EXCHANGE_ROUTE = '/auth/session';

/**
 * Every parameter a redirect carries, from the query *and* the fragment.
 *
 * The ticket rides in the fragment so it never reaches a server. The guards
 * below must not narrow along with it: a credential reintroduced in *either*
 * half has to red. Reading both keeps them anchored to "nothing in this URL
 * authenticates" rather than to whichever half the ticket currently occupies.
 */
function redirectParams(url: URL): Array<[string, string]> {
  return [...url.searchParams, ...new URLSearchParams(url.hash.slice(1))];
}

/**
 * The exchange ticket a redirect carries, wherever it carries it.
 *
 * Deliberately reads the query as well as the fragment: the positive
 * assertions must not stop finding a ticket that regressed back into the
 * query, and the `notOk` guards must not go green for one that appeared there.
 */
function ticketFrom(url: URL): string | null {
  return new URLSearchParams(url.hash.slice(1)).get(TICKET_PARAM)
    ?? url.searchParams.get(TICKET_PARAM);
}

/** Redeems a ticket the way the consumer's landing page does. */
function exchange(endpoint: string, ticket: string): Promise<Response> {
  return fetch(`${endpoint}${EXCHANGE_ROUTE}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ticket }),
  });
}

interface CompletedLogin {
  /** The full redirect the browser is sent to, parsed. */
  redirect: URL;
  /** The exchange ticket it carries. */
  ticket: string;
}

/** Drives a login all the way to the frontend redirect, keeping the cookie jar. */
async function completeLogin(endpoint: string): Promise<CompletedLogin> {
  const { state, cookie } = await login(endpoint);
  const response = await fetch(callbackUrl(endpoint, state, 'test-code'), {
    redirect: 'manual',
    headers: { cookie },
  });
  const redirect = new URL(response.headers.get('location')!);

  return { redirect, ticket: ticketFrom(redirect)! };
}

/** Completes a login and redeems its ticket, returning the session id. */
async function loginAndExchange(endpoint: string): Promise<string> {
  const { ticket } = await completeLogin(endpoint);
  const { sessionId } = await (await exchange(endpoint, ticket)).json();

  return sessionId;
}

/**
 * Asserts that nothing in a URL — query or fragment — is a credential.
 *
 * This is the half of #45 that stops a rename from satisfying it vacuously:
 * it does not look for a key called `sessionId`, it feeds *every* value the
 * URL carries to the authenticating surface and requires it to refuse.
 * Renaming `sessionId` to `token`, or moving it from the query into the
 * fragment, would pass a key-absence check and fail this one.
 */
async function assertNoCredentialInRedirect(assert: Assert, url: URL, label: string): Promise<void> {
  const entries = redirectParams(url);
  assert.true(entries.length > 0, `${label}: the redirect carries something to check`);

  for (const [key, value] of entries) {
    const authenticated = await fetch(`${endpoint}/auth`, { headers: { 'session-id': value } });
    assert.equal(authenticated.status, 401, `${label}: ${key}= does not authenticate at GET /auth`);
  }
}

/**
 * Asserts that nothing in a *rejected* flow's redirect can be exchanged.
 *
 * Only ever called on a failure path, where the redirect is supposed to carry
 * no redeemable value at all — on the success path the ticket is redeemable by
 * design and calling this would spend it.
 *
 * This is what makes the re-anchored #36 guards rename-proof: an
 * implementation that leaked a redeemable value under some name other than
 * `ticket` would slip past a key-absence check and is caught here.
 */
async function assertNothingRedeemable(assert: Assert, url: URL, label: string): Promise<void> {
  const entries = redirectParams(url);
  assert.true(entries.length > 0, `${label}: the redirect carries something to check`);

  for (const [key, value] of entries) {
    const exchanged = await exchange(endpoint, value);
    assert.equal(exchanged.status, 400, `${label}: ${key}= is not redeemable at POST /auth/session`);
  }
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
    assert.ok(ticketFrom(redirectUrl), 'redirect includes an exchange ticket');
    assert.ok(
      new URLSearchParams(redirectUrl.hash.slice(1)).get('expiresAt'),
      'redirect includes expiresAt',
    );
    assert.equal(redirectUrl.search, '', 'and the query carries nothing at all');
  });

  test('the exchange 200 is Cache-Control: no-store — its body is the bearer credential', async function(assert: Assert) {
    const { ticket } = await completeLogin(endpoint);
    const response = await exchange(endpoint, ticket);

    assert.equal(response.status, 200, 'the ticket redeemed');
    assert.equal(
      response.headers.get('cache-control'),
      'no-store',
      'the response carrying the session id is not storable by any intermediary',
    );
  });

  test('GET /auth with valid session returns user', async function(assert: Assert) {
    const sessionId = await loginAndExchange(endpoint);

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
    const sessionId = await loginAndExchange(endpoint);

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
    assert.ok(ticketFrom(firstLocation), 'first use succeeds');

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
        assert.equal(sessions.size, before, `${label}: no session minted server-side`);

        // Re-anchored for #45. `notOk(get('sessionId'))` was this guard's wire
        // half until the session id stopped appearing in the query at all, at
        // which point it became permanently, silently green — still named for
        // what it used to prove, unable to fail. The replacement asserts the
        // same invariant against the shape the redirect actually has now, and
        // reds if a ticket is ever handed to an unbound caller.
        assert.notOk(
          ticketFrom(redirect),
          `${label}: no exchange ticket handed to the caller`,
        );
        await assertNoCredentialInRedirect(assert, redirect, label);
        await assertNothingRedeemable(assert, redirect, label);
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
    assert.equal(sessions.size, before, 'no session minted server-side');

    // Re-anchored for #45 — see the note on the AC2 guard above.
    assert.notOk(ticketFrom(redirect), 'no exchange ticket handed to the caller');
    await assertNoCredentialInRedirect(assert, redirect, 'no binding cookie');
    await assertNothingRedeemable(assert, redirect, 'no binding cookie');
  });

  test('AC7: the binding cookie is read by name from anywhere in the Cookie header, and only under its own name', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;

    // The whole point of `readBindingCookies` is that it parses the header
    // rather than reading position 0, and the whole point of
    // `anyCandidateMatches` is that it scans every value carrying the name.
    // Both are reasoned about at length in the source and covered at the unit
    // layer, but the ordering they defend against only exists on the wire — a
    // browser that already holds any other cookie for this host sends
    // `Cookie: session=x; oauth_state=y`. Nothing else in the suite ever puts
    // `oauth_state` anywhere but first.

    const trailing = await login(endpoint);
    const trailingValue = parseSetCookie(trailing.setCookie[0] ?? '').value;
    const before = sessions.size;

    const accepted = await fetch(callbackUrl(endpoint, trailing.state), {
      redirect: 'manual',
      headers: { cookie: `session=unrelated; ${STATE_COOKIE_NAME}=${trailingValue}` },
    });

    assert.ok(
      ticketFrom(new URL(accepted.headers.get('location')!)),
      'a browser holding another cookie first still completes the login',
    );
    assert.equal(sessions.size, before + 1, 'and the session is minted server-side');

    // RFC 6265 section 4.2.1 allows optional whitespace around the delimiter,
    // so both halves of the pair are trimmed, not just the name.
    const padded = await login(endpoint);
    const paddedValue = parseSetCookie(padded.setCookie[0] ?? '').value;

    const acceptedPadded = await fetch(callbackUrl(endpoint, padded.state), {
      redirect: 'manual',
      headers: { cookie: `a=1; b=2 ; ${STATE_COOKIE_NAME} = ${paddedValue}` },
    });

    assert.ok(
      ticketFrom(new URL(acceptedPadded.headers.get('location')!)),
      'a deeply nested, whitespace-padded pair is still read',
    );

    // The negative half: presenting the correct binding value under some other
    // cookie name must not authenticate. Without this, dropping the name check
    // entirely — accepting every value in the header as a candidate — passes.
    const decoyed = await login(endpoint);
    const decoyedValue = parseSetCookie(decoyed.setCookie[0] ?? '').value;
    const beforeDecoy = sessions.size;

    const rejected = await fetch(callbackUrl(endpoint, decoyed.state), {
      redirect: 'manual',
      headers: { cookie: `session=${decoyedValue}; ${STATE_COOKIE_NAME}=not-the-binding-value` },
    });
    const redirect = new URL(rejected.headers.get('location')!);

    assert.equal(
      redirect.searchParams.get('error'),
      'auth_failed',
      'the binding value under a different cookie name is not a candidate',
    );
    // Re-anchored for #45, and given the same two rename-proof helpers its AC2
    // and AC4 siblings got. It had only the key check, which is a key-*absence*
    // check: measured out-of-sample, a leak of a redeemable value under the key
    // `token` reds AC2 and AC4 and reports `ok` here. The key check stays as a
    // readable statement of the wire shape; the two below are what make it fail
    // for a leak under any key, in the query or the fragment.
    assert.notOk(ticketFrom(redirect), 'no exchange ticket handed to the caller');
    await assertNoCredentialInRedirect(assert, redirect, 'the binding value under a decoy name');
    await assertNothingRedeemable(assert, redirect, 'the binding value under a decoy name');
    assert.equal(sessions.size, beforeDecoy, 'no session minted server-side');
  });

  test('AC6 (GUARD — passes with the fix reverted; not evidence of the fix): the same-client flow still works', async function(assert: Assert) {
    const { state, cookie } = await login(endpoint);

    const response = await fetch(callbackUrl(endpoint, state), {
      redirect: 'manual',
      headers: cookie ? { cookie } : {},
    });
    const ticket = ticketFrom(new URL(response.headers.get('location')!));
    assert.ok(ticket, 'the client that started the flow receives an exchange ticket');

    const { sessionId } = await (await exchange(endpoint, ticket!)).json();
    assert.ok(sessionId, 'and the ticket redeems for a session');

    const authenticated = await fetch(`${endpoint}/auth`, { headers: { 'session-id': sessionId } });
    const user = await authenticated.json();

    assert.equal(authenticated.status, 200, 'the issued session validates at GET /auth');
    assert.equal(user.id, 'mock-user-123', 'and resolves to the authenticated user');
  });

  // ===========================================================================
  // #45 — the session id must not be delivered in the redirect URL.
  //
  // Same reason as the #36 block above: `hooks.after` closes the server, so
  // these have to live inside this module rather than in a file that sorts
  // after it.
  // ===========================================================================

  test('AC1: the success redirect carries no session id, and no value in it authenticates', async function(assert: Assert) {
    const { redirect } = await completeLogin(endpoint);

    assert.equal(
      redirect.searchParams.get('sessionId')
        ?? new URLSearchParams(redirect.hash.slice(1)).get('sessionId'),
      null,
      'the session id is not handed over in the URL, in either the query or the fragment',
    );

    // The half that stops a rename from satisfying this vacuously: every value
    // the URL carries is fed to the surface that authenticates, and every one
    // of them must be refused. `?token=<the session id>` passes the assertion
    // above and fails this one.
    await assertNoCredentialInRedirect(assert, redirect, 'the success redirect');
  });

  test('AC2: the redirect carries a ticket that is not the session id and does not authenticate', async function(assert: Assert) {
    const { ticket } = await completeLogin(endpoint);

    assert.equal(typeof ticket, 'string', 'the redirect carries a ticket');
    assert.true(ticket.length >= 32, 'and it carries real entropy');

    const asCredential = await fetch(`${endpoint}/auth`, { headers: { 'session-id': ticket } });
    assert.equal(asCredential.status, 401, 'the ticket is not accepted as a session-id header');

    const { sessionId } = await (await exchange(endpoint, ticket)).json();
    assert.notEqual(ticket, sessionId, 'and it is not the session id it redeems for');
  });

  test('AC3: the exchange ticket is single-use', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;
    const before = sessions.size;

    const { ticket } = await completeLogin(endpoint);
    assert.equal(sessions.size, before + 1, 'the callback mints the session; the exchange only hands over its id');

    const first = await exchange(endpoint, ticket);
    const body = await first.json();
    assert.equal(first.status, 200, 'the first redemption succeeds');
    assert.ok(body.sessionId, 'and returns a session id');
    assert.ok(body.expiresAt, 'and the expiry that goes with it');

    const second = await exchange(endpoint, ticket);
    assert.equal(second.status, 400, 'the second redemption is rejected');

    // The assertion a bare status check would miss: a store that deletes the
    // ticket only *after* writing the response, or one that mints a fresh
    // session per redemption, still answers 400 on the second call while
    // having left a second live credential behind.
    assert.equal(sessions.size, before + 1, 'exactly one session exists across both redemptions');
  });

  test('AC4: the exchange ticket expires, and is still live just under the TTL', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;

    // Two tickets minted on the real clock, then aged together. Only `Date` is
    // faked: faking the timer wheel as well stalls the in-process HTTP server
    // this suite talks to over a real socket.
    const live = await completeLogin(endpoint);
    const stale = await completeLogin(endpoint);

    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });

    try {
      clock.tick(TICKET_TTL_MS - 1_000);

      const beforeLive = sessions.size;
      const accepted = await exchange(endpoint, live.ticket);
      assert.equal(accepted.status, 200, 'a ticket one second inside its window still redeems');
      assert.ok((await accepted.json()).sessionId, 'and hands over the session id');
      assert.equal(sessions.size, beforeLive, 'redeeming mints nothing new');

      // Both bounds are asserted deliberately. A store with a zero-second TTL
      // passes the expiry half below on its own and breaks every real login;
      // only the assertion above separates the two.
      clock.tick(2_000);

      const beforeStale = sessions.size;
      const rejected = await exchange(endpoint, stale.ticket);
      assert.equal(rejected.status, 400, 'a ticket past the 60s TTL is rejected');
      assert.equal(sessions.size, beforeStale, 'and no session is minted for it');
    } finally {
      clock.restore();
    }
  });

  test('AC5: POST /auth/session is reachable cross-origin as a browser would call it', async function(assert: Assert) {
    // The consumer's landing page is served from another origin (4200) and
    // talks to this server (47301 in production, the test port here), so the
    // exchange is a preflighted cross-origin request. If the preflight fails
    // the browser never sends the POST and every login breaks — with the
    // session id no longer in the URL, there is no fallback.
    const preflight = await fetch(`${endpoint}${EXCHANGE_ROUTE}`, {
      method: 'OPTIONS',
      headers: {
        origin: 'http://localhost:4200',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type',
      },
    });

    // Status and `allow-origin` alone prove nothing here, and that was measured:
    // `cors@2.8.6` (lib/index.js:163-181) terminates *every* `OPTIONS` with
    // `res.statusCode = 204; res.end()` before routing, without consulting the
    // requested method and without checking the route exists — `OPTIONS
    // /auth/does-not-exist` also answers 204 with `allow-origin: *`. So those
    // two assertions cannot fail for the defect this test names.
    //
    // `access-control-allow-methods` is the header the browser actually gates
    // on, and it is the one this module now depends on: before #45 this module
    // served only `GET`, so a deployment pinned to `REST_CORS_METHODS=GET` lost
    // nothing. After #45 that same deployment has no working login at all.
    assert.equal(preflight.status, 204, 'the preflight is answered');
    assert.ok(
      preflight.headers.get('access-control-allow-origin'),
      'and allows the requesting origin',
    );
    assert.true(
      (preflight.headers.get('access-control-allow-methods') ?? '').includes('POST'),
      'and advertises POST, without which the browser never sends the exchange',
    );

    const { ticket } = await completeLogin(endpoint);
    const response = await fetch(`${endpoint}${EXCHANGE_ROUTE}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: 'http://localhost:4200' },
      body: JSON.stringify({ ticket }),
    });

    assert.equal(response.status, 200, 'and the cross-origin POST itself succeeds');
    assert.ok((await response.json()).sessionId, 'with the session id in the body');
  });

  test('AC5: the exchange rejects a malformed or absent body without minting anything', async function(assert: Assert) {
    const { sessions } = OAuth.instance!.sessionManager;
    const before = sessions.size;

    // Every one of these is a request an unauthenticated caller can make, and
    // the form-encoded case is the measured gotcha: `@stonyx/rest-server`
    // installs `express.json()` only, so a form body arrives unparsed.
    const cases: Array<[string, RequestInit]> = [
      ['no body at all', { method: 'POST' }],
      ['an empty JSON object', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' }],
      ['a non-string ticket', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"ticket":{}}' }],
      ['an empty ticket', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"ticket":""}' }],
      ['an unissued ticket', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"ticket":"never-issued"}' }],
      ['a form-encoded body', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'ticket=never-issued',
      }],
    ];

    for (const [label, init] of cases) {
      const response = await fetch(`${endpoint}${EXCHANGE_ROUTE}`, init);
      assert.equal(response.status, 400, `${label}: rejected`);
    }

    assert.equal(sessions.size, before, 'and none of them minted a session');
  });

  test('AC7 (GUARD — passes with the fix reverted; not evidence of the fix): login -> callback -> exchange -> /auth -> logout', async function(assert: Assert) {
    const { ticket } = await completeLogin(endpoint);

    const exchanged = await exchange(endpoint, ticket);
    assert.equal(exchanged.status, 200, 'the ticket redeems');
    const { sessionId } = await exchanged.json();

    const authenticated = await fetch(`${endpoint}/auth`, { headers: { 'session-id': sessionId } });
    assert.equal(authenticated.status, 200, 'the exchanged session validates at GET /auth');
    assert.equal((await authenticated.json()).id, 'mock-user-123', 'and resolves to the authenticated user');

    const loggedOut = await fetch(`${endpoint}/auth/logout`, { headers: { 'session-id': sessionId } });
    assert.equal(loggedOut.status, 200, 'logout accepts the exchanged session');

    const afterLogout = await fetch(`${endpoint}/auth`, { headers: { 'session-id': sessionId } });
    assert.equal(afterLogout.status, 401, 'and it is dead afterwards');
  });
});
