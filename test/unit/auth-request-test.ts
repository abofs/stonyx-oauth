// Route-layer tests for the #36 client binding.
//
// These drive the real `AuthRequest` handlers against a real `OAuth`
// instance — no local re-implementation — so deleting the production
// behaviour they describe turns them red.
import QUnit from 'qunit';
import OAuth from '../../src/main.js';
import AuthRequest from '../../src/auth-request.js';
import SessionManager from '../../src/session-manager.js';
import TokenManager from '../../src/token-manager.js';
import MockProvider from '../sample/providers/mock.js';
import type { CookieOptions } from '../../src/auth-request.js';

const { module, test } = QUnit;

const LOOPBACK_REDIRECT_URI = 'http://localhost:2666/auth/callback/mock';

/**
 * The cookie name as it appears on the wire. Pinned here rather than imported
 * so a rename shows up as a deliberate breaking change (#36).
 */
const STATE_COOKIE_NAME = 'oauth_state';

/** The fragment key the callback redirect carries after #45. Pinned for the same reason. */
const TICKET_PARAM = 'ticket';

/**
 * The session id a redirect stands for, reached through the exchange rather
 * than read off the URL.
 *
 * Asserting on the ticket alone would pass against a redirect carrying a
 * random string that redeems for nothing; this resolves it the way the
 * consumer does.
 *
 * Reads the query as well as the fragment so that a ticket regressing back
 * into the query is still found — the guards on this value must not go green
 * because the credential moved rather than because it left.
 */
function exchangedSessionId(oauth: OAuth, redirect: string): string | undefined {
  const url = new URL(redirect);
  const ticket = new URLSearchParams(url.hash.slice(1)).get(TICKET_PARAM)
    ?? url.searchParams.get(TICKET_PARAM);
  if (!ticket) return undefined;

  return oauth.redeemExchangeTicket(ticket)?.sessionId;
}

function buildOAuth(redirectUri: string = LOOPBACK_REDIRECT_URI): OAuth {
  OAuth.instance = null;

  const oauth = new OAuth();
  const flow = new MockProvider({
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri,
    scopes: ['identify'],
  });

  oauth.providers.set('mock', { flow, tokenManager: new TokenManager(flow) });
  oauth.sessionManager = new SessionManager(3600);
  oauth.frontendCallbackUrl = 'http://localhost:4200/auth/callback';

  return oauth;
}

interface RecordedCookie {
  name: string;
  value: string;
  options: CookieOptions;
}

interface ClearedCookie {
  name: string;
  options: Omit<CookieOptions, 'maxAge'>;
}

/**
 * A stand-in for the express response, recording both directions.
 *
 * `clearCookie` records rather than no-ops: the placement of the clear is a
 * security decision (see `AuthRequest`'s callback handler) and a no-op stub
 * gives it zero test weight in either direction.
 */
function recordingResponse(recorded: RecordedCookie[], cleared: ClearedCookie[] = []) {
  return {
    cookie(name: string, value: string, options: CookieOptions) {
      recorded.push({ name, value, options });
    },
    clearCookie(name: string, options: Omit<CookieOptions, 'maxAge'>) {
      cleared.push({ name, options });
    },
  };
}

interface StartedLogin {
  stateToken: string;
  bindingValue: string;
}

/** Drives the real login route and returns what the client walks away with. */
async function startLogin(authRequest: AuthRequest, res: ReturnType<typeof recordingResponse>): Promise<StartedLogin> {
  const recorded: RecordedCookie[] = [];
  const capturing = {
    cookie: (name: string, value: string, options: CookieOptions) => {
      recorded.push({ name, value, options });
      res.cookie(name, value, options);
    },
    clearCookie: (name: string, options: Omit<CookieOptions, 'maxAge'>) => res.clearCookie(name, options),
  };
  const routeState: { redirect?: string } = {};

  await authRequest.handlers.get['/login/:provider'](
    { params: { provider: 'mock' }, headers: {}, query: {}, res: capturing },
    routeState,
  );

  return {
    stateToken: new URL(routeState.redirect!).searchParams.get('state')!,
    bindingValue: recorded[0]!.value,
  };
}

module('[Unit] AuthRequest binding cookie', function(hooks) {
  hooks.afterEach(function() {
    OAuth.instance = null;
  });

  test('AC5: login fails closed and issues no state when the response cannot set a cookie', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);
    const routeState: { redirect?: string } = {};
    // No `res` — this is what a rest-server release that stops populating
    // `req.res` looks like from here. The pinned exact devDependency means
    // CI cannot catch that regression, so the route must contain it.
    const req = { params: { provider: 'mock' }, headers: {}, query: {} };

    const status = await authRequest.handlers.get['/login/:provider'](req, routeState);

    assert.equal(status, 500, 'login is refused with a non-2xx/3xx status');
    assert.equal(routeState.redirect, undefined, 'no redirect to the provider is issued');
    assert.equal(oauth.pendingStates.size, 0, 'no state is issued that the client cannot be bound to');
  });

  test('CONTROL: login succeeds and issues exactly one state when the cookie can be set', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);
    const recorded: RecordedCookie[] = [];
    const routeState: { redirect?: string } = {};
    const req = { params: { provider: 'mock' }, headers: {}, query: {}, res: recordingResponse(recorded) };

    const status = await authRequest.handlers.get['/login/:provider'](req, routeState);

    assert.equal(status, undefined, 'no error status');
    assert.ok(routeState.redirect?.startsWith('https://mock.provider/oauth/authorize?'), 'redirects to the provider');
    assert.equal(oauth.pendingStates.size, 1, 'exactly one pending state is issued');
    assert.equal(recorded.length, 1, 'exactly one cookie is set');
  });

  test('the binding cookie is Secure when the configured redirect URI is https', async function(assert) {
    const oauth = buildOAuth('https://app.example.com/auth/callback/mock');
    const authRequest = new AuthRequest(oauth);
    const recorded: RecordedCookie[] = [];
    const routeState: { redirect?: string } = {};
    const req = { params: { provider: 'mock' }, headers: {}, query: {}, res: recordingResponse(recorded) };

    await authRequest.handlers.get['/login/:provider'](req, routeState);

    assert.equal(recorded.length, 1, 'a cookie was set');
    assert.true(recorded[0]?.options.secure === true, 'Secure is derived from the redirect URI scheme, not hardcoded');
  });

  test('the binding cookie is not Secure when the configured redirect URI is plaintext loopback', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);
    const recorded: RecordedCookie[] = [];
    const routeState: { redirect?: string } = {};
    const req = { params: { provider: 'mock' }, headers: {}, query: {}, res: recordingResponse(recorded) };

    await authRequest.handlers.get['/login/:provider'](req, routeState);

    assert.equal(recorded.length, 1, 'a cookie was set');
    assert.false(recorded[0]?.options.secure === true, 'plaintext local development is not broken by a hardcoded Secure');
  });

  test('an absent or unparseable redirect URI fails secure', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);

    assert.true(
      authRequest.isSecureContext('not-a-configured-provider'),
      'an absent redirect URI yields Secure, not a cookie shipped in the clear',
    );

    oauth.providers.get('mock')!.flow.redirectUri = 'not://a valid url';
    assert.true(
      authRequest.isSecureContext('mock'),
      'an unparseable redirect URI yields Secure',
    );

    // Through the route, so the fail-open reaches the wire and not just the predicate.
    const misconfigured = buildOAuth('%%% not a url %%%');
    const recorded: RecordedCookie[] = [];
    const routeState: { redirect?: string } = {};

    await new AuthRequest(misconfigured).handlers.get['/login/:provider'](
      { params: { provider: 'mock' }, headers: {}, query: {}, res: recordingResponse(recorded) },
      routeState,
    );

    assert.equal(recorded.length, 1, 'a cookie was set');
    assert.true(
      recorded[0]?.options.secure === true,
      'a provider misconfigured with an unparseable redirect URI does not silently ship the binding cookie over plaintext',
    );
  });

  // ---------------------------------------------------------------------------
  // Where the binding cookie is cleared is a security decision, not a detail.
  // Both directions are asserted: exactly one clear on the success path, and
  // none on any failure path.
  // ---------------------------------------------------------------------------

  test('a successful callback clears the binding cookie, with the attributes it was set with', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);
    const recorded: RecordedCookie[] = [];
    const cleared: ClearedCookie[] = [];
    const res = recordingResponse(recorded, cleared);

    const { stateToken, bindingValue } = await startLogin(authRequest, res);
    const routeState: { redirect?: string } = {};

    await authRequest.handlers.get['/callback/:provider']({
      params: { provider: 'mock' },
      headers: { cookie: `${STATE_COOKIE_NAME}=${bindingValue}` },
      query: { code: 'test-code', state: stateToken },
      res,
    }, routeState);

    const successRedirect = new URL(routeState.redirect!);
    assert.equal(
      successRedirect.searchParams.get('sessionId')
        ?? new URLSearchParams(successRedirect.hash.slice(1)).get('sessionId'),
      null,
      'the session id is not written into the redirect URL, query or fragment (#45)',
    );
    assert.equal(
      successRedirect.search,
      '',
      'and the success redirect carries no query at all — the ticket rides in the fragment',
    );
    assert.ok(
      exchangedSessionId(oauth, routeState.redirect!),
      'the same-client callback minted a session, reachable through the exchange ticket',
    );
    assert.equal(cleared.length, 1, 'the spent binding cookie is cleared exactly once');
    assert.equal(cleared[0]?.name, STATE_COOKIE_NAME, 'and it is the binding cookie that is cleared');
    assert.deepEqual(
      cleared[0]?.options,
      { httpOnly: true, sameSite: 'lax', path: '/', secure: false },
      'cleared with the attributes it was set with — a mismatched Path or SameSite leaves the cookie in the jar',
    );
  });

  test('a failing callback never clears the binding cookie, so a bare ?code is not a denial of login', async function(assert) {
    const oauth = buildOAuth();
    const authRequest = new AuthRequest(oauth);
    const recorded: RecordedCookie[] = [];
    const cleared: ClearedCookie[] = [];
    const res = recordingResponse(recorded, cleared);

    // A victim sitting on the provider's consent screen: state pending, cookie held.
    const victim = await startLogin(authRequest, res);

    // `code` is attacker-supplied and unvalidated, so a bare `?code=1` — with
    // no knowledge of anyone's state — reaches the handler. Delivered to the
    // victim's browser it arrives carrying the victim's own cookie. Clearing
    // on this path deletes their binding while leaving their pending state
    // intact, so nothing is detectable server-side and their real callback
    // then fails.
    const forged: { redirect?: string } = {};
    await authRequest.handlers.get['/callback/:provider']({
      params: { provider: 'mock' },
      headers: { cookie: `${STATE_COOKIE_NAME}=${victim.bindingValue}` },
      query: { code: '1' },
      res,
    }, forged);

    assert.equal(
      new URL(forged.redirect!).searchParams.get('error'),
      'auth_failed',
      'the forged callback is rejected',
    );
    assert.equal(cleared.length, 0, "the victim's binding cookie is not cleared");
    assert.true(oauth.pendingStates.has(victim.stateToken), "and the victim's pending state is untouched");

    // The whole point: the victim can still finish the login they started.
    const real: { redirect?: string } = {};
    await authRequest.handlers.get['/callback/:provider']({
      params: { provider: 'mock' },
      headers: { cookie: `${STATE_COOKIE_NAME}=${victim.bindingValue}` },
      query: { code: 'test-code', state: victim.stateToken },
      res,
    }, real);

    assert.ok(
      exchangedSessionId(oauth, real.redirect!),
      'the victim completes their own login afterwards',
    );
    assert.equal(cleared.length, 1, 'and that success is the only thing that ever clears the cookie');
  });
});
