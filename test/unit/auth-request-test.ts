// Route-layer tests for the #36 client binding.
//
// These drive the real `AuthRequest` handlers against a real `OAuth`
// instance — no local re-implementation — so deleting the production
// behaviour they describe turns them red.
import QUnit from 'qunit';
import OAuth from '../../src/main.js';
import AuthRequest from '../../src/auth-request.js';
import OAuthFlow from '../../src/oauth-flow.js';
import TokenManager from '../../src/token-manager.js';

const { module, test } = QUnit;

const LOOPBACK_REDIRECT_URI = 'http://localhost:2666/auth/callback/mock';

function buildOAuth(redirectUri: string = LOOPBACK_REDIRECT_URI): OAuth {
  OAuth.instance = null;

  const oauth = new OAuth();
  const flow = new OAuthFlow({
    clientId: 'test-client-id',
    clientSecret: 'test-client-secret',
    redirectUri,
    scopes: ['identify'],
    authorizationUrl: 'https://mock.provider/oauth/authorize',
    tokenUrl: 'https://mock.provider/oauth/token',
    userInfoUrl: 'https://mock.provider/api/me',
  });

  oauth.providers.set('mock', { flow, tokenManager: new TokenManager(flow) });
  oauth.frontendCallbackUrl = 'http://localhost:4200/auth/callback';

  return oauth;
}

interface RecordedCookie {
  name: string;
  value: string;
  options: Record<string, unknown>;
}

function recordingResponse(recorded: RecordedCookie[]) {
  return {
    cookie(name: string, value: string, options: Record<string, unknown>) {
      recorded.push({ name, value, options });
    },
    clearCookie() {},
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
});
