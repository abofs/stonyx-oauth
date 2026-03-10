import QUnit from 'qunit';
import RestServer from '@stonyx/rest-server';
import config from 'stonyx/config';
import { setupIntegrationTests } from 'stonyx/test-helpers';
import OAuth from '../../src/main.js';

const { module, test } = QUnit;
let endpoint;

async function getValidState(endpoint) {
  const loginResponse = await fetch(`${endpoint}/auth/login/mock`, { redirect: 'manual' });
  const location = loginResponse.headers.get('location');
  const url = new URL(location);
  return url.searchParams.get('state');
}

module('[Integration] OAuth', function(hooks) {
  setupIntegrationTests(hooks);

  hooks.before(function() {
    endpoint = `http://localhost:${config.restServer.port}`;
  });

  hooks.after(function() {
    RestServer.close();
  });

  test('GET /auth/login/mock redirects to provider auth URL', async function(assert) {
    const response = await fetch(`${endpoint}/auth/login/mock`, { redirect: 'manual' });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    assert.ok(location.startsWith('https://mock.provider/oauth/authorize?'));
    assert.ok(location.includes('client_id=test-client-id'));
    assert.ok(location.includes('response_type=code'));
  });

  test('GET /auth/login/nonexistent returns 404', async function(assert) {
    const response = await fetch(`${endpoint}/auth/login/nonexistent`, { redirect: 'manual' });

    assert.equal(response.status, 404);
  });

  test('GET /auth/callback/mock with valid state redirects to frontend with session', async function(assert) {
    const stateToken = await getValidState(endpoint);
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code&state=${stateToken}`, { redirect: 'manual' });

    assert.equal(response.status, 302);

    const location = response.headers.get('location');
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'http://localhost:4200/auth/callback');
    assert.ok(redirectUrl.searchParams.get('sessionId'), 'redirect includes sessionId');
    assert.ok(redirectUrl.searchParams.get('expiresAt'), 'redirect includes expiresAt');
  });

  test('GET /auth with valid session returns user', async function(assert) {
    const stateToken = await getValidState(endpoint);
    const callbackResponse = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=${stateToken}`, { redirect: 'manual' });
    const location = callbackResponse.headers.get('location');
    const sessionId = new URL(location).searchParams.get('sessionId');

    const response = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': sessionId },
    });
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.equal(data.id, 'mock-user-123');
  });

  test('GET /auth without session returns 401', async function(assert) {
    const response = await fetch(`${endpoint}/auth`);

    assert.equal(response.status, 401);
  });

  test('GET /auth with invalid session returns 401', async function(assert) {
    const response = await fetch(`${endpoint}/auth`, {
      headers: { 'session-id': 'invalid-session' },
    });

    assert.equal(response.status, 401);
  });

  test('GET /auth/logout invalidates session', async function(assert) {
    const stateToken = await getValidState(endpoint);
    const callbackResponse = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=${stateToken}`, { redirect: 'manual' });
    const location = callbackResponse.headers.get('location');
    const sessionId = new URL(location).searchParams.get('sessionId');

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

  test('GET /auth/callback/mock rejects missing state token', async function(assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location');
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.searchParams.get('error'), 'auth_failed');
  });

  test('GET /auth/callback/mock rejects invalid state token', async function(assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code&state=bogus-state`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location');
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.searchParams.get('error'), 'auth_failed');
  });

  test('GET /auth/callback/mock with error param redirects with error', async function(assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?error=access_denied`, { redirect: 'manual' });

    assert.equal(response.status, 302);
    const location = response.headers.get('location');
    const redirectUrl = new URL(location);
    assert.equal(redirectUrl.origin + redirectUrl.pathname, 'http://localhost:4200/auth/callback');
    assert.equal(redirectUrl.searchParams.get('error'), 'access_denied');
  });

  test('GET /auth/callback/mock state token cannot be reused', async function(assert) {
    const stateToken = await getValidState(endpoint);

    // First use succeeds
    const first = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=${stateToken}`, { redirect: 'manual' });
    assert.equal(first.status, 302);
    const firstLocation = new URL(first.headers.get('location'));
    assert.ok(firstLocation.searchParams.get('sessionId'), 'first use succeeds');

    // Second use fails
    const second = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=${stateToken}`, { redirect: 'manual' });
    assert.equal(second.status, 302);
    const secondLocation = new URL(second.headers.get('location'));
    assert.equal(secondLocation.searchParams.get('error'), 'auth_failed', 'reuse is rejected');
  });
});
