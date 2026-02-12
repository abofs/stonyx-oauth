import QUnit from 'qunit';
import RestServer from '@stonyx/rest-server';
import config from 'stonyx/config';
import { setupIntegrationTests } from 'stonyx/test-helpers';

const { module, test } = QUnit;
let endpoint;

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

  test('GET /auth/callback/mock exchanges code and returns session', async function(assert) {
    const response = await fetch(`${endpoint}/auth/callback/mock?code=test-auth-code&state=abc`);
    const data = await response.json();

    assert.equal(response.status, 200);
    assert.ok(data.sessionId);
    assert.ok(data.user);
    assert.equal(data.user.id, 'mock-user-123');
    assert.equal(data.user.username, 'mockuser');
  });

  test('GET /auth with valid session returns user', async function(assert) {
    // Create a session first
    const callbackResponse = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=abc`);
    const { sessionId } = await callbackResponse.json();

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
    // Create a session
    const callbackResponse = await fetch(`${endpoint}/auth/callback/mock?code=test-code&state=abc`);
    const { sessionId } = await callbackResponse.json();

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
});
