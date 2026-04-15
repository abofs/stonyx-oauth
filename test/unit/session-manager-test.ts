import QUnit from 'qunit';
import SessionManager from '../../src/session-manager.js';

const { module, test } = QUnit;

const mockUser = { id: '1', username: 'testuser' };
const mockTokens = { accessToken: 'abc', expiresAt: Date.now() + 60000 };

module('[Unit] SessionManager', function() {
  module('create', function() {
    test('generates a unique session ID and stores session', function(assert) {
      const manager = new SessionManager(3600);
      const session1 = manager.create(mockUser, mockTokens);
      const session2 = manager.create(mockUser, mockTokens);

      assert.ok(session1.sessionId);
      assert.ok(session2.sessionId);
      assert.notEqual(session1.sessionId, session2.sessionId);
      assert.deepEqual(session1.user, mockUser);
    });

    test('sets expiresAt based on duration', function(assert) {
      const manager = new SessionManager(3600);
      const before = Date.now();
      const session = manager.create(mockUser, mockTokens);

      assert.ok(session.expiresAt >= before + 3600 * 1000);
    });
  });

  module('get', function() {
    test('returns session data for a valid session ID', function(assert) {
      const manager = new SessionManager(3600);
      const { sessionId } = manager.create(mockUser, mockTokens);
      const session = manager.get(sessionId);

      assert.ok(session);
      assert.deepEqual(session!.user, mockUser);
    });

    test('returns null for unknown session ID', function(assert) {
      const manager = new SessionManager(3600);
      const session = manager.get('nonexistent');

      assert.equal(session, null);
    });
  });

  module('validate', function() {
    test('returns user for a valid, non-expired session', function(assert) {
      const manager = new SessionManager(3600);
      const { sessionId } = manager.create(mockUser, mockTokens);
      const user = manager.validate(sessionId);

      assert.deepEqual(user, mockUser);
    });

    test('returns null for an expired session and cleans it up', function(assert) {
      const manager = new SessionManager(0);
      const { sessionId } = manager.create(mockUser, mockTokens);
      const user = manager.validate(sessionId);

      assert.equal(user, null);
      assert.equal(manager.get(sessionId), null);
    });

    test('returns null for nonexistent session', function(assert) {
      const manager = new SessionManager(3600);
      const user = manager.validate('missing');

      assert.equal(user, null);
    });
  });

  module('destroy', function() {
    test('removes the session', function(assert) {
      const manager = new SessionManager(3600);
      const { sessionId } = manager.create(mockUser, mockTokens);

      manager.destroy(sessionId);

      assert.equal(manager.get(sessionId), null);
    });
  });
});
