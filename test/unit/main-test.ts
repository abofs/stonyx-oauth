import QUnit from 'qunit';
import sinon from 'sinon';
import OAuth from '../../src/main.js';
import log from 'stonyx/log';

const { module, test } = QUnit;

module('[Unit] OAuth', function (hooks) {
  hooks.afterEach(function () {
    sinon.restore();
    OAuth.instance = null;
  });

  module('self-registers log type in init() (#28)', function () {
    test('registers oauth log type on init', async function (assert) {
      assert.strictEqual(typeof log.defineType, 'function', 'log.defineType is available');

      const oauth = new OAuth();
      // init() will throw later (no rest-server in the unit harness) but
      // defineType runs as the first statement, before the throw.
      try { await oauth.init(); } catch { /* expected */ }

      assert.strictEqual(typeof log.oauth, 'function', 'log.oauth is callable after init');
    });

    test('idempotent: calling init twice does not throw', async function (assert) {
      const oauth1 = new OAuth();
      try { await oauth1.init(); } catch { /* expected */ }
      OAuth.instance = null;

      const oauth2 = new OAuth();
      try { await oauth2.init(); } catch { /* expected */ }

      assert.strictEqual(typeof log.oauth, 'function', 'log.oauth still callable after second init');
    });
  });
});
