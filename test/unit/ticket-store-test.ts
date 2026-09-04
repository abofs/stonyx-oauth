// Unit coverage for the single-use exchange ticket store (#45).
//
// The store is the half of the fix that cannot be observed from the wire: the
// integration suite can see that a ticket is spent, but only these tests pin
// *when* it is spent relative to the TTL check, which is what stops the
// endpoint from becoming a repeatable oracle.
import QUnit from 'qunit';

const { module, todo } = QUnit;

module('[Unit] TicketStore', function() {
  todo('issue mints an opaque ticket that is not the session id', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('redeem returns the session for a live ticket', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('a ticket is single-use — the second redeem is a miss', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('a ticket older than the TTL is rejected', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('a ticket just under the TTL is still accepted', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('an expired ticket is consumed on presentation, so redeem is not an oracle', function(assert) {
    assert.ok(false, 'TODO');
  });

  todo('an unknown or empty ticket is a miss, never a throw', function(assert) {
    assert.ok(false, 'TODO');
  });
});
