// Unit coverage for the single-use exchange ticket store (#45).
//
// The store is the half of the fix that cannot be observed from the wire. The
// integration suite can see *that* a ticket is spent; only these tests pin
// *when* it is spent relative to the TTL check, which is what stops
// `POST /auth/session` from being a repeatable oracle against a ticket the
// caller did not mint.
//
// These drive the real `TicketStore`, not a local re-implementation of it.
import QUnit from 'qunit';
import sinon from 'sinon';
import { createHash } from 'node:crypto';
import TicketStore, { TICKET_TTL_MS } from '../../src/ticket-store.js';

const { module, test } = QUnit;

const SESSION_ID = '11111111-2222-3333-4444-555555555555';
const EXPIRES_AT = 1_800_000_000_000;

module('[Unit] TicketStore', function(hooks: NestedHooks) {
  hooks.afterEach(function() {
    sinon.restore();
  });

  test('issue mints an opaque ticket that is not the session id', function(assert) {
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    assert.equal(typeof ticket, 'string', 'a ticket is a string');
    assert.true(ticket.length >= 32, 'the ticket carries real entropy');
    assert.notEqual(ticket, SESSION_ID, 'the ticket is not the session id');
    assert.false(
      ticket.includes(SESSION_ID),
      'and does not embed it — anything derived from the credential is the credential',
    );

    // Independent entropy, not a deterministic transform: two tickets for the
    // same session must not collide, or a second login would spend the first.
    assert.notEqual(store.issue(SESSION_ID, EXPIRES_AT), ticket, 'two tickets for one session differ');
  });

  test('the store keys tickets by a digest, never by the ticket itself', function(assert) {
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);
    const [key] = [...store.tickets.keys()];

    // Same discipline as #36's `pendingStates`, which holds `bindingHash` and
    // never the binding value: whatever reaches this map must not yield a
    // redeemable credential.
    assert.notEqual(key, ticket, 'the raw ticket is not the key');
    assert.false(store.tickets.has(ticket), 'and probing by the raw ticket misses');
    assert.equal(
      key,
      createHash('sha256').update(ticket).digest('hex'),
      'the key is the SHA-256 of the ticket, computed independently of the store',
    );

    // The digest must still be the *working* key, or the store would be
    // consistent and useless.
    assert.equal(
      store.redeem(ticket)?.sessionId,
      SESSION_ID,
      'and the ticket still redeems through it',
    );
  });

  test('redeem returns the session for a live ticket', function(assert) {
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    assert.deepEqual(
      store.redeem(ticket),
      { sessionId: SESSION_ID, expiresAt: EXPIRES_AT },
      'the ticket resolves to the session it stands for, and to its expiry',
    );
  });

  test('a ticket is single-use — the second redeem is a miss', function(assert) {
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    assert.ok(store.redeem(ticket), 'first redemption succeeds');
    assert.equal(store.redeem(ticket), null, 'second redemption is rejected');
    assert.equal(store.tickets.size, 0, 'and the spent ticket is gone from the map');
  });

  test('a ticket older than the TTL is rejected', function(assert) {
    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    clock.tick(TICKET_TTL_MS + 1_000);

    assert.equal(store.redeem(ticket), null, 'an aged ticket buys nothing');
  });

  test('a ticket just under the TTL is still accepted', function(assert) {
    // Both bounds are required. A store with a zero-second TTL passes the
    // expiry test above and breaks every real login; only this assertion
    // separates the two.
    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    clock.tick(TICKET_TTL_MS - 1_000);

    assert.deepEqual(
      store.redeem(ticket),
      { sessionId: SESSION_ID, expiresAt: EXPIRES_AT },
      'a ticket inside its window still redeems',
    );
  });

  test('an expired ticket is consumed on presentation, so redeem is not an oracle', function(assert) {
    // The ordering this pins: consume on recognition, *then* check the TTL.
    // Delete-after-the-TTL-check leaves an expired ticket in the map answering
    // forever, which is an unauthenticated distinguisher between a ticket that
    // once existed and one that never did.
    const clock = sinon.useFakeTimers({ now: Date.now(), toFake: ['Date'] });
    const store = new TicketStore();
    const ticket = store.issue(SESSION_ID, EXPIRES_AT);

    clock.tick(TICKET_TTL_MS + 1_000);
    store.redeem(ticket);

    // Probed by digest, not by the raw ticket: the map is keyed by the
    // SHA-256, so `has(ticket)` would be false however the store behaved
    // and would assert nothing at all.
    assert.false(
      store.tickets.has(TicketStore.hash(ticket)),
      'the expired ticket is removed from the map',
    );
    assert.equal(store.tickets.size, 0, 'and nothing else is left behind');
  });

  test('an unknown or empty ticket is a miss, never a throw', function(assert) {
    const store = new TicketStore();
    store.issue(SESSION_ID, EXPIRES_AT);

    // Every one of these is a value an unauthenticated caller can post.
    assert.equal(store.redeem('never-issued'), null, 'an unknown ticket is rejected');
    assert.equal(store.redeem(''), null, 'an empty ticket is rejected');
    assert.equal(store.redeem(SESSION_ID), null, 'the session id itself is not a ticket');
    assert.equal(store.tickets.size, 1, 'and none of them consumed the live ticket');
  });
});
