import { createHash, randomBytes } from 'node:crypto';

/**
 * Lifetime of an exchange ticket.
 *
 * Sized for one redirect plus one page load, and deliberately two orders of
 * magnitude tighter than the 10-minute state TTL: the ticket is a bearer value
 * travelling in a URL, and the whole point of #45 is that a bearer value in a
 * URL must not be long-lived — in the fragment, so it reaches no server, but
 * still into browser history and readable by scripts on the landing page.
 */
export const TICKET_TTL_MS = 60 * 1000;

/** Entropy of a ticket, in bytes. */
export const TICKET_BYTES = 32;

interface TicketRecord {
  sessionId: string;
  expiresAt: number;
  createdAt: number;
}

export interface RedeemedTicket {
  sessionId: string;
  expiresAt: number;
}

/**
 * Single-use, short-lived tickets that stand in for a session id on the wire.
 *
 * The callback redirect hands the browser a ticket instead of the session id
 * (#45), in the URL *fragment*, which no user agent transmits to any server.
 * The ticket authenticates nothing — `GET /auth` reads the `session-id` header
 * and knows only about `SessionManager` — so a ticket observed in history or
 * by a script reading `location.hash` is worth something only inside the
 * sub-second window before the landing page redeems it, and nothing at all
 * afterwards.
 *
 * Known residual, stated rather than papered over: a ticket observed *within*
 * that window is redeemable by the observer, because nothing here binds a
 * ticket to the client that started the flow. Closing it means binding the way
 * #36 bound the state, and that binding has to travel on a cookie the
 * cross-origin exchange cannot carry.
 *
 * The blocker is `abofs/stonyx-rest-server#63`: `@stonyx/rest-server` calls
 * `cors({ origin, methods })` and has no `credentials` support at all. It is
 * *not* `abofs/stonyx-rest-server#45` — that issue is the response-header half
 * and is already worked around in `auth-request.ts`, which sets and clears the
 * binding cookie on a redirect by reaching through `req.res`. Closing #45
 * would not make this residual closeable. It is a reduction, not an
 * elimination.
 *
 * Like `OAuth.pendingStates`, an abandoned ticket is never collected. That is
 * a pre-existing pattern in this module, not something this store introduces,
 * and it is bounded here by a 60-second TTL rather than a 10-minute one.
 * Tracked, with both maps named, at `abofs/stonyx-oauth#43`.
 *
 * ---
 *
 * **Why this is a second store rather than a reuse of `OAuth.pendingStates`.**
 *
 * The duplication is real and is not an oversight: `pendingStates` is also a
 * single-use, TTL-bounded, consume-on-recognition map keyed by a
 * `randomBytes`-minted opaque token, with the same delete-before-TTL-check
 * ordering and the same never-collected caveat. The shared shape could be
 * extracted into one primitive, and the two constants homes (`STATE_TTL_MS`
 * and `BINDING_VALUE_BYTES` in `main.ts`, `TICKET_TTL_MS` and `TICKET_BYTES`
 * here) could then live together.
 *
 * It is deliberately not done in the change that fixes #45. Widening a
 * security fix into a refactor of the CSRF store means the #36 binding
 * mechanism — whose invariants are load-bearing and separately guarded — moves
 * in the same commit as the fix, for no security gain in either. The two also
 * do not have the same invariants: `pendingStates` is a security control fed
 * by an unauthenticated `GET`, holding a *digest* of a client secret, with a
 * 10-minute budget sized for a provider round trip; this is a delivery
 * convenience reachable only after a successfully bound callback, holding a
 * value it hands back, with a 60-second budget sized for a page load.
 * Collapsing them would couple the control to the convenience.
 *
 * The extraction is tracked at `abofs/stonyx-oauth#58`.
 */
export default class TicketStore {
  /**
   * Live tickets, keyed by the **SHA-256 of the ticket**, never by the ticket.
   *
   * Keying by the digest means the map holds no redeemable *ticket*: a ticket
   * is a client-presented secret looked up server-side, so what a reader of
   * this map gets is a digest, and a digest cannot be presented to `redeem`.
   *
   * That does not make the map safe to expose. The record *value* holds a
   * plaintext, live `sessionId` — the 24-hour bearer credential this store
   * exists to keep out of URLs — so a heap dump, a debug serialisation or an
   * accidental log of this map yields live session ids. The map is sensitive
   * on that basis and must not be dumped or logged. Whether the stored
   * `sessionId` should itself be protected is a separate question, and is not
   * settled here.
   *
   * This is the mirror image of `OAuth.pendingStates`, not the same shape:
   * there the *key* is the plaintext state token and the digest
   * (`bindingHash`) sits in the value, so that record unlocks nothing on its
   * own; here the digest is the key and the value is a live credential. What
   * the two stores share is the discipline of never keeping a
   * client-presented secret in the clear — neither the ticket nor the binding
   * value is on the heap — but they place the digest on opposite sides of the
   * entry.
   *
   * No constant-time comparison is needed and none is used: lookup is a hash
   * probe on a 256-bit high-entropy key, not a secret-dependent byte
   * comparison, so there is no early-exit timing signal to exploit. That is
   * the same reason `redeem` can stay an ordinary `Map.get`.
   */
  tickets = new Map<string, TicketRecord>();
  ttl = TICKET_TTL_MS;

  /** SHA-256 of a ticket, hex — the only form of the *ticket* this store keeps. */
  static hash(ticket: string): string {
    return createHash('sha256').update(ticket).digest('hex');
  }

  /**
   * Mints a ticket for a freshly created session.
   *
   * The ticket is independent entropy, never a transform of the session id:
   * anything derived from the credential is the credential.
   */
  issue(sessionId: string, expiresAt: number): string {
    const ticket = randomBytes(TICKET_BYTES).toString('base64url');
    this.tickets.set(TicketStore.hash(ticket), { sessionId, expiresAt, createdAt: Date.now() });
    return ticket;
  }

  /**
   * Spends a ticket, if it is live.
   *
   * Consumed on recognition, *before* the TTL check, for the same reason
   * `OAuth.handleCallback` consumes a pending state before validating its
   * binding: every ticket gets exactly one attempt whatever the outcome, so
   * this endpoint is never a repeatable oracle. Deleting after the TTL check
   * instead would leave an expired ticket in the map answering `400` forever
   * while a live one answers `200` — an unauthenticated distinguisher.
   *
   * Returns `null` for unknown, spent and expired tickets alike. The caller
   * maps all three to the same `400`; telling them apart is information the
   * holder of a ticket they did not mint has no business having.
   */
  redeem(ticket: string): RedeemedTicket | null {
    const key = ticket ? TicketStore.hash(ticket) : null;
    const record = key ? this.tickets.get(key) : undefined;
    if (!record) return null;

    this.tickets.delete(key!);

    if (Date.now() - record.createdAt > this.ttl) return null;

    return { sessionId: record.sessionId, expiresAt: record.expiresAt };
  }
}
