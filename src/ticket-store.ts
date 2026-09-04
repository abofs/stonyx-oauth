import { randomBytes } from 'node:crypto';

/**
 * Lifetime of an exchange ticket.
 *
 * Sized for one redirect plus one page load, and deliberately two orders of
 * magnitude tighter than the 10-minute state TTL: the ticket is a bearer value
 * travelling in a URL, and the whole point of #45 is that a bearer value in a
 * URL must not be long-lived.
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
 * (#45). The ticket authenticates nothing — `GET /auth` reads the `session-id`
 * header and knows only about `SessionManager` — so a ticket observed in
 * history, in a `Referer`, or by a script reading `location.search` is worth
 * something only inside the sub-second window before the landing page redeems
 * it, and nothing at all afterwards.
 *
 * Known residual, stated rather than papered over: a ticket observed *within*
 * that window is redeemable by the observer. Closing it means binding the
 * ticket to the client the way #36 bound the state, and that binding has to
 * travel on a cookie the cross-origin exchange cannot carry today — see
 * `abofs/stonyx-rest-server#45`. It is a reduction, not an elimination.
 *
 * Like `OAuth.pendingStates`, an abandoned ticket is never collected. That is
 * a pre-existing pattern in this module, not something this store introduces,
 * and it is bounded here by a 60-second TTL rather than a 10-minute one.
 */
export default class TicketStore {
  tickets = new Map<string, TicketRecord>();
  ttl = TICKET_TTL_MS;

  /**
   * Mints a ticket for a freshly created session.
   *
   * The ticket is independent entropy, never a transform of the session id:
   * anything derived from the credential is the credential.
   */
  issue(sessionId: string, expiresAt: number): string {
    const ticket = randomBytes(TICKET_BYTES).toString('base64url');
    this.tickets.set(ticket, { sessionId, expiresAt, createdAt: Date.now() });
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
    const record = ticket ? this.tickets.get(ticket) : undefined;
    if (!record) return null;

    this.tickets.delete(ticket);

    if (Date.now() - record.createdAt > this.ttl) return null;

    return { sessionId: record.sessionId, expiresAt: record.expiresAt };
  }
}
