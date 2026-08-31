import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { BINDING_VALUE_BYTES, STATE_TTL_MS } from './constants.js';

/**
 * Server-side record for an OAuth flow that is in progress.
 *
 * Deliberately holds a *digest* of the binding value rather than the value
 * itself: a callback is only accepted when the caller presents the plaintext
 * that hashes to `bindingHash`, so the record on its own unlocks nothing.
 */
export interface PendingState {
  provider: string;
  bindingHash: string;
  createdAt: number;
}

/**
 * The five reasons a callback is rejected, as fixed strings.
 *
 * Named rather than inlined so that collapsing two of them into one is a
 * visible edit: distinguishing them in the server log is the whole point of
 * logging a reason, and an operator telling an expired state from a
 * cross-provider replay depends on them staying distinct.
 */
export const STATE_REJECTION = {
  unknownState: 'Invalid or missing state token',
  expired: 'State token has expired',
  wrongProvider: 'State token was not issued for this provider',
  missingBinding: 'Missing state binding value',
  unboundClient: 'State token is not bound to this client',
} as const;

/**
 * A callback rejected by `StateStore.consume`.
 *
 * Carries two things the route layer cannot otherwise recover: that the
 * rejection came from state validation rather than from anything downstream of
 * it, and whether a pending record was actually consumed.
 */
export class StateRejection extends Error {
  /** True when this attempt recognised a pending record and burned it. */
  consumed: boolean;

  constructor(reason: string, consumed: boolean) {
    super(reason);
    this.name = 'StateRejection';
    this.consumed = consumed;
  }
}

export interface IssuedState {
  /** Sent to the provider as the OAuth2 `state` parameter. */
  stateToken: string;
  /** Held by the client that started the flow (a cookie), never by the provider. */
  bindingValue: string;
}

/**
 * Issues and validates OAuth2 `state` tokens bound to the client that started
 * the flow (#36).
 *
 * Presence-plus-age on a process-global map is replay-window limiting, not the
 * CSRF binding `state` exists to provide (RFC 6749 section 10.12): any state
 * issued to any visitor validated for any callback, so an attacker could
 * harvest their own state and code and deliver them to a victim, logging the
 * victim in as the attacker. A state is now only accepted when the caller also
 * presents the matching client-held binding value, and only at the provider it
 * was issued for.
 */
export default class StateStore {
  pending = new Map<string, PendingState>();
  ttl: number;

  constructor(ttl: number = STATE_TTL_MS) {
    this.ttl = ttl;
  }

  static hash(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /** Length-independent, content-constant-time comparison of two digests. */
  static digestsMatch(a: string, b: string): boolean {
    if (a.length !== b.length) return false;

    let difference = 0;
    for (let index = 0; index < a.length; index++) {
      difference |= a.charCodeAt(index) ^ b.charCodeAt(index);
    }

    return difference === 0;
  }

  issue(provider: string): IssuedState {
    const stateToken = randomUUID();
    const bindingValue = randomBytes(BINDING_VALUE_BYTES).toString('base64url');

    this.pending.set(stateToken, {
      provider,
      bindingHash: StateStore.hash(bindingValue),
      createdAt: Date.now(),
    });

    return { stateToken, bindingValue };
  }

  /**
   * Validates and consumes a pending state. Throws on every rejection path.
   *
   * The record is removed as soon as the state is recognised — before the TTL,
   * provider and binding checks — so every state gets exactly one attempt
   * whatever the outcome.
   *
   * That uniformity is the justification, not brute-force resistance:
   * guessing `BINDING_VALUE_BYTES` of CSPRNG output is infeasible whether or
   * not the record survives. What retaining it would buy an attacker is a
   * repeatable, unauthenticated oracle on this endpoint for the state's full
   * lifetime — and the safety of that would then rest entirely on an entropy
   * constant a future change can lower. One attempt per state is a structural
   * property; entropy arithmetic is not.
   *
   * The trade is real: an attacker who already knows a victim's state can burn
   * it, and the victim must restart at `/auth/login/:provider`. That vector is
   * accepted deliberately — it requires the victim's `randomUUID` state, and
   * it is self-healing on retry. `consumed` on the rejection says whether this
   * call actually burned a record, so a caller can distinguish "nothing of the
   * victim's was touched" from "one attempt was spent".
   *
   * `bindingValues` is every value the client presented under the binding
   * cookie's name, not just the first — see `anyCandidateMatches`.
   */
  consume(stateToken: string | undefined, provider: string, bindingValues: readonly string[]): void {
    if (!stateToken) throw new StateRejection(STATE_REJECTION.unknownState, false);

    const record = this.pending.get(stateToken);
    if (!record) throw new StateRejection(STATE_REJECTION.unknownState, false);
    this.pending.delete(stateToken);

    if (Date.now() - record.createdAt > this.ttl) throw new StateRejection(STATE_REJECTION.expired, true);
    if (record.provider !== provider) throw new StateRejection(STATE_REJECTION.wrongProvider, true);

    const candidates = bindingValues.filter(value => value.length > 0);
    if (candidates.length === 0) throw new StateRejection(STATE_REJECTION.missingBinding, true);

    if (!this.anyCandidateMatches(candidates, record)) {
      throw new StateRejection(STATE_REJECTION.unboundClient, true);
    }
  }

  /**
   * Whether *any* presented value is the binding value for this record.
   *
   * Every candidate is tried, and the callback is accepted if one matches.
   * Returning on the first value carrying the cookie name instead made a
   * planted cookie a permanent, unauthenticated denial of login: RFC 6265
   * section 5.4 orders the `Cookie` header by path length then creation time,
   * so an attacker with content control on a sibling subdomain sets a
   * same-named cookie once and every subsequent callback for that victim reads
   * theirs, fails the binding check, and burns the state on the way out. The
   * victim cannot recover by retrying.
   *
   * Accepting any match gives an attacker nothing: they would have to present
   * the victim's own binding value, which is the property being checked. The
   * record is consumed on recognition, so a state still gets exactly one
   * attempt however many candidates were presented, and the candidate count is
   * bounded by Node's header size limit rather than by a cap here — a cap
   * truncates the list from the wrong end and reinstates the denial this method
   * exists to close. See `constants.ts`.
   *
   * The loop does not short-circuit, so the work is a function of how many
   * values were presented and not of which one matched.
   */
  anyCandidateMatches(candidates: readonly string[], record: PendingState): boolean {
    return candidates.reduce(
      (matched, candidate) => StateStore.digestsMatch(StateStore.hash(candidate), record.bindingHash) || matched,
      false,
    );
  }
}
