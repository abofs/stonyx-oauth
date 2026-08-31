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
   * The record is removed as soon as the state is recognised — before the
   * binding is checked — so a state cannot survive a failed attempt and be
   * used as a target for guessing the binding value.
   */
  consume(stateToken: string | undefined, provider: string, bindingValue: string | undefined): void {
    if (!stateToken) throw new Error('Invalid or missing state token');

    const record = this.pending.get(stateToken);
    if (!record) throw new Error('Invalid or missing state token');
    this.pending.delete(stateToken);

    if (Date.now() - record.createdAt > this.ttl) throw new Error('State token has expired');
    if (record.provider !== provider) throw new Error('State token was not issued for this provider');
    if (!bindingValue) throw new Error('Missing state binding value');

    if (!StateStore.digestsMatch(StateStore.hash(bindingValue), record.bindingHash)) {
      throw new Error('State token is not bound to this client');
    }
  }
}
