import { createHash, randomBytes, randomUUID } from 'node:crypto';
import config from 'stonyx/config';
import log from 'stonyx/log';
import { waitForModule } from 'stonyx';
import { setup, emit } from '@stonyx/events';
import RestServer from '@stonyx/rest-server';
import TokenManager from './token-manager.js';
import SessionManager from './session-manager.js';
import AuthRequest from './auth-request.js';
import type OAuthFlow from './oauth-flow.js';

setup(['authenticate']);

/** Lifetime of a pending state, and the binding cookie's `Max-Age`. */
export const STATE_TTL_MS = 10 * 60 * 1000;

/** Entropy of the client-held binding value, in bytes. */
export const BINDING_VALUE_BYTES = 32;

interface ProviderEntry {
  flow: OAuthFlow;
  tokenManager: TokenManager;
}

/**
 * A flow that is in progress.
 *
 * Holds a *digest* of the binding value rather than the value itself: a
 * callback is only accepted when the caller presents the plaintext that hashes
 * to `bindingHash`, so the record on its own unlocks nothing.
 */
export interface PendingState {
  bindingHash: string;
  createdAt: number;
}

export interface IssuedState {
  /** Sent to the provider as the OAuth2 `state` parameter. */
  url: string;
  /** Retained so a login that cannot be bound can withdraw its own state. */
  stateToken: string;
  /** Held by the client that started the flow, never by the provider. */
  bindingValue: string;
}

interface ProviderConfig {
  module?: string;
  [key: string]: unknown;
}

export default class OAuth {
  static instance: OAuth | null;

  providers = new Map<string, ProviderEntry>();
  pendingStates = new Map<string, PendingState>();
  stateTtl = STATE_TTL_MS;
  sessionManager!: SessionManager;
  frontendCallbackUrl?: string;

  constructor() {
    if (OAuth.instance) return OAuth.instance;
    OAuth.instance = this;
  }

  async init(): Promise<void> {
    // Self-register so log.oauth works even when @stonyx/oauth is in the
    // consumer's `dependencies` (stonyx loader only merges devDependencies).
    const { logColor = 'magenta', logMethod = 'oauth' } = config.oauth;
    log.defineType(logMethod, logColor);

    const oauthConfig = config.oauth;
    const { providers, sessionDuration, frontendCallbackUrl } = oauthConfig;
    this.frontendCallbackUrl = frontendCallbackUrl;

    for (const [name, providerConfig] of Object.entries(providers)) {
      const modulePath = providerConfig.module
        ? `${config.rootPath}/${providerConfig.module}`
        : `./providers/${name}.js`;
      const { default: Provider } = await import(modulePath);
      const flow: OAuthFlow = new Provider(providerConfig);
      this.providers.set(name, { flow, tokenManager: new TokenManager(flow) });
    }

    this.sessionManager = new SessionManager(sessionDuration);

    await waitForModule('rest-server');
    RestServer.instance.mountRoute(AuthRequest, { name: 'auth', options: this });

    log.oauth?.('OAuth module initialized');
  }

  getProvider(name: string): ProviderEntry {
    const provider = this.providers.get(name);
    if (!provider) throw new Error(`OAuth provider "${name}" is not configured`);
    return provider;
  }

  /**
   * SHA-256 of a binding value, hex encoded.
   *
   * The pending record stores the digest so that read access to the map does
   * not hand over the value a callback must present.
   */
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

  /**
   * Whether *any* presented value is the binding value for this record.
   *
   * Every candidate is tried, and the callback is accepted if one matches.
   * Stopping at the first value carrying the cookie's name instead makes a
   * planted cookie a permanent, unauthenticated denial of login: RFC 6265
   * section 5.4 orders the `Cookie` header by path length then creation time,
   * so an attacker with content control on a sibling subdomain sets a
   * same-named cookie once and every subsequent callback for that victim reads
   * theirs, fails the binding check, and burns the state on the way out. The
   * victim cannot recover by retrying.
   *
   * Accepting any match gives an attacker nothing: they would have to present
   * the victim's own binding value, which is the property being checked. And
   * the candidate list is deliberately uncapped — a cap does not bound an
   * attack, it *is* one, reinstating that denial above its own threshold
   * because the planted cookies are the ones that sort first. The work is
   * already bounded by Node's 16 KB header limit.
   *
   * The reduce does not short-circuit, so the work is a function of how many
   * values were presented and not of which one matched.
   */
  static anyCandidateMatches(candidates: readonly string[], bindingHash: string): boolean {
    return candidates.reduce(
      (matched, candidate) => OAuth.digestsMatch(OAuth.hash(candidate), bindingHash) || matched,
      false,
    );
  }

  /**
   * Starts a flow: an OAuth2 `state` for the provider, and a binding value for
   * the client that asked for it.
   *
   * `state` on its own is replay-window limiting, not the CSRF binding it
   * exists to provide (RFC 6749 section 10.12, RFC 9700): before this, any
   * state issued to any visitor validated for any callback, so an attacker
   * could harvest their own state and code, deliver them to a victim over a
   * plain link, and log the victim into the attacker's account. The binding
   * value is the thing the victim's browser carries and the attacker's does
   * not (#36).
   */
  getAuthorizationUrl(providerName: string): IssuedState {
    const { flow } = this.getProvider(providerName);
    const stateToken = randomUUID();
    const bindingValue = randomBytes(BINDING_VALUE_BYTES).toString('base64url');

    this.pendingStates.set(stateToken, {
      bindingHash: OAuth.hash(bindingValue),
      createdAt: Date.now(),
    });

    return { url: flow.buildAuthorizationUrl(stateToken), stateToken, bindingValue };
  }

  /**
   * Withdraws a state that was issued but could not be handed to a client.
   *
   * Used by the login route when the binding cookie cannot be set: a state the
   * client cannot be bound to is exactly the defect this mechanism exists to
   * prevent, so it must not outlive the request that failed to bind it.
   */
  discardState(stateToken: string): void {
    this.pendingStates.delete(stateToken);
  }

  /**
   * Validates and consumes a pending state, then completes the flow.
   *
   * `bindingValues` is every value the client presented under the binding
   * cookie's name — see `anyCandidateMatches`.
   */
  async handleCallback(providerName: string, code: string, stateToken: string, bindingValues: readonly string[]) {
    const record = stateToken ? this.pendingStates.get(stateToken) : undefined;
    if (!record) throw new Error('Invalid or missing state token');

    // Consumed on recognition, before the TTL and binding checks, so every
    // state gets exactly one attempt whatever the outcome. Checking the
    // binding first would leave the record in place on a mismatch and turn
    // this endpoint into a repeatable, unauthenticated oracle against the
    // binding value for the state's full lifetime.
    this.pendingStates.delete(stateToken);

    if (Date.now() - record.createdAt > this.stateTtl) {
      throw new Error('State token has expired');
    }

    // No "absent means skip". An empty candidate list is a rejection, which is
    // what makes an attacker-delivered link fail for a victim who never
    // started the flow and therefore holds no binding cookie.
    const candidates = bindingValues.filter(value => value.length > 0);
    if (candidates.length === 0) throw new Error('Missing state binding value');

    if (!OAuth.anyCandidateMatches(candidates, record.bindingHash)) {
      throw new Error('State token is not bound to this client');
    }

    // Everything below burns a live authorization code, so the binding is
    // settled before `exchangeCode` is ever reached.
    const { flow, tokenManager } = this.getProvider(providerName);
    const tokens = await tokenManager.getTokens(code);
    const rawUser = await flow.fetchUserInfo(tokens.accessToken);
    const user = flow.normalizeUser(rawUser);
    await emit('authenticate', user);
    return this.sessionManager.create(user, tokens);
  }

  /** The provider's configured redirect URI, used to decide the cookie's `Secure`. */
  redirectUriFor(providerName: string): string | undefined {
    return this.providers.get(providerName)?.flow.redirectUri;
  }

  getSession(sessionId: string) {
    return this.sessionManager.validate(sessionId);
  }

  logout(sessionId: string): void {
    this.sessionManager.destroy(sessionId);
  }
}
