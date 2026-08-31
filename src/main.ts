import config from 'stonyx/config';
import log from 'stonyx/log';
import { waitForModule } from 'stonyx';
import { setup, emit } from '@stonyx/events';
import RestServer from '@stonyx/rest-server';
import TokenManager from './token-manager.js';
import SessionManager from './session-manager.js';
import AuthRequest from './auth-request.js';
import StateStore from './state-store.js';
import type OAuthFlow from './oauth-flow.js';

setup(['authenticate']);

interface ProviderEntry {
  flow: OAuthFlow;
  tokenManager: TokenManager;
}

interface ProviderConfig {
  module?: string;
  [key: string]: unknown;
}

export interface AuthorizationRequest {
  /** Provider authorization URL to redirect the client to. */
  url: string;
  /**
   * Client-held half of the state binding (#36). The caller must hand this to
   * the client that started the flow — the auth routes set it as an HttpOnly
   * cookie — and present it back to `handleCallback`.
   */
  bindingValue: string;
}

export default class OAuth {
  static instance: OAuth | null;

  providers = new Map<string, ProviderEntry>();
  stateStore = new StateStore();
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

  getAuthorizationUrl(providerName: string): AuthorizationRequest {
    const { flow } = this.getProvider(providerName);
    const { stateToken, bindingValue } = this.stateStore.issue(providerName);

    return { url: flow.buildAuthorizationUrl(stateToken), bindingValue };
  }

  /**
   * `bindingValues` is required, not optional (#36). An optional parameter lets
   * an existing three-argument call site keep compiling and then fail at
   * runtime on the first real login; a compile error is the loudest disclosure
   * channel available for this break.
   *
   * It is an array, not a single value, because a client can hold more than one
   * cookie of the binding cookie's name and every one of them has to be tried —
   * see `StateStore.anyCandidateMatches`. A caller driving the flow itself
   * passes `[bindingValue]`; the route handler passes through every value the
   * client presented, which may be none.
   */
  async handleCallback(
    providerName: string,
    code: string,
    stateToken: string,
    bindingValues: readonly string[],
  ) {
    this.stateStore.consume(stateToken, providerName, bindingValues);

    const { flow, tokenManager } = this.getProvider(providerName);
    const tokens = await tokenManager.getTokens(code);
    const rawUser = await flow.fetchUserInfo(tokens.accessToken);
    const user = flow.normalizeUser(rawUser);
    await emit('authenticate', user);
    return this.sessionManager.create(user, tokens);
  }

  getSession(sessionId: string) {
    return this.sessionManager.validate(sessionId);
  }

  logout(sessionId: string): void {
    this.sessionManager.destroy(sessionId);
  }
}
