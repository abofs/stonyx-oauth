import config from 'stonyx/config';
import log from 'stonyx/log';
import { waitForModule } from 'stonyx';
import RestServer from '@stonyx/rest-server';
import TokenManager from './token-manager.js';
import SessionManager from './session-manager.js';
import AuthRequest from './auth-request.js';

export default class OAuth {
  providers = new Map();
  pendingStates = new Map();

  constructor() {
    if (OAuth.instance) return OAuth.instance;
    OAuth.instance = this;
  }

  async init() {
    const { providers, sessionDuration, frontendCallbackUrl } = config.oauth;
    this.frontendCallbackUrl = frontendCallbackUrl;

    for (const [name, providerConfig] of Object.entries(providers)) {
      const modulePath = providerConfig.module
        ? `${config.rootPath}/${providerConfig.module}`
        : `./providers/${name}.js`;
      const { default: Provider } = await import(modulePath);
      const flow = new Provider(providerConfig);
      this.providers.set(name, { flow, tokenManager: new TokenManager(flow) });
    }

    this.sessionManager = new SessionManager(sessionDuration);

    await waitForModule('rest-server');
    RestServer.instance.mountRoute(AuthRequest, { name: 'auth', options: this });

    log.oauth?.('OAuth module initialized');
  }

  getProvider(name) {
    const provider = this.providers.get(name);
    if (!provider) throw new Error(`OAuth provider "${name}" is not configured`);
    return provider;
  }

  getAuthorizationUrl(providerName) {
    const { flow } = this.getProvider(providerName);
    const stateToken = crypto.randomUUID();
    this.pendingStates.set(stateToken, Date.now());
    return flow.buildAuthorizationUrl(stateToken);
  }

  async handleCallback(providerName, code, stateToken) {
    if (!stateToken || !this.pendingStates.has(stateToken)) {
      throw new Error('Invalid or missing state token');
    }

    const stateCreatedAt = this.pendingStates.get(stateToken);
    this.pendingStates.delete(stateToken);

    const TEN_MINUTES = 10 * 60 * 1000;
    if (Date.now() - stateCreatedAt > TEN_MINUTES) {
      throw new Error('State token has expired');
    }

    const { flow, tokenManager } = this.getProvider(providerName);
    const tokens = await tokenManager.getTokens(code);
    const rawUser = await flow.fetchUserInfo(tokens.accessToken);
    const user = flow.normalizeUser(rawUser);
    return this.sessionManager.create(user, tokens);
  }

  getSession(sessionId) {
    return this.sessionManager.validate(sessionId);
  }

  logout(sessionId) {
    this.sessionManager.destroy(sessionId);
  }
}
