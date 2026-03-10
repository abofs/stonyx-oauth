import { Request } from '@stonyx/rest-server';

export default class AuthRequest extends Request {
  constructor(oauth) {
    super();
    this.oauth = oauth;
  }

  handlers = {
    get: {
      '/': ({ headers }) => {
        const sessionId = headers['session-id'];
        if (!sessionId) return 401;

        const user = this.oauth.getSession(sessionId);
        if (!user) return 401;

        return user;
      },

      '/login/:provider': (req, state) => {
        const { provider: providerName } = req.params;

        try {
          const url = this.oauth.getAuthorizationUrl(providerName);
          state.redirect = url;
        } catch {
          return 404;
        }
      },

      '/callback/:provider': async (req, state) => {
        const { provider: providerName } = req.params;
        const { code, state: stateToken, error } = req.query;

        if (error) {
          if (this.oauth.frontendCallbackUrl) {
            state.redirect = `${this.oauth.frontendCallbackUrl}?error=${encodeURIComponent(error)}`;
            return;
          }
          return 400;
        }

        if (!code) return 400;

        try {
          const session = await this.oauth.handleCallback(providerName, code, stateToken);

          if (this.oauth.frontendCallbackUrl) {
            const params = new URLSearchParams({
              sessionId: session.sessionId,
              expiresAt: session.expiresAt,
            });
            state.redirect = `${this.oauth.frontendCallbackUrl}?${params}`;
            return;
          }

          return session;
        } catch {
          if (this.oauth.frontendCallbackUrl) {
            state.redirect = `${this.oauth.frontendCallbackUrl}?error=auth_failed`;
            return;
          }
          return 500;
        }
      },

      '/logout': ({ headers }) => {
        const sessionId = headers['session-id'];
        if (sessionId) this.oauth.logout(sessionId);
      },
    }
  };
}
