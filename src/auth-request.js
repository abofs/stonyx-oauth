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

      '/callback/:provider': async (req) => {
        const { provider: providerName } = req.params;
        const { code, state: stateToken } = req.query;

        if (!code) return 400;

        try {
          return await this.oauth.handleCallback(providerName, code, stateToken);
        } catch {
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
