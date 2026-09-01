import { Request } from '@stonyx/rest-server';

interface OAuthInstance {
  frontendCallbackUrl?: string;
  getSession(sessionId: string): unknown;
  getAuthorizationUrl(providerName: string): string;
  handleCallback(providerName: string, code: string, stateToken: string): Promise<{ sessionId: string; expiresAt: number }>;
  logout(sessionId: string): void;
}

interface RouteRequest {
  headers: Record<string, string | undefined>;
  params: Record<string, string>;
  query: Record<string, string>;
}

interface RouteState {
  redirect?: string;
}

export default class AuthRequest extends Request {
  oauth: OAuthInstance;

  constructor(oauth: OAuthInstance) {
    super();
    this.oauth = oauth;
  }

  handlers = {
    get: {
      '/': ({ headers }: RouteRequest) => {
        const sessionId = headers['session-id'];
        if (!sessionId) return 401;

        const user = this.oauth.getSession(sessionId);
        if (!user) return 401;

        return user;
      },

      '/login/:provider': (req: RouteRequest, state: RouteState) => {
        const { provider: providerName } = req.params;

        try {
          const url = this.oauth.getAuthorizationUrl(providerName);
          state.redirect = url;
        } catch {
          return 404;
        }
      },

      '/callback/:provider': async (req: RouteRequest, state: RouteState) => {
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
              expiresAt: String(session.expiresAt),
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

      '/logout': ({ headers }: RouteRequest) => {
        const sessionId = headers['session-id'];
        if (sessionId) this.oauth.logout(sessionId);
      },
    }
  };
}
