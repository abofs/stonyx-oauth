import { Request } from '@stonyx/rest-server';
import log from 'stonyx/log';
import {
  STATE_COOKIE_NAME,
  STATE_COOKIE_PATH,
  STATE_COOKIE_SAME_SITE,
  STATE_TTL_MS,
} from './constants.js';

interface AuthorizationRequest {
  url: string;
  bindingValue: string;
}

interface OAuthInstance {
  frontendCallbackUrl?: string;
  getSession(sessionId: string): unknown;
  getAuthorizationUrl(providerName: string): AuthorizationRequest;
  handleCallback(
    providerName: string,
    code: string,
    stateToken: string,
    bindingValue?: string,
  ): Promise<{ sessionId: string; expiresAt: number }>;
  logout(sessionId: string): void;
}

interface CookieOptions {
  httpOnly: boolean;
  sameSite: string;
  path: string;
  secure: boolean;
  maxAge?: number;
}

/**
 * The response object Express hangs off the request.
 *
 * `@stonyx/rest-server` hands handlers `(req, state)` only, and `state` has no
 * affordance for response headers, so setting a cookie means reaching for
 * `req.res`. This is a deliberate, temporary escape hatch — tracked by
 * `abofs/stonyx-rest-server#45`, which adds a first-class header affordance to
 * migrate onto.
 */
interface ResponseLike {
  cookie(name: string, value: string, options: CookieOptions): unknown;
  clearCookie(name: string, options: Omit<CookieOptions, 'maxAge'>): unknown;
}

interface RouteRequest {
  headers: Record<string, string | undefined>;
  params: Record<string, string>;
  query: Record<string, string>;
  secure?: boolean;
  res?: ResponseLike;
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

        let authorization: AuthorizationRequest;
        try {
          authorization = this.oauth.getAuthorizationUrl(providerName);
        } catch {
          return 404;
        }

        // Fail closed: a state we cannot bind to this client is exactly the
        // defect this mechanism exists to prevent, so never issue one.
        if (!this.setBindingCookie(req, authorization.bindingValue)) return 500;

        state.redirect = authorization.url;
      },

      '/callback/:provider': async (req: RouteRequest, state: RouteState) => {
        const { provider: providerName } = req.params;
        const { code, state: stateToken, error } = req.query;

        // The binding value is single-use: whatever the outcome below, this
        // callback is the end of that cookie's life.
        const bindingValue = this.readBindingCookie(req);
        this.clearBindingCookie(req);

        if (error) {
          if (this.oauth.frontendCallbackUrl) {
            state.redirect = `${this.oauth.frontendCallbackUrl}?error=${encodeURIComponent(error)}`;
            return;
          }
          return 400;
        }

        if (!code) return 400;

        try {
          const session = await this.oauth.handleCallback(providerName, code, stateToken, bindingValue);

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

  cookieOptions(req: RouteRequest): Omit<CookieOptions, 'maxAge'> {
    return {
      httpOnly: true,
      // Load-bearing: the callback is a cross-site top-level GET navigation
      // from the provider. `Strict` withholds the cookie on exactly that
      // request and breaks login outright.
      sameSite: STATE_COOKIE_SAME_SITE,
      path: STATE_COOKIE_PATH,
      secure: req.secure === true,
    };
  }

  setBindingCookie(req: RouteRequest, bindingValue: string): boolean {
    const { res } = req;

    if (typeof res?.cookie !== 'function') {
      log.error('OAuth: unable to set the state binding cookie; login rejected');
      return false;
    }

    res.cookie(STATE_COOKIE_NAME, bindingValue, {
      ...this.cookieOptions(req),
      maxAge: STATE_TTL_MS,
    });

    return true;
  }

  readBindingCookie(req: RouteRequest): string | undefined {
    const header = req.headers.cookie;
    if (!header) return undefined;

    for (const part of header.split(';')) {
      const separator = part.indexOf('=');
      if (separator === -1) continue;
      if (part.slice(0, separator).trim() !== STATE_COOKIE_NAME) continue;

      return decodeURIComponent(part.slice(separator + 1).trim());
    }

    return undefined;
  }

  clearBindingCookie(req: RouteRequest): void {
    const { res } = req;
    if (typeof res?.clearCookie !== 'function') return;

    res.clearCookie(STATE_COOKIE_NAME, this.cookieOptions(req));
  }
}
