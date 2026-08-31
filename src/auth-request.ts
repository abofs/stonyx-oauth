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

/**
 * Hosts treated as a development origin, and the only ones exempt from
 * `Secure` on the binding cookie. See `AuthRequest.isSecureContext`.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

interface OAuthInstance {
  frontendCallbackUrl?: string;
  getSession(sessionId: string): unknown;
  getAuthorizationUrl(providerName: string): AuthorizationRequest;
  handleCallback(
    providerName: string,
    code: string,
    stateToken: string,
    bindingValue: string | undefined,
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

        const bindingValue = this.readBindingCookie(req);

        if (error) {
          if (this.oauth.frontendCallbackUrl) {
            state.redirect = `${this.oauth.frontendCallbackUrl}?error=${encodeURIComponent(error)}`;
            return;
          }
          return 400;
        }

        if (!code) return 400;

        // The binding value is single-use, so this callback is the end of that
        // cookie's life — but only from here down, where the state is actually
        // consumed. Clearing above the two early returns denied login to a
        // client still at the provider's consent screen, via an
        // attacker-induced navigation to `?error=...` that needs no knowledge
        // of the victim's state at all.
        this.clearBindingCookie(req);

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
        } catch (rejection) {
          // `StateStore.consume` distinguishes five rejection reasons that
          // otherwise collapse into one opaque outcome with no server-side
          // signal at all. The client-facing `auth_failed` stays opaque; the
          // server has no reason to be. The messages are fixed strings, so
          // nothing caller-controlled reaches the log.
          const reason = rejection instanceof Error ? rejection.message : String(rejection);
          log.error(`OAuth: callback rejected — ${reason}`);

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
      secure: this.isSecureContext(req),
    };
  }

  /**
   * Whether the binding cookie is issued with `Secure`.
   *
   * Not `req.secure`. Express derives that from the socket unless `trust proxy`
   * is enabled, and `@stonyx/rest-server` leaves it off by default
   * (`trustProxy: REST_TRUST_PROXY === 'true'`). In the standard production
   * topology — TLS terminated at a proxy, plaintext to the origin — `req.secure`
   * is therefore `false` on every request to an HTTPS site, and the binding
   * cookie would ship without `Secure` while the deployment looks correct.
   *
   * So `Secure` is set unconditionally except on a loopback host. Guessing
   * wrong there breaks a non-loopback plaintext development setup, which fails
   * at the first login and is loud. The alternative fails silently, in
   * production, on the one attribute protecting the value this whole mechanism
   * is built around.
   */
  isSecureContext(req: RouteRequest): boolean {
    if (req.secure === true) return true;

    const host = req.headers.host;
    if (!host) return true;

    // `[::1]:2666` -> `::1`; `localhost:2666` -> `localhost`.
    const hostname = (host.startsWith('[')
      ? host.slice(1, host.indexOf(']'))
      : host.split(':')[0]
    ).toLowerCase();

    if (LOOPBACK_HOSTS.has(hostname)) return false;
    if (hostname.startsWith('127.')) return false;
    if (hostname === 'localhost' || hostname.endsWith('.localhost')) return false;

    return true;
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

      // Not decoded. The binding value is base64url, whose alphabet
      // `encodeURIComponent` never escapes, so a decode buys nothing — and
      // `decodeURIComponent` throws `URIError` on malformed input, which any
      // unauthenticated caller can supply, turning the first line of the
      // callback into a 500 with a stack trace.
      return part.slice(separator + 1).trim();
    }

    return undefined;
  }

  clearBindingCookie(req: RouteRequest): void {
    const { res } = req;
    if (typeof res?.clearCookie !== 'function') return;

    res.clearCookie(STATE_COOKIE_NAME, this.cookieOptions(req));
  }
}
