import { Request } from '@stonyx/rest-server';
import log from 'stonyx/log';

/**
 * The cookie carrying the client-held half of the OAuth2 `state` binding (#36).
 *
 * The attributes below are load-bearing, not cosmetic:
 *
 *   - `SameSite=Lax` — the callback is a cross-site, top-level GET navigation
 *     initiated by the provider. `Strict` withholds the cookie on exactly that
 *     request, breaking 100% of logins while passing every CSRF test; `None`
 *     requires `Secure` and widens exposure for no benefit.
 *   - `Path=/` — routing is case-insensitive today
 *     (`abofs/stonyx-rest-server#47`: `GET /AUTH/login/discord` redirects) but
 *     RFC 6265 section 5.1.4 `Path` matching is case-sensitive, so a narrow
 *     `/auth` silently drops the cookie on a case-varied callback and breaks
 *     login.
 *   - `HttpOnly` — script must not be able to read or forge the binding value.
 */
const STATE_COOKIE_NAME = 'oauth_state';
const STATE_COOKIE_PATH = '/';
const STATE_COOKIE_SAME_SITE = 'lax';

interface AuthorizationRequest {
  url: string;
  stateToken: string;
  bindingValue: string;
}

interface OAuthInstance {
  frontendCallbackUrl?: string;
  stateTtl: number;
  getSession(sessionId: string): unknown;
  getAuthorizationUrl(providerName: string): AuthorizationRequest;
  discardState(stateToken: string): void;
  redirectUriFor(providerName: string): string | undefined;
  handleCallback(
    providerName: string,
    code: string,
    stateToken: string,
    bindingValues: readonly string[],
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
 * The response object express hangs off the request.
 *
 * `@stonyx/rest-server` hands handlers `(req, state)` only, and `state.pipe.headers`
 * is unreachable once `state.redirect` is set (`request.ts` returns on the
 * redirect first), so setting a cookie means reaching for `req.res`.
 *
 * This is a deliberate, sanctioned interim reach-around, not an accident:
 * `abofs/stonyx-rest-server#45` is the reopened successor issue that adds a
 * first-class header/cookie affordance to migrate onto, and it is sequenced
 * after this fix. `setBindingCookie` fails closed if the affordance is not
 * there, which is what contains the dependency.
 */
interface ResponseLike {
  cookie(name: string, value: string, options: CookieOptions): unknown;
  clearCookie(name: string, options: Omit<CookieOptions, 'maxAge'>): unknown;
}

interface RouteRequest {
  headers: Record<string, string | undefined>;
  params: Record<string, string>;
  query: Record<string, string>;
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

        // Fail closed. A state we cannot bind to this client is exactly the
        // defect this mechanism exists to prevent, so it is withdrawn rather
        // than issued unbindable.
        if (!this.setBindingCookie(req, providerName, authorization.bindingValue)) {
          this.oauth.discardState(authorization.stateToken);
          return 500;
        }

        state.redirect = authorization.url;
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
          const session = await this.oauth.handleCallback(
            providerName,
            code,
            stateToken,
            this.readBindingCookies(req),
          );

          // Cleared only here, on the success path, which is the only path that
          // is certain to have consumed a state belonging to *this* client.
          //
          // Clearing on failure instead looks harmless and is not: `code` is
          // attacker-supplied and unvalidated, so a bare `?code=1` — no
          // knowledge of anyone's state — would delete the binding cookie of a
          // client still sitting on the provider's consent screen, leaving
          // their pending state untouched so nothing is detectable
          // server-side, and their real callback then fails.
          this.clearBindingCookie(req, providerName);

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

  /**
   * Whether the binding cookie is issued with `Secure`.
   *
   * Derived from the scheme of the provider's configured `redirectUri`, which
   * is the deployment's own statement of the origin this cookie has to survive
   * a round trip to.
   *
   * Not `req.secure`: express derives that from the socket unless `trust proxy`
   * is on, and `@stonyx/rest-server` leaves it off by default, so in the
   * standard production topology — TLS terminated at a proxy, plaintext to the
   * origin — `req.secure` is `false` on every request to an HTTPS site and the
   * cookie would ship without `Secure` while the deployment looks correct. Not
   * the `Host` header either: that is attacker-controllable on any non-browser
   * client. And not hardcoded `true`, which breaks plaintext local development.
   *
   * An unparseable or absent redirect URI fails secure.
   */
  isSecureContext(providerName: string): boolean {
    const redirectUri = this.oauth.redirectUriFor(providerName);
    if (!redirectUri) return true;

    try {
      return new URL(redirectUri).protocol !== 'http:';
    } catch {
      return true;
    }
  }

  cookieOptions(providerName: string): Omit<CookieOptions, 'maxAge'> {
    return {
      httpOnly: true,
      sameSite: STATE_COOKIE_SAME_SITE,
      path: STATE_COOKIE_PATH,
      secure: this.isSecureContext(providerName),
    };
  }

  setBindingCookie(req: RouteRequest, providerName: string, bindingValue: string): boolean {
    const { res } = req;

    if (typeof res?.cookie !== 'function') {
      log.error('OAuth: unable to set the state binding cookie; login rejected');
      return false;
    }

    res.cookie(STATE_COOKIE_NAME, bindingValue, {
      ...this.cookieOptions(providerName),
      maxAge: this.oauth.stateTtl,
    });

    return true;
  }

  /**
   * Every value the client presented under the binding cookie's name.
   *
   * Not the first one, and not capped — see `OAuth.anyCandidateMatches` for why
   * either would hand an attacker a permanent, unauthenticated denial of login
   * for any victim they can plant a same-named cookie on.
   */
  readBindingCookies(req: RouteRequest): string[] {
    const header = req.headers.cookie;
    if (!header) return [];

    const values: string[] = [];

    for (const part of header.split(';')) {
      const separator = part.indexOf('=');
      if (separator === -1) continue;
      if (part.slice(0, separator).trim() !== STATE_COOKIE_NAME) continue;

      // Not decoded. The binding value is base64url, whose alphabet
      // `encodeURIComponent` never escapes, so decoding buys nothing — and
      // `decodeURIComponent` throws `URIError` on malformed input, which any
      // unauthenticated caller can supply, turning the first line of the
      // callback into a 500.
      values.push(part.slice(separator + 1).trim());
    }

    return values;
  }

  clearBindingCookie(req: RouteRequest, providerName: string): void {
    const { res } = req;
    if (typeof res?.clearCookie !== 'function') return;

    res.clearCookie(STATE_COOKIE_NAME, this.cookieOptions(providerName));
  }
}
