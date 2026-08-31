import { Request } from '@stonyx/rest-server';
import log from 'stonyx/log';
import { StateRejection } from './state-store.js';
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
 * Hosts treated as a development origin by exact match, and — together with
 * `127.0.0.0/8` and the IPv4-mapped IPv6 spellings of it — the only ones exempt
 * from `Secure` on the binding cookie. See `AuthRequest.isSecureContext`.
 *
 * `0.0.0.0` and `::` are the wildcard bind addresses a developer reaches a
 * local server on; `127.0.0.1` is covered by the `127.0.0.0/8` test rather than
 * listed here, so the two are not silently redundant.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '::1', '0:0:0:0:0:0:0:1', '0.0.0.0', '::']);

/** `host` values whose port component is anything but a decimal port are rejected. */
const PORT_PATTERN = /^\d{1,5}$/;

/**
 * The characters RFC 1123 permits in a registered hostname, plus `.`.
 *
 * Anything else — `@`, `,`, whitespace, `/` — means the value is not a bare
 * hostname, and the caller fails secure rather than guessing. This is what
 * rejects `localhost:80@evil.com` and a comma-joined multi-value `Host`.
 */
const HOSTNAME_PATTERN = /^[A-Za-z0-9._-]+$/;

/** A dotted-quad whose first octet is 127, i.e. real `127.0.0.0/8` membership. */
function isLoopbackIpv4(hostname: string): boolean {
  const octets = hostname.split('.');
  if (octets.length !== 4) return false;
  if (!octets.every(octet => /^\d{1,3}$/.test(octet) && Number(octet) <= 255)) return false;

  return Number(octets[0]) === 127;
}

/**
 * IPv4-mapped IPv6 loopback, in both spellings a dual-stack listener produces:
 * `::ffff:127.0.0.1` and `::ffff:7f00:1`.
 */
function isLoopbackIpv6(hostname: string): boolean {
  const mapped = /^::ffff:(.+)$/.exec(hostname);
  if (!mapped) return false;

  const rest = mapped[1];
  if (isLoopbackIpv4(rest)) return true;

  const hextets = /^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(rest);
  if (!hextets) return false;

  return parseInt(hextets[1], 16) >>> 8 === 127;
}

interface OAuthInstance {
  frontendCallbackUrl?: string;
  getSession(sessionId: string): unknown;
  getAuthorizationUrl(providerName: string): AuthorizationRequest;
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
  /**
   * Node's flat `[name, value, name, value, ...]` header list, when the runtime
   * supplies it. Read only to detect a *duplicate* `Host`: Node collapses
   * repeats into the first value, so `req.headers.host` alone cannot tell an
   * unambiguous origin from a smuggled one.
   */
  rawHeaders?: string[];
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

        const bindingValues = this.readBindingCookies(req);

        if (error) {
          if (this.oauth.frontendCallbackUrl) {
            state.redirect = `${this.oauth.frontendCallbackUrl}?error=${encodeURIComponent(error)}`;
            return;
          }
          return 400;
        }

        if (!code) return 400;

        try {
          const session = await this.oauth.handleCallback(providerName, code, stateToken, bindingValues);

          // The binding value is single-use and the state has now been
          // consumed, so this is the end of that cookie's life.
          this.clearBindingCookie(req);

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
          // Clear only when this request actually spent the cookie.
          //
          // Moving the clear below the `error` and `!code` returns was not
          // enough: it still ran unconditionally for any request carrying a
          // `code`, and `code` is attacker-supplied and unvalidated. So
          // `?code=1` — one query parameter, no knowledge of the victim's state
          // — deleted the binding cookie of a client still at the provider's
          // consent screen, leaving their pending state untouched so nothing
          // was detectable server-side, and their real callback then failed.
          //
          // `StateRejection.consumed` is the only thing that distinguishes
          // "nothing of this client's was touched" from "one attempt was
          // spent". Anything that is not a `StateRejection` was thrown below
          // the state check, which means the record was already burned.
          if (!(rejection instanceof StateRejection) || rejection.consumed) {
            this.clearBindingCookie(req);
          }

          // `StateStore.consume` distinguishes five rejection reasons that
          // otherwise collapse into one opaque outcome with no server-side
          // signal at all. The client-facing `auth_failed` stays opaque; the
          // server has no reason to be.
          //
          // Only a `StateRejection`'s message is logged, and those are the
          // fixed strings in `STATE_REJECTION`. The `try` above spans far more
          // than `consume` — `getProvider`, `TokenManager.getTokens` ->
          // `flow.exchangeCode`, `flow.fetchUserInfo`, `flow.normalizeUser`,
          // `emit('authenticate')`, `sessionManager.create` — and three of
          // those are consumer-overridable through the documented
          // `providers.<name>.module` extension point. A provider that puts
          // request context in its error, which is ordinary practice, would
          // otherwise land its `clientSecret` and the caller-supplied `code` in
          // the log verbatim; `@stonyx/logs` appends content raw when
          // `logToFile` is enabled, so an echoed `code` is also a CRLF
          // log-forging primitive for an unauthenticated caller. Before this
          // module logged anything, all of that was swallowed.
          //
          // Anything below the state check therefore gets a fixed
          // discriminator, and the detail is left to whatever the provider
          // itself logs.
          if (rejection instanceof StateRejection) {
            log.error(`OAuth: callback rejected — ${rejection.message}`);
          } else {
            log.error('OAuth: callback failed after state validation');
          }

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
   *
   * The exemption is decided by *parsing* the `Host` header and testing the
   * result for membership, never by matching a prefix or a suffix on the raw
   * value — `Host` is attacker-controllable on any non-browser client, and a
   * security predicate written as a substring match drifts. Every shape that
   * cannot be parsed as a bare `host[:port]`, and every request with more than
   * one `Host`, fails secure.
   */
  isSecureContext(req: RouteRequest): boolean {
    if (req.secure === true) return true;
    if (AuthRequest.hasAmbiguousHost(req)) return true;

    const host = req.headers.host;
    if (!host) return true;

    const hostname = AuthRequest.parseHostname(host);
    if (hostname === undefined) return true;

    return !AuthRequest.isLoopbackHost(hostname);
  }

  /**
   * True when the request carried more than one `Host` header.
   *
   * Node keeps the first and discards the rest, so a component that *prepends*
   * a `Host:` line — request smuggling, or a proxy that appends rather than
   * replaces — can make `req.headers.host` read `localhost` on a request whose
   * real origin is public. RFC 9112 section 3.2 makes such a request invalid;
   * this treats it as unattributable and fails secure rather than trusting it.
   */
  static hasAmbiguousHost(req: RouteRequest): boolean {
    const raw = req.rawHeaders;
    if (!Array.isArray(raw)) return false;

    let seen = 0;
    for (let index = 0; index < raw.length; index += 2) {
      if (typeof raw[index] === 'string' && raw[index].toLowerCase() === 'host') seen++;
    }

    return seen > 1;
  }

  /**
   * The hostname component of a `Host` header, lowercased, or `undefined` when
   * the value is not a well-formed `host[:port]`.
   *
   * `host.split(':')[0]` is not enough: it truncates at the *first* colon, so
   * `localhost:80@evil.com` reduces to `localhost`. The port is therefore
   * required to be decimal, and the hostname to contain only characters a
   * registered name may contain.
   */
  static parseHostname(host: string): string | undefined {
    if (host.startsWith('[')) {
      const close = host.indexOf(']');
      if (close === -1) return undefined;

      const port = host.slice(close + 1);
      if (port !== '' && !(port.startsWith(':') && PORT_PATTERN.test(port.slice(1)))) return undefined;

      const literal = host.slice(1, close);
      if (!/^[0-9A-Fa-f:.]+$/.test(literal)) return undefined;

      return literal.toLowerCase();
    }

    const colon = host.indexOf(':');
    if (colon === -1) return HOSTNAME_PATTERN.test(host) ? host.toLowerCase() : undefined;

    if (!PORT_PATTERN.test(host.slice(colon + 1))) return undefined;

    const name = host.slice(0, colon);

    return HOSTNAME_PATTERN.test(name) ? name.toLowerCase() : undefined;
  }

  /**
   * Whether a parsed hostname is a loopback development origin.
   *
   * Membership tests, never prefix or suffix tests. `startsWith('127.')`
   * matched `127.evil.com`, a perfectly registerable name (RFC 1123 permits a
   * leading digit in a label), and `endsWith('.localhost')` exempted an entire
   * suffix — so a `.localhost` split-horizon vhost shipped the binding value in
   * cleartext. The `.localhost` exemption is withdrawn rather than tightened:
   * the README documented `127.0.0.0/8`, `localhost`, `::1` and `0.0.0.0` and
   * never documented it, and a developer on `app.localhost` reaches the same
   * server on `localhost` or `127.0.0.1`.
   */
  static isLoopbackHost(hostname: string): boolean {
    if (LOOPBACK_HOSTS.has(hostname)) return true;
    if (isLoopbackIpv4(hostname)) return true;

    return isLoopbackIpv6(hostname);
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

  /**
   * Every value the client presented under the binding cookie's name.
   *
   * Not the first one. A browser sends every applicable cookie in a single
   * header, and a sibling subdomain can set a same-named cookie on the parent
   * domain that RFC 6265 section 5.4 orders *ahead* of the real one — so
   * returning on the first name match handed an attacker a permanent,
   * unauthenticated denial of login for any victim they could plant a cookie
   * on. `Secure`, `HttpOnly` and `SameSite` do not constrain that: the attacker
   * is writing, not reading.
   *
   * Every value is returned, with no cap. A cap here does not bound an attack,
   * it *is* one: truncating the list reinstates exactly the denial above its
   * own threshold, because the planted cookies are the ones that sort first.
   * The work is already bounded by Node's 16 KB header limit — at most 779
   * hashable candidates, 0.32 ms to parse and hash all of them. See
   * `constants.ts` for the measurement.
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
      // `encodeURIComponent` never escapes, so a decode buys nothing — and
      // `decodeURIComponent` throws `URIError` on malformed input, which any
      // unauthenticated caller can supply, turning the first line of the
      // callback into a 500 with a stack trace.
      values.push(part.slice(separator + 1).trim());
    }

    return values;
  }

  clearBindingCookie(req: RouteRequest): void {
    const { res } = req;
    if (typeof res?.clearCookie !== 'function') return;

    res.clearCookie(STATE_COOKIE_NAME, this.cookieOptions(req));
  }
}
