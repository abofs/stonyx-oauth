// Shared constants for the OAuth state/client-binding mechanism (#36).
//
// The binding cookie attributes are load-bearing, not cosmetic:
//   - `SameSite=Lax` — the OAuth callback is a cross-site, top-level GET
//     navigation initiated by the provider. `Strict` withholds the cookie on
//     exactly that request and breaks login; `None` requires `Secure` and
//     widens exposure for no benefit. `Lax` is the only correct value.
//   - `Path=/auth` — the cookie is only ever read by the callback route.
//   - `HttpOnly` — script must not be able to read or forge the binding value.

export const STATE_COOKIE_NAME = 'stonyx_oauth_state';
export const STATE_COOKIE_PATH = '/auth';
export const STATE_COOKIE_SAME_SITE = 'lax';

/** Lifetime of a pending state record, and the binding cookie's Max-Age. */
export const STATE_TTL_MS = 10 * 60 * 1000;

/** Entropy of the client-held binding value, in bytes. */
export const BINDING_VALUE_BYTES = 32;

/**
 * There is deliberately no cap on how many values carrying `STATE_COOKIE_NAME`
 * a callback will try.
 *
 * A client can hold more than one cookie of the same name — a sibling subdomain
 * can set one on the parent domain — and the browser sends every applicable
 * cookie in one header, so all of them must be tried or a planted cookie denies
 * login by sorting ahead of the real one (RFC 6265 section 5.4).
 *
 * A cap of 8 was tried and withdrawn: it *reinstated* that denial above its own
 * threshold. Measured on the pre-change tree, 7 shadow cookies still minted a
 * session and 8 failed permanently — the same outcome as the original defect,
 * with the attacker's cost raised from one planted cookie to eight. That is
 * reachable: RFC 6265 section 5.4 orders by path length then creation time, so
 * a 4-label API host with a foothold beneath it gets 3 settable parent domains
 * x 3 usable paths = 9 candidates ahead of the real one.
 *
 * What the cap was defending is already bounded, structurally and for free.
 * Node caps the whole header block at `http.maxHeaderSize`, 16 KB by default,
 * and the shortest segment that can reach the hash is `stonyx_oauth_state=x` at
 * 20 bytes, so a request cannot present more than 779 hashable candidates.
 * Parsing and SHA-256-hashing all 779 costs 0.32 ms median / 0.81 ms worst of 9
 * runs (Node 24.13.0, Apple silicon). Paying a permanent, unauthenticated
 * denial of login to avoid a third of a millisecond is the wrong trade, so the
 * bound is left where it already was: the header size limit.
 */
