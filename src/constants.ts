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
