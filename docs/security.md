# Security model

What each control in `@stonyx/oauth` protects, what it does not, and how to check that a change preserves it. Consumer-facing descriptions of the cookie and the exchange ticket are in the [README](../README.md#login-csrf-protection--the-oauth_state-cookie); this file covers the internals.

## State binding is the CSRF control

**Requirement (RFC 6749 §10.12, RFC 9700):** the `state` returned on the callback must be bound to the user agent that started the flow. A `pendingStates` entry that is single-use and expires after 10 minutes bounds the replay window only; on its own it is the login-CSRF defect fixed in #36.

**Implementation:**
- `getAuthorizationUrl()` issues a `randomUUID()` state and a 32-byte `randomBytes(BINDING_VALUE_BYTES)` binding value, and stores only `{ bindingHash, createdAt }` (SHA-256 of the binding value), never the value itself.
- `/auth/login/:provider` sets the binding value as the `oauth_state` cookie and fails closed: if the cookie cannot be set, the state is withdrawn with `discardState()` and the login returns `500`.
- `handleCallback()` deletes the record as soon as it recognises the state, before the TTL and binding checks, so a rejected state is still spent and the endpoint is not a repeatable oracle. It rejects an empty candidate list rather than skipping the check, and compares every presented candidate with the constant-time `OAuth.digestsMatch` (see the rationale on `OAuth.anyCandidateMatches`).

**What to verify after a change:** checking only single-use and TTL passes a design with no binding at all. The cases that must stay covered:
- the record is consumed on recognition, so a rejected state cannot be retried;
- an expired record (> 10 minutes) is rejected; a missing or unknown state throws;
- a callback presenting no binding value, only empty values, or another client's value is rejected;
- a callback presenting the real value among several same-named candidates is accepted;
- concurrent callbacks with one state: the second fails;
- `/auth/login/:provider` withdraws the state when the cookie cannot be set.

`STATE_TTL_MS` (10 minutes, also the cookie's `Max-Age`) is a replay-window bound and a usability limit, not the CSRF control. Widening it lengthens the window in which a bound state stays live; it does not weaken the binding. Long authorization flows (a user creating a provider account mid-login) can outlive it.

## The session id is a bearer credential

After a callback, a UUID session id authenticates every request through the `session-id` header (`GET /auth`, `GET /auth/logout`). It must never be written into a URL, and neither may any value that authenticates or redeems on its behalf, beyond one short-lived single use.

- With `frontendCallbackUrl` set, the callback redirects with a single-use 60-second exchange ticket in the URL fragment, never the session id (#45). The ticket is independent 32-byte entropy, authenticates nothing at `GET /auth`, and is redeemed once at `POST /auth/session`.
- Without `frontendCallbackUrl`, the callback returns `{ sessionId, expiresAt }` as the response body, which is not a URL.
- **How the suite checks it:** `assertNoCredentialInRedirect` and `assertNothingRedeemable` in `test/integration/oauth-test.ts` feed every query and fragment value of the redirect to both `GET /auth` and `POST /auth/session`. A key-absence check such as "no `sessionId` parameter" does not establish the property, because the credential could travel under another name.

## The exchange endpoint

`POST /auth/session` is the module's one unauthenticated write surface: it takes an opaque ticket from a JSON body and returns a live session id. Its controls, all of which must survive any change:

- single use, consumed on recognition before the TTL comparison;
- 60-second TTL (`TICKET_TTL_MS` in `src/ticket-store.ts`);
- one indistinguishable `400` for unknown, spent, expired and unparseable tickets.

**Known residual:** nothing binds a ticket to the client that started the flow, so a ticket observed inside its pre-exchange window can be redeemed by the observer. Binding needs a cookie the cross-origin exchange cannot carry; that is blocked on [`abofs/stonyx-rest-server#63`](https://github.com/abofs/stonyx-rest-server/issues/63) (CORS `credentials` unsupported), not on `abofs/stonyx-rest-server#45`. A regression in the controls above is a defect; the residual itself is documented in the README.

## What is held in memory, and in what form

| Store | Key | Value | Sensitive part |
|---|---|---|---|
| `OAuth.pendingStates` | plaintext state | `{ bindingHash, createdAt }` | nothing redeemable: the binding value is only a digest |
| `TicketStore.tickets` | SHA-256 of the ticket (`TicketStore.hash`) | `{ sessionId, expiresAt, createdAt }` | the **plaintext session id** in the value |
| `SessionManager.sessions` | plaintext session id | `{ user, tokens, expiresAt }` | session ids, provider access and refresh tokens |
| each provider (`OAuthFlow`) | n/a | `clientId`, `clientSecret` as instance properties | the client secret, for the life of the process |

Consequences:
- A heap dump, debug serialisation or log of module state leaks live session ids, provider tokens and the client secret. `OAuthFlow` defines no `toJSON`/`toString`, so serialising a provider instance includes `clientSecret`.
- The ticket store keys by digest, so a reader of the map gets no redeemable ticket. No constant-time compare is needed there: `redeem` is a `Map.get` hash probe on a 256-bit key. A change that puts the ticket back in the key, or widens what the record holds, is a regression (pinned by the unit test "the store keys tickets by a digest, never by the ticket itself").
- Neither `pendingStates` nor `TicketStore.tickets` is swept; expired entries are removed only when read. Both sites are tracked together at [stonyx-oauth#43](https://github.com/abofs/stonyx-oauth/issues/43); a fix must cover both.

## Other properties

- **Client secret in transit:** `clientSecret` is sent in the token-exchange and refresh POST bodies to the provider's `tokenUrl`, and is not logged by this module.
- **Session fixation:** every successful callback creates a fresh `randomUUID()` session; there is no way to supply a session id, so fixation is limited to an already-issued session's lifetime. There is no session regeneration within a session.
- **Logout does not revoke:** `logout()` destroys the session but does not call the provider's `revokeToken()`. Providers that support revocation can implement it, but nothing calls it today.
- **Redirect URI:** the configured `redirectUri` is used in both the authorization URL and the code exchange. A mismatch with the provider's registered callback fails the token exchange.
- **`frontendCallbackUrl` is a redirect target:** it comes from config only and must never be made user-controllable. The success redirect is built as `` `${frontendCallbackUrl}#${params}` ``, which assumes the configured URL has no fragment of its own.
- **User info:** fetched with `Authorization: Bearer <accessToken>` from the provider's `userInfoUrl`. The module adds no scheme fallback; the URL each provider declares is what is used (Discord: `https`).
- **Published files:** the package ships `src/` and `config/` alongside `dist/` (`files` in `package.json`), so source must carry no credentials, test-only code or debug logging.
