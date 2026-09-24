# oidc_mfa_auth — Miqaat Core Authentication

Core login service for Miqaat: **OpenID Connect provider + server-rendered login + MFA**, built on
NestJS + Fastify, `oidc-provider`, TypeORM (repository pattern), PostgreSQL and Redis.

It implements the *authentication* part of the specs in `../new-authentication/`
(Core Identity Service Authentication v1.0, SSO Technical Implementation v1.1), as drawn in
`../new-authentication/Miqaat_Auth_00..05_*.svg`. It also implements realm-wide logout with signed
back-channel notifications, and trusted handoff between apps of the same realm
(`../new-authentication/Miqaat_BU_Trusted_Handoff_Implementation_v1.0.md`). Authorization (roles,
permissions) stays in each Business Unit.

| Rule | How it is enforced |
|---|---|
| `sub` = ITS ID | `users.mumin_id` is the account id; nothing else is ever used as `sub` |
| Realm from the client | `auth_clients.auth_realm` (ADMIN / MUMIN); a client without a realm is rejected |
| Separate SSO per realm | One opaque cookie + one server-side session per realm; ADMIN never unlocks MUMIN |
| Authorization Code + PKCE S256 | Enforced by `oidc-provider`; implicit flow and plain PKCE are off |
| MFA owned by Core | OTP by **Email (default)** / SMS through adapters, or TOTP; reused only in the same realm session while fresh |
| Tokens | RS256 ID token, audience = the one client, `acr`, `amr`, `auth_time`, `auth_realm`, `sid` |
| JWKS | `/.well-known/jwks.json`, public keys only, rotation NEXT → ACTIVE → RETIRING → RETIRED, emergency revoke, AWS KMS signing |

## Endpoints

| Path | Served by | Purpose |
|---|---|---|
| `GET /.well-known/openid-configuration` | oidc-provider | discovery |
| `GET /.well-known/jwks.json` | oidc-provider | public signing keys |
| `GET/POST /auth` | oidc-provider | authorization endpoint |
| `POST /token` | oidc-provider | code exchange, client authenticated with `client_secret_basic` (standard; see Client authentication) |
| `GET /me` | oidc-provider | userinfo |
| `POST /token/revocation` | oidc-provider | token revocation |
| `GET /interaction/:uid` | Nest SSR | realm gate: silent SSO, login page or MFA page |
| `POST /interaction/:uid/login` | Nest SSR | ITS ID + password |
| `POST /interaction/:uid/mfa` | Nest SSR | verify the code |
| `POST /interaction/:uid/mfa/resend` · `/mfa/switch` | Nest SSR | new code · other method |
| `POST /interaction/:uid/abort` | Nest SSR | cancel → `access_denied` to the app |
| `GET /logout` · `POST /logout/confirm` | Nest SSR | realm-wide logout (advertised as `end_session_endpoint`) |
| `POST /v1/handoff/requests` | Nest (JSON) | source BU backend asks for a handoff (client-authenticated) |
| `GET /v1/handoff/:id` | Nest SSR | browser: realm session check → signed assertion auto-POSTed to the target |
| `POST /v1/handoff/:id/login` · `/mfa` · `/mfa/resend` · `/mfa/switch` · `/abort` | Nest SSR | login / MFA when the session is missing or too weak |
| `GET /health/live` · `/health/ready` | Nest | liveness · PostgreSQL + Redis readiness |

## Project structure

```
src/
  main.ts                      Fastify bootstrap: cookies, helmet (CSP, frame-ancestors 'none'), static, oidc mount
  config/                      env.ts (zod schema, every setting validated at start-up), AppConfig
  common/                      crypto (HMAC, AES-GCM, masking), request meta
  redis/                       shared ioredis client (key prefix REDIS_KEY_PREFIX)
  database/
    entities/identity/         users, mumin_master, user_eligible            (SYNCED - read only)
    entities/auth/             auth_clients, auth_client_callbacks, auth_sessions, auth_session_clients,
                               auth_login_attempts, auth_audit_events, signing_key_metadata,
                               user_mfa_factors (NEW), auth_otp_challenges (NEW)
    repositories/              one repository per table group - services use only these
    migrations/                1790300000000-OidcMfaAuthSchema (idempotent, no data migration)
    schema-guard.service.ts    refuses to start if the migration has not been run
  modules/
    identity/                  CredentialService (legacy password decrypt, status, allow_login, eligibility)
    sessions/                  GlobalSessionService (realm cookie, Redis hot copy + auth_sessions)
    mfa/                       MfaService, TOTP, adapters/{email,sms}-otp.adapter.ts + registry
    keys/                      SigningKeyService (file or AWS KMS via ExternalSigningKey) + metadata sync
    oidc/                      provider.factory.ts, Redis adapter, client registry, interaction service/controller
    views/                     tiny SSR template renderer
    security/ audit/ health/
views/                         layout.html, login.html, mfa.html, error.html   (edit freely)
public/                        css/auth.css, js/auth.js, img/logo.svg (placeholder - replace with the real logo)
scripts/                       keys, password, client-register, mfa-add-factor, e2e-flow, e2e-suite (+ lib/test-kit)
test/unit.spec.ts
```

## Database: what the migration does

`npm run migration:run` against the **existing** identity database (`DB_SCHEMA`, e.g. `miqaat_core`):

* **never** touches `users`, `mumin_master`, `user_eligible` (checks they exist, then only SELECTs);
* creates the existing auth tables **only if missing** (same DDL as `core-authentication`);
* adds new, nullable columns with `ADD COLUMN IF NOT EXISTS`:
  * `auth_clients`: `auth_realm`, `token_endpoint_auth_method`, `client_jwks_uri`, `client_jwks`, `client_secret_enc`, `allowed_scopes`, `default_acr`
  * `auth_sessions`: `auth_realm`, `session_secret_hash`, `status`, `aal`, `amr`, `auth_time`, `mfa_verified_at`, `mfa_method`
  * `auth_session_clients`: `established_by` · `auth_login_attempts`: `attempt_type`
  * `signing_key_metadata`: `public_jwk`, `key_provider_ref`, `purpose`, `environment`, `activated_at`, `revoked_at`
* creates **`user_mfa_factors`** and **`auth_otp_challenges`**;
* migrates **no data**. History is kept in its own table `oidc_mfa_auth_migrations`.

`migration:revert` removes only what it added (the two new tables and the new columns).
`core-authentication` keeps working on the same database (verified with its `npm run db:check`).

## Login rules (existing identity tables)

1. `users` JOIN `mumin_master` on `mumin_id`, `status_id = ACTIVE_STATUS_ID` (3), not deleted at source
2. account lockout: `LOGIN_MAX_FAILURES_PER_ACCOUNT` wrong passwords in `LOGIN_ACCOUNT_LOCK_SECONDS`
3. password: legacy `Decrypt(users.password)` (byte-for-byte port of the C# code)
4. `COALESCE(users.allow_login, true)`
5. **eligibility**: `LOGIN_ELIGIBILITY_CHECK_ENABLED=true` → the ITS ID must be in `user_eligible`;
   `false` → no eligibility check at all

Allow-login and eligibility messages are only shown after a correct password.

## MFA

* **Required** when the client asks (`acr_values=urn:miqaat:aal:2`, or the client's `default_acr`),
  when `MFA_REQUIRED_FOR_ALL=true`, or for members with the legacy `users.is_otprequired` flag
  (`MFA_HONOR_USER_OTP_FLAG`).
* **Reused** without a prompt when the same realm session is AAL2 and the MFA is younger than
  `min(mfa_max_age request param, MFA_MAX_AGE_SECONDS)`.
* **Methods**: the member's default factor in `user_mfa_factors`; with no factor, **Email OTP to
  `mumin_master.email`**. SMS needs an `SMS_OTP` factor with a phone number (no phone column exists
  in the synced tables). TOTP needs a `TOTP` factor.
* **OTP**: 6 digits, stored only as `HMAC(OTP_HMAC_KEY, code:itsId:sid:uid)`, 5 min, 5 attempts,
  single use, resend cooldown, hourly cap.
* **Adapters** (`src/modules/mfa/adapters`): `EmailOtpAdapter` (SMTP, or `outbox` files in dev),
  `SmsOtpAdapter` (`http` JSON gateway, or `outbox`, or `disabled`). A new channel = one more class
  implementing `OtpDeliveryAdapter`, registered in `mfa.module.ts`.
* **Static test OTP (testing only)**: `MFA_STATIC_OTP=123456` makes that code work for **every member
  and every method** — Email OTP, SMS OTP and TOTP — besides the real code. A member with no method at
  all gets an MFA step that only the static code completes, and the hourly OTP cap is not applied.
  Wrong codes, attempt limits, expiry and the per-session challenge still apply; each success is
  audited as `MFA_SUCCESS` with `staticOtp: true`, and the service logs a warning at start-up.
  Empty = off (default). **The service refuses to start with it in production.**

## Getting started (local)

```bash
cp .env.example .env            # fill DB_*, secrets (see comments); dev: EMAIL_TRANSPORT=outbox
npm install
npm run migration:run           # schema only - see above
npm run keys -- generate        # RS256 signing key (file provider) -> .keys/signing-keys.json
npm run client:register -- --client-id rms-admin-dev --name "RMS Admin" --realm ADMIN \
  --redirect http://localhost:5173/auth/callback --auth-method client_secret_basic --business-unit RMS
npm run build && npm start      # http://localhost:4000
```

Optional: give a member an Email / SMS / TOTP factor (e.g. when `mumin_master.email` is empty):

```bash
npm run mfa:add-factor -- --its 10110101 --method EMAIL_OTP --destination member@example.com --default
```

### End-to-end check

`scripts/e2e-flow.ts` plays browser + BU backend against the running service: `/auth` with PKCE →
login → MFA (code read from the dev outbox) → callback → `/token` → ID token verified via JWKS →
code replay refused.

```bash
E2E_CLIENT_SECRET=<secret> npm run e2e:flow -- --client-id rms-admin-dev \
  --redirect http://localhost:5173/auth/callback --its 10110101 --password-from-db \
  --acr urn:miqaat:aal:2 --jar .e2e/browser.json --expect login
```

Reuse the same `--jar` with another ADMIN client (`--expect sso`) or a MUMIN client (`--expect login`)
to see SSO and realm isolation. `--password-from-db` is refused when `NODE_ENV=production`.

## BU integration (what an application does)

1. Redirect to `/auth` with `response_type=code`, `client_id`, exact `redirect_uri`, `scope=openid [profile]`,
   `state`, `nonce`, `code_challenge` (S256) and, for sensitive pages, `acr_values=urn:miqaat:aal:2`
   (optionally `mfa_max_age=<seconds>`).
2. On the callback, check `state`, then `POST /token` with the code, `code_verifier` and
   `Authorization: Basic base64(client_id:client_secret)`.
3. Verify the ID token with the JWKS (RS256 only): `iss`, `aud` = own client_id, `exp`, `nonce`, and `acr`
   for the page's policy. `sub` is the ITS ID; keep `sid` in the local session.
4. Apply the BU's own roles and permissions (Core never does).
5. Step-up later = repeat step 1 with `acr_values=urn:miqaat:aal:2`: the password is skipped (SSO), only MFA runs.

## Client authentication (client_secret_basic)

Every Business Unit backend authenticates to Core with **`client_secret_basic`**: the secret issued at
registration, sent as `Authorization: Basic base64(url-encoded client_id ":" url-encoded client_secret)`.
It is used at `POST /token` and `POST /v1/handoff/requests`. The browser never sees the secret.

```
POST /token
Authorization: Basic cm1zLWFkbWluLWRldjo8c2VjcmV0Pg==
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…
```

| Setting / command | Purpose |
|---|---|
| `CLIENT_AUTH_METHODS=client_secret_basic` (default) | Methods Core accepts, comma separated. Only Basic is advertised in discovery; a secret in the body (`client_secret_post`) or a client assertion (`private_key_jwt`) is refused, and a client registered for a method that is not enabled cannot sign in. `private_key_jwt` / `client_secret_post` can be switched back on here without code changes. |
| `npm run client:register -- … ` | Defaults to `--auth-method client_secret_basic`; prints the 64-hex secret **once**. |
| `npm run client:rotate-secret -- --client-id X` | New secret, printed once; the old one stops working at once (update the BU secret store, then restart the BU). Moves a client from another method to Basic. |

Secrets are stored encrypted (AES-256-GCM with `DATA_ENCRYPTION_KEY`), never in clear and never logged. In
production keep `DATA_ENCRYPTION_KEY` in AWS Secrets Manager / KMS and each client secret in the BU's own
secret store. Note: when `client_secret_post` is also enabled, oidc-provider treats the two secret methods as
equivalent at `/token` (the handoff API still enforces the registered method).

## Docker

| | Development | Production |
|---|---|---|
| Image | `docker/Dockerfile.dev` (all deps, hot reload) | `docker/Dockerfile.prod` (multi-stage, compiled JS + prod deps only, no TypeScript / ts-node / Nest CLI) |
| Compose | `docker-compose.dev.yml` | `docker-compose.prod.yml` |
| Settings | `.env` (DB / Redis pointed at `host.docker.internal`) | `.env.production` (copy `.env.production.example`) |
| Signing keys | `.keys/` bind mount (file provider) | AWS KMS (enforced) |
| Email / SMS | outbox → `./.outbox` | SMTP / SMS gateway (outbox refused) |
| Hardening | — | non-root `node`, read-only root FS, `cap_drop: ALL`, `no-new-privileges`, healthcheck on `/health/ready`, bound to 127.0.0.1 behind an HTTPS proxy |

```bash
# development (http://localhost:4000, src/ views/ public/ reload on change)
docker compose -f docker-compose.dev.yml run --rm migrate
docker compose -f docker-compose.dev.yml up --build
docker compose -f docker-compose.dev.yml exec app npm run keys -- list

# production
cp .env.production.example .env.production      # fill in, never commit
docker compose -f docker-compose.prod.yml run --rm migrate     # compiled migration, idempotent
docker compose -f docker-compose.prod.yml up -d --build
```

The production container refuses to start (exit 1, every problem listed) with unsafe settings: http
issuer, insecure cookies, outbox transports, signing keys outside KMS or a custom AWS endpoint.

## Logout (realm-wide)

`GET /logout?client_id=…&post_logout_redirect_uri=…&state=…[&id_token_hint=…]` (spec §24-31):

1. The BU ends its own session, then sends the browser to Core `/logout`.
2. Core validates the client, the **exact** registered post-logout URI and the `id_token_hint` (issued by
   Core to this client for this realm; its expiry is not held against it). Without a valid hint Core shows
   a CSRF-protected **"Sign out?"** page, so another site cannot sign members out.
3. Core revokes the realm session (DB + Redis), revokes every token issued in it (`/me` → 401), clears the
   realm cookie, and queues a signed back-channel logout for **every app that joined the session**.
4. The browser is redirected to the post-logout URI with `state` (or a "Signed out" page). The other realm
   is never touched; repeating the logout is a no-op.

**Back-channel message**: `POST <client BACK_CHANNEL_LOGOUT uri>`, form field `logout_token` = RS256 JWS,
`typ: miqaat-logout+jwt`, claims `iss aud sub sid auth_realm reason iat exp(+120 s) jti events`, signed
with the Core key (file or KMS). The BU verifies it with the JWKS, de-duplicates `jti` and ends every local
session with that `sid`.

**Delivery** (`logout_jobs`, `logout_deliveries`): durable PostgreSQL queue, `FOR UPDATE SKIP LOCKED` (safe
with several instances), retries on 5xx / 408 / 429 / timeout / network error following
`LOGOUT_RETRY_SCHEDULE_SECONDS` (0, 5 s, 30 s, 2 min, 10 min, 30 min), then `DEAD`; other 4xx → `FAILED`
(no retry); no URI → `NO_ENDPOINT`. Every attempt is audited. A failed delivery never restores the session.

Register the URIs: `npm run client:add-uri -- --client-id X --type POST_LOGOUT_REDIRECT|BACK_CHANNEL_LOGOUT --uri …`
(or `--post-logout` / `--backchannel-logout` on `client:register`).

## Trusted handoff (app → app, same realm)

Opens a page of another app of the **same realm** (e.g. RMS Admin → AMS Admin `/events/123`) without a
second login and without passing tokens between apps.

1. **Source backend** → `POST /v1/handoff/requests`, authenticated as itself with `client_secret_basic`
   (`private_key_jwt` / `client_secret_post` only if enabled in `CLIENT_AUTH_METHODS`). Body:
   `{ "target_client_id": "ams-admin-dev", "requested_path": "/events/123" }`. The source **never** sends
   the ITS ID. Core checks: source active + outbound enabled; target exists, active, inbound enabled, has a
   callback; same environment; same realm; and the path (relative, no `//`, `\`, `..`, `%2e%2e`, schemes,
   fragments, spaces or control characters; must match the target allowlist, where `*` = exactly one segment).
   → `201 { handoff_request_id, browser_redirect_url, expires_in }` (default 90 s), or 400/401/403/429 with
   `SOURCE_CLIENT_INVALID`, `TARGET_CLIENT_NOT_FOUND`, `TARGET_CLIENT_DISABLED`, `ENVIRONMENT_MISMATCH`,
   `REALM_MISMATCH`, `HANDOFF_PATH_INVALID`.
2. **Browser** → `GET browser_redirect_url` on Core. Core binds the request to the member of the **realm
   session cookie** (login page if there is none; MFA if the target's `default_acr` needs aal:2 and MFA is
   not fresh). The request is completed atomically (one-time URL), the target is recorded as a session
   participant (`HANDOFF`, so realm logout reaches it) and Core auto-POSTs a signed assertion to the
   target's `handoff_callback_uri`.
3. **Assertion**: RS256 JWS, `typ: miqaat-handoff+jwt`, 60 s, claims `iss sub aud source_client_id
   target_client_id auth_realm requested_path sid auth_time acr amr [mfa_time] iat exp jti`.
4. **Target** verifies it (JWKS, `iss`, `aud` = itself, `typ`, `alg`, `exp`, realm), consumes the `jti`
   once, re-validates the path with its own rules, applies **its own authorization**, creates its local
   session with the Core `sid`, and redirects to the path. `verifyHandoff` in `scripts/test-console.ts`
   is a reference implementation.

Configure a client:

```bash
npm run client:handoff -- --client-id ams-admin-dev --callback https://ams.example.com/auth/core/handoff \
  --paths "/dashboard,/events/*,/events/*/details" --inbound --outbound      # --disable turns it off
```

Settings: `HANDOFF_REQUEST_TTL_SECONDS` (90), `HANDOFF_ASSERTION_TTL_SECONDS` (60),
`HANDOFF_RATE_LIMIT_PER_MINUTE` (60 per source client). Audit events: `HANDOFF_REQUESTED`,
`HANDOFF_REJECTED`, `HANDOFF_COMPLETED`, `HANDOFF_CANCELLED`.

## Signing keys: file (dev) or AWS KMS (production)

`SIGNING_KEY_PROVIDER=kms` (enforced in production) signs every token inside AWS KMS through
oidc-provider's `ExternalSigningKey`: the private key never leaves KMS, only the public JWK is kept
in `signing_key_metadata` (`key_provider_ref = kms:<KeyId>`). The service self-tests a KMS signature
at start-up and refuses to start when it fails.

```bash
npm run keys -- list
npm run keys -- generate                 # ACTIVE if none, else NEXT (prepublished in JWKS, not signing)
npm run keys -- activate <kid>           # NEXT -> ACTIVE, old ACTIVE -> RETIRING (still published)
npm run keys -- retire <kid>             # RETIRING -> RETIRED (removed from JWKS)
npm run keys -- revoke <kid> [--revoke-sessions]
                                         # EMERGENCY: removed from JWKS at once, never signs again,
                                         # NEXT promoted or a new key created; KMS key scheduled for deletion;
                                         # --revoke-sessions ends every active Core session (DB + Redis)
```

Restart / roll the service after each change. Normal rotation: generate → wait ≥ JWKS cache time →
activate → wait max token lifetime + skew → retire.

## Legacy password cipher

`src/modules/identity/legacy-password-cipher.ts` holds `decrypt` (byte-for-byte port of the C# code)
and `encrypt`, its exact inverse (random printable key half, self-checked). This service only reads
`users.password`; `encrypt` is for the owning system and test data.

```bash
npm run password -- encrypt --value 'Secret@123'          # ciphertext accepted by the legacy Decrypt()
npm run password -- verify --its 10110101 --value '...'    # MATCH / NO MATCH against users.password
npm run password -- roundtrip                              # decrypt -> encrypt -> decrypt every stored password
```

## Test Console (browser UI, development only)

```bash
npm run build && npm start      # terminal 1: the service on :4000
npm run console                  # terminal 2: http://localhost:5170
```

One page with three demo Business Unit apps (RMS Admin :5173, AMS Admin :5174, RMS Mumin :5175) that
sign in through Core (PKCE, token exchange, JWKS verification, /me), plus live panels: OTP codes from
the dev outbox, test members (status, eligibility, MFA methods, passwords), Core sessions, the audit
trail, service health / signing keys, logout deliveries, handoff requests and a scenario checklist.
Each card has **Open via handoff** (target app + path): the card acts as the source backend, Core
delivers the assertion to the target app, which verifies it and opens the page (`/admin/*` is denied by
the demo target authorization; a MUMIN target is refused by Core with `REALM_MISMATCH`). Client secrets are read from
`.e2e-<app>.txt`. Refuses to run with NODE_ENV=production.

**Client registration** panel (`http://localhost:5170/#clients`) — the UI form of `npm run client:register`
(both use `scripts/lib/client-admin.ts`, so the rules are identical):

* Form: client ID, name, realm, environment, business unit, default assurance, redirect / post-logout /
  back-channel URIs, scopes, client authentication (`client_secret_basic` standard; `private_key_jwt` with a
  JWKS URI or public JWKS) and optional trusted handoff (start / receive, callback URI, allowed paths).
* On success the **secret is shown once**, with the exact `Authorization: Basic …` header the app must send.
  Errors (invalid ID, realm, non-https or wildcard URIs, duplicate client, missing handoff callback …) are
  shown in the page and nothing is written.
* Registered clients table: realm, method, status, URIs, handoff, whether Core can use it (and why not),
  and actions **Open test app**, **New secret** (rotation, old secret stops at once) and **Suspend / Activate**.
* **Use console test URLs** points the new client's redirect, post-logout, back-channel and handoff URIs at
  the console's **test app** (`/try?client_id=…`), which then plays that client's backend: Sign in (AAL1),
  Sign in + MFA (AAL2 step-up), Call `/me`, Logout (realm-wide, its back-channel logout is received and
  verified), handoff **out** to a demo app and handoff **in** from a demo app, with a log of every step.
* The API behind it only accepts JSON requests from the console page (custom header + Origin check), so
  another web site cannot register clients through your browser. There is no delete.

## Postman collection

`postman/Miqaat_Core_Auth.postman_collection.json` (Postman v2.1) — import it in Postman, or run it:

```bash
npm start && npm run console        # service :4000 + Test Console :5170 (MFA_STATIC_OTP=123456 in .env)
npx newman run postman/Miqaat_Core_Auth.postman_collection.json
```

| Folder | What it does |
|---|---|
| 0. Setup | Registers the client `postman-dev` through the Test Console API (or issues it a new secret) and fills `client_id` / `client_secret` |
| 1. Discovery, keys, health | openid-configuration, JWKS, `/health/live`, `/health/ready` |
| 2. Sign in | `/auth` with PKCE → follow redirects → SSR login form → MFA form (`mfa_code`, default `123456`) → code at the redirect_uri → `POST /token` with **client_secret_basic**; checks the ID token claims |
| 3. Userinfo | `GET /me` with the access token |
| 4. Trusted handoff | Create a handoff request, open the one-time URL (signed assertion checked), reuse refused, other realm / unsafe path / no auth refused |
| 5. Client authentication - refused | No credentials, wrong secret, secret in the body, code replay |
| 6. Logout | `/logout` with `id_token_hint` → post-logout URI + state, `/me` 401, next sign-in asks for the password |

The sign-in folder chains itself when run (Collection Runner / newman); clicked one by one, the Postman
console names the next request. Variables: `its_id` / `password` (local test member), `acr_values`
(`urn:miqaat:aal:2` = with MFA, `urn:miqaat:aal:1` = password only), `mfa_code`, `handoff_target` /
`handoff_path`. To use another client, skip folder 0 and set `client_id`, `client_secret`, `redirect_uri`
and `post_logout_redirect_uri`. Development only.

## Tests

```bash
npm test                         # unit tests (TOTP RFC vectors, ciphers, templates, config rules, MFA policy)
npm run build && npm run test:e2e
npm run test:browser             # real Edge through the Test Console (service + console running)
```

`test:e2e` (`scripts/e2e-suite.ts`, development databases only) starts the built service 20 times
with different settings and runs **242 checks** end to end: discovery / JWKS / health; first login;
SSO; ADMIN vs MUMIN isolation; step-up; MFA reuse and stale MFA; client `default_acr`; Email / SMS /
TOTP; resend + cooldown; switch method; wrong codes and attempt limit; OTP expiry; hourly cap; no
method available; cancel; every login rule (wrong password, inactive, unknown, malformed, allow_login,
eligibility on/off); lockout; per-IP limit; request validation (unknown client, client without realm,
foreign redirect_uri, missing / plain PKCE, implicit, prompt=none); token endpoint (wrong secret,
wrong verifier, other redirect, code replay revoking issued tokens, code of another client);
client authentication (`client_secret_basic` standard: no credentials, secret in the body and
`private_key_jwt` refused; optional methods via `CLIENT_AUTH_METHODS`: `private_key_jwt` valid / replayed jti /
wrong key; secret rotation: old secret refused at once, new secret works); `/me`; CSRF, Origin, security headers and cookie
flags; session cookie rotation; idle and absolute expiry; Redis loss (rebuild from PostgreSQL); SMS
HTTP gateway (success + outage); key rotation NEXT → ACTIVE → RETIRING → RETIRED; emergency revoke
with session revocation; KMS signing, rotation and revoke on LocalStack; audit events, hashed OTPs and
no OTP / password in logs; realm logout with back-channel delivery and retries; trusted handoff
(Basic source authentication, other methods refused, assertion claims / JWKS / 60 s, one-time URL, expiry,
login and aal:2 step-up on the handoff, cancel, cross-realm and unsafe paths, inbound / outbound
disabled, participant recorded and notified on logout). It resets only its own `e2e-*` clients and the auth rows of the fixed test
ITS IDs; synced tables are only read. KMS checks need LocalStack on `http://localhost:4566`.

## Out of scope / still open

* **MFA enrollment UI** — factors are added with `mfa:add-factor`; there is no phone-number column in
  the synced tables, so SMS needs an `SMS_OTP` factor.
* **Real providers** — SMTP and the SMS gateway are exercised through the dev outbox and a mock HTTP
  gateway; `SmsOtpAdapter.send()` posts generic JSON and must be adapted to the chosen SMS provider.
* `users.is_otprequired` is covered by unit tests only (the synced table is never modified by tests).
* Existing clients (e.g. `rms-web-dev`) have no `auth_realm` and are rejected until one is set.
* `prompt=none` returns `login_required` (every request passes the Core realm gate).
