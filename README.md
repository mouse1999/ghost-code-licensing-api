# Interview Assistant — Licensing API (Phase 128)

A standalone Java 21 / Spring Boot 4.1 service that is the **authority** for licenses: issuance, activation, device limits,
expiry, suspension and revocation. It is a separate project; the desktop application's `pom.xml` is untouched.

> **Status:** the framework-free core and the database layer were compiled and tested in the authoring sandbox; the Spring Boot
> layer (controllers, filters, wiring, `pom.xml`) was **only syntax-checked** because Maven Central was unreachable there. Run
> `mvn verify` before anything else. See `PHASE_128_REPORT.md` for exactly what was and was not executed.

## Layout

| Package | Contents | Needs Spring? |
|---|---|---|
| `domain` | immutable records: `License`, `LicensePolicy`, `DeviceRegistration`, `Entitlement`, `AuditEvent`; `LicenseStatus` state machine | no |
| `crypto` | activation codes (keyed hash), Ed25519 JWS entitlements, device-key proofs, PEM keys, key ring | no |
| `security` | admin bearer-token authentication + scopes, rate limiter, replay (nonce) cache | no |
| `store` | `LicenseStore` port, JDBC implementation, transaction runner | no (JDBC only) |
| `service` | issuance, client activation/validation/renewal, admin lifecycle + audit review | no |
| `web` | controllers, DTOs, filters, error handler, configuration properties, wiring | yes |
| `tools` | `AdminTokenTool`, `KeyGenTool` (command-line helpers) | no |

## Build and test

```
mvn verify          # unit tests + H2 integration test (JdbcLicenseStoreIT)
src/test/db/postgres-db-tests.sh run     # as a PostgreSQL superuser: real-PostgreSQL constraint/concurrency checks
```

## First-time setup

1. **Signing key and pepper** (once; keep the output secret):
   `mvn -q compile && java -cp target/classes com.interviewassistant.licensing.tools.KeyGenTool 2026-a /etc/licensing/keys`
   It writes `2026-a.key.pem` (private, mode 600 — **server only**) and `2026-a.pub.pem` (public — embed in the desktop build in
   Phase 129), and prints `LICENSING_CODE_PEPPER_BASE64`.
2. **First administrator credential:** run `java -cp target/classes com.interviewassistant.licensing.tools.AdminTokenTool`. It prints a token **once** and the SHA-256 hash. Keep the token in a
   password manager; give the server only the hash (below).
3. **Database:** create a PostgreSQL database and a role that owns it. Flyway applies `db/migration/common` and
   `db/migration/postgresql` at start-up. Then, once, as the owner:
   `REVOKE UPDATE, DELETE, TRUNCATE ON audit_event FROM <app_role>;`
4. **Environment** (never commit these; use your platform's secret store):

| Variable | Meaning |
|---|---|
| `LICENSING_DB_URL`, `LICENSING_DB_USER`, `LICENSING_DB_PASSWORD` | PostgreSQL connection |
| `LICENSING_CODE_PEPPER_BASE64` | from `KeyGenTool`; **do not change while codes are outstanding** |
| `LICENSING_SIGNING_KEY_ID`, `LICENSING_SIGNING_PRIVATE_KEY_FILE`, `LICENSING_SIGNING_PUBLIC_KEY_FILE` | active signing key |
| `LICENSING_SIGNING_VERIFY_ONLY_DIR` | optional: retired `<kid>.pub.pem` files (rotation) |
| `LICENSING_ADMIN_CREDENTIALS_0_ID` / `_TOKEN_SHA256` / `_SCOPES` | from `AdminTokenTool` (add `_1_…` for more) |
| `LICENSING_ISSUER` | public URL of the service, written into every entitlement |
| `LICENSING_PORT`, `LICENSING_TRUSTED_PROXIES` | listen port; regex of reverse-proxy addresses whose `X-Forwarded-*` is trusted |
| `LICENSING_ENTITLEMENT_TTL` | entitlement lifetime (default `7d`) |
| `LICENSING_RATE_*` | optional rate-limit overrides |

5. **Start:** `java -jar licensing-api.jar` (production) or `--spring.profiles.active=dev` (localhost, HTTP, throw-away signing key;
   still needs a database, a pepper and an admin hash — there are no default credentials).

## HTTPS in deployment

The application never terminates TLS itself in the documented setup. Run it behind a reverse proxy (Caddy, nginx, a cloud load
balancer) that terminates TLS 1.2+/1.3, redirects HTTP→HTTPS, and sets `X-Forwarded-For`/`X-Forwarded-Proto`. Set
`LICENSING_TRUSTED_PROXIES` to the proxy's address so the container honours those headers **only from it**. With
`licensing.security.require-https=true` (the default) the app answers `403 HTTPS_REQUIRED` to anything that did not arrive over
TLS, and adds HSTS on secure requests. Bind the app's own port to the private network only.

## Issuing a license (manual payment)

1. Verify the customer's payment yourself, outside this system.
2. `POST /api/v1/admin/licenses` with `Authorization: Bearer <token>`, a fresh `Idempotency-Key`, and `"paymentVerified": true`.
3. Read the `activationCode` from the response **now** — it is never shown again — and send it to the customer over a channel you
   trust. If the response is lost, revoke that license and issue a new one.

Full contract: `docs/API.md`. Security design and limits: `docs/SECURITY.md`. Key rotation: `docs/KEY_ROTATION.md`.

## Administrator portal
Open `/admin` on a running instance; see `docs/ADMIN_PORTAL.md` (manual-payment issuance, search, lifecycle, renewal, dashboard).
