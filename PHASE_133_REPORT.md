# Phase 133 — Administrator portal, manual license issuance, subscription management

## Read this first: what is and is not verified
Maven Central is blocked from my environment (policy denial, as in Phases 129–132; not circumvented), so **`mvn verify` was not run, nothing was
started under Spring, and no Flyway/JDBC/end-to-end run happened.** What did run, and on what:

| Check | Environment | Result |
|---|---|---|
| Server tests: 91 earlier + 20 new (`AdminPortalServiceTest`) = **111** | `javac` + JUnit-5-API shim, **real** domain/service/crypto classes, in-memory store | **111 / 111 pass** |
| New SQL (search, status counts, audit counts, earliest audit) | **real PostgreSQL 16**, real migrations V1+V2, bound parameters via PREPARE/EXECUTE, SQL text read from `JdbcLicenseStore.java` | **13 / 13 pass** (`phase133-pg/run-postgres-checks.sh`) |
| Portal UI behaviour | Chromium (Playwright) against **my mock API** serving the real portal files with the portal CSP | **46 / 46 pass** (desktop and 375 px) |
| `AdminController`, `Dtos`, `PortalController` | `javac` against hand-written annotation/type **stubs** of Spring/Jakarta (type-check only) | compile |
| Real Spring wiring, `@Valid`, Jackson, Flyway, `JdbcLicenseStore` executed through JDBC, real HTTP | — | **not done** |

The mock proves the page; it does not prove the real API returns the same JSON. The DTOs and the page were written together, but treat the first real run as the test.

## 1. Files and modules changed (all in `licensing-api/`)
- **Domain:** `License` (`issue(..., fixedEnd)`, `renew`, pending-lapse rule, activation keeps a preset end), `AuditAction.LICENSE_RENEWED`, `LicenseStatus` (doc).
- **Service:** `IssuanceService` (optional explicit expiry), `AdminLicenseService` (`renew`, `search`, `stats` + records).
- **Store:** `LicenseCounts` (new), `LicenseStore` (+4 methods), `JdbcLicenseStore` (SQL for them).
- **Web:** `AdminController` (+`/licenses/search`, `/stats`, `/licenses/{id}/renew`, `expiresAt` on issue), `Dtos`, **`PortalController`** (new).
- **Portal:** `src/main/resources/portal/{index.html,portal.css,portal.js}`.
- **Docs:** `docs/ADMIN_PORTAL.md`, `docs/API.md`, `README.md`. **Tests:** `AdminPortalServiceTest`, `InMemoryLicenseStore`. **No migration** and no change to the signed entitlement format or client endpoints.

## 2. Admin authentication and authorization
Unchanged mechanism, reused: `AdminAuthFilter` protects the whole `/api/v1/admin/**` prefix (rate-limited failures, constant-time hash check); each service method calls `admin.require(scope)`. The portal (`/admin`, three fixed static files, no directory serving) is public like a login page but contains no data. The token is pasted into a password field and kept in a JS variable only: no URL, cookie, localStorage/sessionStorage (checked in the UI test), not in the DOM after sign-in, never logged. A 401 signs the page out. Scopes drive what works (issue / read / lifecycle / audit); a read-only credential sees counts but gets "unavailable" for activity and history. The page has its own CSP (`script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'none'; frame-ancestors 'none'`, no inline code); all server text is rendered with `textContent` (a hostile e-mail string rendered inert in the UI test). Buttons are hidden by status for convenience only; the server enforces transitions and scopes.

## 3. Issuance flow; when records are created
Form → client validation → **Review** (nothing sent) → **Confirm** → one `POST /api/v1/admin/licenses` with a fresh idempotency key. The administrator must tick that they verified payment outside the app (the server refuses `paymentVerified != true`; the page never claims verification). The existing `IssuanceService` creates the license, activation-credential hash, idempotency record and audit event in one transaction. The activation key appears once (Copy button, secure-sending warning), is wiped on Done/navigation, and only its HMAC hash is stored. A double click or retry reuses the key and returns the same license without a code (tested in service tests, 8 concurrent submissions = 1 license, and in the UI: 2 clicks = 1 request). Records exist only after that confirmed call.

## 4. Custom duration and exact expiry
Presets 30/90/180/365, custom days (1–3650, counted from activation), a fixed end date (UTC 23:59:59 of the chosen day; future, ≤3650 days; mutually exclusive with days), or no end date. A fixed end is stored as `expires_at` on the PENDING row at issuance (no migration), survives activation, and is what the signed entitlement carries. If it passes before activation the code is unusable and the license shows as expired/lapsed.

## 5. Lifecycle and renewal
Suspend / reinstate / revoke as before (confirmation dialog + optional reason). **Renew** is an explicit choice: extend by N days (from the later of current end and now; refused when the license has no end date) or set an exact end date. It changes only the end date (EXPIRED → ACTIVE); device bindings, activation time and rights are untouched, a SUSPENDED license stays suspended, REVOKED and never-activated licenses are refused (409), and a stored-EXPIRED license with a bound device validates again without re-activation (tested). Eligibility is checked before the date, so a refused state outranks a bad date.

## 6. Analytics and data sources
Counts (total, awaiting activation, active, expired, lapsed-unactivated, suspended, revoked) come from one SQL aggregate over `license` at request time (no cache, no second store); they are mutually exclusive and sum to the total (checked in SQL and Java). Activity (activation successes/failures, entitlements issued, validations refused, licenses issued; last 30 days and all-recorded, plus "events recorded since" and the 15 newest events) comes from `audit_event`. Without `AUDIT_READ` those are `null` and the page says unavailable, not zero; with it and no events the page says they are real zeros. Pending reads **"effective"** status the same way in SQL and Java (verified on PostgreSQL for stored/derived/fixed-end/window lapses).

## 7. Audit events added
`LICENSE_RENEWED` (detail: old end, new end, mode, reason). Issuance, suspend, reinstate, revoke were already audited; refused attempts are recorded as failures (tested). No raw key, hash or e-mail in audit detail beyond what existed.

## 8. Tests executed
Server: 111/111 (20 new: nothing stored without payment confirmation and refusals leave nothing behind; custom duration; explicit expiry persisted/kept at activation/carried in the signed entitlement; duration+date refused; passed-before-activation; repeated and concurrent submissions → one license, code never shown again; issued code activates through the desktop flow and only the hash is stored; renewal extends/keeps devices/expired→active/suspended stays suspended/revoked and pending refused/inputs validated; every mutation audited; each new operation checks its scope; literal search; status filter and paging; stats match records and separate unavailable from zero; lapsed vs expired). PostgreSQL SQL: 13/13. UI mock: 46/46 (sign-in and storage, review-before-create, no duplicates, one-time key and wipe, copy, fixed date, XSS inertness, search, confirmations, suspend/reinstate/renew/revoke, audit view, CSP clean, same-origin only, 375 px no horizontal scroll). Defects found by testing and fixed: PENDING renewal returned a validation error instead of the transition error; the nav bar was visible on the sign-in screen (`hidden` overridden by CSS); two test-arithmetic mistakes of mine.

## 9. Limitations
Not run: Maven build, Spring startup, `@Valid` handling and JSON binding of the new DTOs, Flyway, the Java `JdbcLicenseStore` through a driver (only its SQL text on PostgreSQL), the portal against the real API, a real browser session with the Railway proxy/CSP. No `@SpringBootTest` exists. The list shows no per-row "last activity"; the detail page shows the newest history event. The "payment verified" tick is an attestation by the administrator, recorded in the audit trail, not independent verification. The portal has no CSRF surface (bearer header, no cookies) but also no session expiry beyond closing the tab.

## 10. Blockers before production use
1. `mvn -B clean verify` on a machine with Maven Central; fix anything in the three web files first (type-checked only against stubs).
2. Start against a real PostgreSQL; open `/admin`, sign in, issue a test license, activate it from the desktop build, suspend/renew/revoke, confirm the audit trail.
3. Run `phase133-pg/run-postgres-checks.sh` where PostgreSQL 16 is available (it needs a non-root user) and the Java store's integration test (`JdbcLicenseStoreIT`) with a DB.
4. Phase 132 blockers remain (Railway deployment, trusted-proxy setting, production keys/pepper/admin token, desktop build with URL and public key).
5. Decide whether the admin token should be replaced by named per-person credentials/scopes before more than one person uses the portal.

Phase 134 has not been started.
