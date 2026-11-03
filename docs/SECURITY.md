# Security design and known limitations (Phase 128)

## What the server guarantees
| Requirement | How it is met | Where it is tested |
|---|---|---|
| Server is the authority | status, rights, limits, expiry exist only in the database; no endpoint accepts them from a customer | `ClientLicenseServiceTest` |
| Strong activation credential | 160 random bits (`SecureRandom`), Crockford base32 in 8×4 groups | `ActivationCodesTest` |
| Raw code never stored/logged/re-shown | only `HMAC-SHA256(pepper, code)` is persisted; returned once at issuance; `toString` of results/commands redacts; audit text scrubs code-shaped strings | `IssuanceServiceTest`, `ClientLicenseServiceTest.noSecretsReachTheLogs…` |
| Admin endpoints protected | deny-by-default filter on `/api/v1/admin/**`; hashed 256-bit bearer tokens, constant-time compare, per-credential scopes, failure throttling | `AdminAuthenticatorTest`, `IssuanceServiceTest`, `AdminLicenseServiceTest` |
| Payment confirmed by the admin | `paymentVerified` must be `true`; recorded in the audit event | `IssuanceServiceTest` |
| Device ownership | Ed25519 key pair on the device; signature over operation + subject + time + nonce; fingerprint is only evidence | `ClientLicenseServiceTest`, `DeviceKeysTest` |
| No enumeration | one `INVALID_CREDENTIALS` for unknown email / wrong code / unknown device / bad signature | `ClientLicenseServiceTest.unknownEmailAndWrongCode…` |
| Brute force | per-client request limit; per-(client, email) failure lockout; 160-bit codes make guessing infeasible regardless; lockout is per client so an attacker cannot lock a victim out from elsewhere | `ClientLicenseServiceTest` |
| Replay | timestamp window (±5 min) + one-time nonce, nonce consumed only after the signature verifies | `ClientLicenseServiceTest` |
| Device limit under concurrency | one conditional `UPDATE … WHERE active_device_count < device_limit`, plus a `CHECK` constraint | PostgreSQL script (40 parallel sessions → exactly 3), service race tests |
| Atomicity | activation, slot, device row and audit events in one transaction | `JdbcLicenseStoreIT` (rollback), service tests |
| Signed entitlements | JWS/EdDSA; strict verifier (alg, typ, kid, signature first, expiry) | `EntitlementTokensTest` |
| Revocation beats signature | validate/renew consult the database every time | `…DoesNotOverrideRevocation` |
| Append-only audit | code never updates/deletes; PostgreSQL triggers reject UPDATE/DELETE/TRUNCATE | PostgreSQL script |
| Safe errors | one error shape, no echo of input, generic 500 | `ApiExceptionHandler` (**not executed**) |
| Transport | HTTPS required (proxy-terminated), HSTS, nosniff, no-store, CSP `default-src 'none'`, no CORS, no cookies | `SecurityFilter` (**not executed**) |

## Known limitations — read before going live
1. **Not production-ready by evidence.** No deployment-level test was possible. The Spring layer (filters, controllers, wiring, `pom.xml`,
   Flyway/Boot 4.1 starter names) has never been compiled or started.
2. **Admin authentication is deliberately minimal:** static bearer tokens in configuration. No user accounts, MFA, sessions, per-person
   attribution beyond the credential id, or revocation without a restart. Whoever holds a token with `LICENSE_ISSUE` can mint licenses.
   Keep tokens in a password manager, use the narrowest scopes, rotate on any doubt.
3. **Rate limits and the nonce cache are in memory and per process.** Several instances multiply the limits; a restart clears them
   (a replay inside the ±5-minute window right after a restart is possible). Put a gateway/WAF limit in front; add shared state
   (database or Redis) if you scale out.
4. **Audit is application-level append-only.** A database superuser or the table owner can alter it. Restrict DB access, `REVOKE` the
   app role's privileges, and ship audit rows to separate write-once storage for tamper evidence.
5. **The audit trail does not record every read** and does not record failed admin authentication (those are logged at WARN, without tokens).
6. **Unredeemed code theft:** whoever has email + code before the customer does can activate. Deliver codes over a trusted channel and keep
   the activation window short. Activating also needs a device key, so a stolen code alone cannot run on the customer's existing device.
7. **A compromised customer machine** can use its own device key; a signed entitlement proves only that the server issued it. Offline
   behaviour (grace period vs. entitlement lifetime) and local key protection are Phase 129. Nothing here makes cracking "impossible".
8. **Device reset and later edits** (limit, rights, expiry of an existing license) are not implemented.
9. `LICENSE_PENDING` on validate/renew is defensive; the normal flow cannot reach it.
10. Clock: all time comes from the server clock; keep NTP running.
11. H2 (tests) differs from PostgreSQL (production): no V2 audit triggers, different locking implementation.
12. Client-address rate limiting relies on correct reverse-proxy configuration (`LICENSING_TRUSTED_PROXIES`); a wrong value makes every
    client share the proxy's address (over-throttling) or lets spoofed headers through.

## Do not enable PostgreSQL driver debug logging in production (Phase 137)
With the real pgjdbc driver, enabling `org.postgresql` logging at FINE/FINEST (for example `logging.level.org.postgresql=TRACE`, or a global
TRACE/ALL level bridged from java.util.logging) writes SQL bind parameters to the log, including customer e-mail addresses and device public
keys. Activation codes, entitlements and private keys are never bound (only hashes are), but customer data would still be logged. Keep the
driver at its default level. Found when the real driver was first run under the log-secrecy test.
