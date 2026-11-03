# Licensing API v1 — contract

Base path `/api/v1`. JSON only (`Content-Type: application/json`). All times are ISO-8601 UTC. All examples use **dummy data**.
Every error has the same body: `{"code": "<ERROR_CODE>", "message": "<generic text>"}`. Bodies are capped at 16 KiB (`413`).

## Authentication

| Area | Mechanism |
|---|---|
| `/api/v1/admin/**` | `Authorization: Bearer ia_adm_…` (enforced for the whole prefix by a filter). Missing/invalid → `401 UNAUTHENTICATED`; valid but lacking the scope → `403 FORBIDDEN`. |
| `/api/v1/client/**`, `/api/v1/entitlement-keys` | No bearer token. Authorised by what the caller proves: activation code **and** a device-key signature (see below). |

Admin scopes: `LICENSE_ISSUE`, `LICENSE_READ`, `LICENSE_LIFECYCLE`, `AUDIT_READ`.

## Device proof (client endpoints)

The device holds an Ed25519 key pair. The **public** key (X.509 SubjectPublicKeyInfo DER, base64url, 44 bytes) is registered at
activation. Each client request carries `proofTimestamp` (Unix seconds), `proofNonce` (16–64 chars `[A-Za-z0-9_-]`, never reused) and
`proofSignature` (base64url Ed25519 signature) over the UTF-8 message (LF = newline):

```
activate:     "ia-license-v1" LF "activate"    LF <normalised email> LF <key thumbprint> LF <timestamp> LF <nonce>
validate:     "ia-license-v1" LF "validate"    LF <licenseId> LF <deviceRegistrationId> LF <timestamp> LF <nonce>
entitlement:  "ia-license-v1" LF "entitlement" LF <licenseId> LF <deviceRegistrationId> LF <timestamp> LF <nonce>
```
`key thumbprint` = lowercase hex SHA-256 of the DER public-key bytes. `normalised email` = trimmed, lower-case. The timestamp must be within
±5 minutes of server time; a nonce can be used once. A hardware/OS fingerprint (`supplementaryFingerprint`) is stored only as a keyed
hash and is **never** sufficient on its own.

## Admin endpoints

### POST /admin/licenses — issue after manual payment verification (scope LICENSE_ISSUE)
Headers: `Idempotency-Key: <16–128 chars [A-Za-z0-9_-]>` (required).
```json
{ "customerEmail": "customer@example.com", "paymentVerified": true, "paymentReference": "bank-2026-11-01-0042",
  "policy": { "deviceLimit": 1, "validityDays": 365, "rights": ["LIVE","AI_LIVE","DSA","SCREEN_QUESTION"], "activationWindowDays": 30 } }
```
`validityDays` omitted/null = never expires (counted from first activation). Optional `"expiresAt": "2030-05-17T23:59:59Z"` fixes the end
date instead (then `validityDays` must be null; a future instant at most 3650 days away, stored to the second). The end date is kept
through activation and is what the signed entitlement carries; if it passes before activation the code stops working. `activationWindowDays` omitted = server default (30).
`paymentVerified` must be literally `true` or the request is refused (`400 PAYMENT_NOT_CONFIRMED`).
`201`:
```json
{ "license": { "id": "6f1d0c1e-0000-4000-8000-000000000001", "customerEmail": "customer@example.com", "status": "PENDING",
    "effectiveStatus": "PENDING", "deviceLimit": 1, "activeDeviceCount": 0, "validityDays": 365,
    "rights": ["AI_LIVE","DSA","LIVE","SCREEN_QUESTION"], "createdAt": "2026-11-01T12:00:00Z",
    "activationDeadline": "2026-12-01T12:00:00Z", "activatedAt": null, "expiresAt": null, "suspendedAt": null, "revokedAt": null },
  "activationCode": "7H2K-9QPM-X4TD-0VBN-C8RJ-W3YE-A5FG-ZS61", "replayed": false }
```
**Idempotency:** the same key + same request again → `200` with the same license, `"activationCode": null`, `"replayed": true`
(the code cannot be recovered; revoke and reissue if lost). Same key + different request → `409 IDEMPOTENCY_KEY_REUSED`.
Errors: `400 VALIDATION_FAILED | PAYMENT_NOT_CONFIRMED`, `401`, `403`, `409 IDEMPOTENCY_KEY_REUSED | CONFLICT`.

### GET /admin/licenses/{id} · GET /admin/licenses?customerEmail= (scope LICENSE_READ)
Returns the license object above (never a credential). `404 LICENSE_NOT_FOUND`. `status` is stored; `effectiveStatus` accounts for time.

### POST /admin/licenses/{id}/suspend · /reinstate · /revoke (scope LICENSE_LIFECYCLE)
Body optional: `{"reason": "chargeback under review"}` (≤200 chars). Returns the license. Not idempotent as such, but repeating a
transition that is no longer allowed returns `409 ILLEGAL_TRANSITION` and changes nothing. Allowed transitions are in `LicenseStatus`.
`REVOKED` is terminal. `EXPIRED` licenses are not suspended or reinstated, but an activated one can be **renewed** (next section).

### POST /admin/licenses/{id}/renew (scope LICENSE_LIFECYCLE)
`{"mode":"EXTEND_DAYS","days":365,"reason":"…"}` (new end = the later of the current end and now, plus `days`; refused if the license has
no end date) **or** `{"mode":"SET_END","endsAt":"2031-02-03T23:59:59Z","reason":"…"}`. Exactly one of `days`/`endsAt`, matching `mode`.
Only the end date changes (and EXPIRED → ACTIVE): device bindings, activation time and rights stay; a SUSPENDED license stays suspended.
`409 ILLEGAL_TRANSITION` for a revoked license or one never activated. Audited as `LICENSE_RENEWED` with `expiresFrom/expiresTo/mode`.

### GET /admin/licenses/search?q=&status=&limit=&offset= (scope LICENSE_READ)
`q` is a literal, case-insensitive fragment of the e-mail (max 100 chars; `%` and `_` are ordinary characters). `status` is an *effective*
status (PENDING, ACTIVE, EXPIRED, SUSPENDED, REVOKED). Newest first; `limit` ≤ 100, `offset` ≤ 10000. `{"items":[license…],"hasMore":false,"offset":0}`.

### GET /admin/stats (scope LICENSE_READ; activity part needs AUDIT_READ)
Counts computed by the database at request time: `licenses` {total, pending, active, expiredAfterActivation, lapsedUnactivated, suspended, revoked}
(mutually exclusive, sum to total). With AUDIT_READ also `activityAvailable:true`, `activityRecordedSince`, `last30Days`/`allRecorded`
{activationSuccesses, activationFailures, entitlementsIssued, validationRejections, licensesIssued} and `recent` (15 newest audit events).
Without it: `activityAvailable:false` and the activity fields are `null` (unavailable, **not** zero).

### GET /admin/licenses/{id}/audit · GET /admin/audit?beforeId=&limit= (scope AUDIT_READ)
Newest first, `limit` 1–200 (default 50). `{"events":[{"id":42,"occurredAt":"…","actor":"admin:developer","action":"LICENSE_REVOKED","licenseId":"…","outcome":"SUCCESS","detail":"from=ACTIVE; to=REVOKED; note=refund"}],"nextBeforeId":41}`; pass `nextBeforeId` as `beforeId` for the next page (`null` = last page).

### Deferred: device reset (Phase 129+)
Not implemented. The schema (`device_registration.status = RESET`, `reset_at`) and counter logic are ready; the authorisation rules (who may
reset, cooldown, audit) need their own design.

## Client endpoints

### POST /client/activate
```json
{ "email": "customer@example.com", "activationCode": "7H2K-9QPM-X4TD-0VBN-C8RJ-W3YE-A5FG-ZS61",
  "devicePublicKey": "MCowBQYDK2VwAyEA…(base64url, 44 bytes)", "proofTimestamp": 1793534400, "proofNonce": "q3Zr9mXk1TqW8dLpA2vN7g",
  "proofSignature": "…(base64url, 64 bytes)", "deviceLabel": "Work laptop", "supplementaryFingerprint": "optional-evidence" }
```
`200`:
```json
{ "licenseId": "6f1d0c1e-…0001", "deviceRegistrationId": "0a8e…", "status": "ACTIVE", "rights": ["DSA","LIVE"],
  "licenseExpiresAt": "2027-11-01T12:00:00Z", "entitlement": "<JWS>", "entitlementExpiresAt": "2026-11-08T12:00:00Z",
  "renewAfter": "2026-11-05T00:00:00Z", "alreadyRegistered": false }
```
**Idempotency:** the same device key retrying (also concurrently) is bound once; later calls return `alreadyRegistered: true` with a fresh
entitlement. A different key after the device limit is reached → `409 DEVICE_LIMIT_REACHED`. A reused nonce → `400 INVALID_DEVICE_PROOF`
(use a new nonce and signature on each retry).

### POST /client/validate · POST /client/entitlement
Body: `{"licenseId":"…","deviceRegistrationId":"…","proofTimestamp":…,"proofNonce":"…","proofSignature":"…"}`.
`validate` → `{"valid":true,"licenseId":"…","deviceRegistrationId":"…","status":"ACTIVE","rights":[…],"licenseExpiresAt":…,"serverTime":…}`.
`entitlement` → `{"licenseId":…,"deviceRegistrationId":…,"rights":[…],"licenseExpiresAt":…,"entitlement":"<JWS>","entitlementExpiresAt":…,"renewAfter":…}`.
Each `entitlement` call mints a new token (new `jti`); it is safe to retry but not idempotent in value.

### GET /entitlement-keys
Public verification keys as a JWK set (`kty:"OKP"`, `crv:"Ed25519"`, `kid`, `x`). For operations/tooling; the desktop must embed its trusted keys at build time.

## Error codes

| HTTP | Code | When |
|---|---|---|
| 400 | `VALIDATION_FAILED` | malformed body/field, bad email or code format |
| 400 | `INVALID_DEVICE_PROOF` | stale/future timestamp, bad nonce, signature does not verify at activation, nonce replay |
| 400 | `PAYMENT_NOT_CONFIRMED` | `paymentVerified` is not `true` |
| 401 | `UNAUTHENTICATED` | admin token missing/invalid |
| 401 | `INVALID_CREDENTIALS` | **one answer** for unknown email, wrong code, unknown device, bad device signature on validate/renew |
| 403 | `FORBIDDEN` | admin credential lacks the scope |
| 403 | `LICENSE_SUSPENDED` / `LICENSE_REVOKED` / `LICENSE_EXPIRED` | revealed only after the caller proved the right to ask |
| 403 | `DEVICE_NOT_REGISTERED` | the device's registration is no longer active |
| 403 | `HTTPS_REQUIRED` | request did not arrive over TLS |
| 404 | `LICENSE_NOT_FOUND` | admin lookups |
| 409 | `LICENSE_PENDING` | validate/renew against a license that has not completed activation (defensive; unreachable through normal flows) |
| 409 | `DEVICE_LIMIT_REACHED` | license already bound to other device(s) up to its limit |
| 409 | `ILLEGAL_TRANSITION` / `IDEMPOTENCY_KEY_REUSED` / `CONFLICT` | state or concurrency conflict |
| 413 | `PAYLOAD_TOO_LARGE` | body over the cap |
| 429 | `RATE_LIMITED` | with `Retry-After` seconds |
| 500 | `INTERNAL_ERROR` | generic; details only in the server log |

## Entitlement format (v1)
JWS compact serialisation, `alg: EdDSA` (Ed25519), header `{"alg":"EdDSA","kid":"<key id>","typ":"ia-entitlement+jwt"}`.
Claims: `ver`=1, `iss`, `jti` (entitlement id), `lic` (license id), `dev` (device registration id), `dkt` (device key thumbprint),
`rights` (array), `iat`, `exp` (honour no later), `ren` (renew from), `lexp` (license end; omitted if none). The signature covers the exact
`header.payload` bytes. A valid signature does **not** override a server-side suspension or revocation.
