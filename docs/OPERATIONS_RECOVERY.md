# Operations and recovery (Phase 136)

Procedures only. **Not rehearsed in this repository's test runs**: do a dry run of every section below against a throw-away database
and a throw-away key before you depend on it. Never paste tokens, activation codes, the pepper, DB passwords or PEM files into tickets, chats or logs.
See also `KEY_ROTATION.md` (rotation steps) and `RAILWAY_DEPLOYMENT.md` (variables).

## What lives where
| Item | Lives in | Lost means |
|---|---|---|
| Licenses, devices, audit, idempotency records | PostgreSQL | Customers' licenses and history gone back to the last backup |
| Signing **private** key (`LICENSING_SIGNING_*`) | Server environment/secret store only | No new entitlements can be signed. The matching **public** key is baked into desktop builds, so recovery without the old key needs a new desktop release |
| Signing **public** key | Desktop build (`trusted-keys.properties`) | Nothing server-side; copy is in the repo history of the build |
| Activation-code pepper (`LICENSING_CODE_PEPPER_BASE64`) | Server environment | Every not-yet-redeemed activation code stops working |
| Admin token **hashes** (`LICENSING_ADMIN_CREDENTIALS_n_*`) | Server environment | Plain tokens exist only in your password manager |
| DB credentials | Server environment + database | Service cannot start |

## 1. PostgreSQL backup and restore
* Backup (scheduled by you, in addition to anything the host offers): `pg_dump -Fc --no-owner -d "$DB_URL" -f licensing-$(date -u +%Y%m%dT%H%MZ).dump`. Encrypt the file (it contains customer e-mails) and store it away from the host. Keep the pepper, signing key and admin hashes **separately**; they are not in the dump.
* Restore into a **new, empty** database, never over production: `createdb licensing_restore && pg_restore --no-owner -d licensing_restore file.dump`.
* Check: `SELECT count(*) FROM license;`, `SELECT max(occurred_at) FROM audit_event;`, `SELECT version,success FROM flyway_schema_history ORDER BY installed_rank;` (all `success = t`).
* Cut over: change only `LICENSING_DB_URL`/`USER`/`PASSWORD`, redeploy, run `deploy/verify-deployment.sh` read-only. Keep the old database until the check passes.
* Test the restore procedure at least once before launch and after any migration.

## 2. What a restore loses (recovery expectations)
* Anything written after the backup: licenses issued, devices activated, renewals, suspensions, audit rows. **RPO = your backup interval.**
* Licenses issued after the backup: the customer holds an activation code whose hash no longer exists. Reconcile against your payment records, then reissue (new code, new idempotency key). Do not reuse the old code.
* Devices activated after the backup must activate again (their signed entitlements keep working until they expire, default 7 days, then the desktop refuses: there is no offline grace).
* A suspension/revocation made after the backup is **undone** by a restore. After restoring, compare with your own records and reapply them through the portal before announcing recovery.
* Audit rows are append-only in the live database; a restore does not repair the gap. Record the gap in your own notes.

## 3. Signing-key backup and recovery
* Back up `<kid>.key.pem` and `<kid>.pub.pem` encrypted, in a password manager or vault, separate from DB backups and from the server. Never commit them (`*.pem`, `*.key` are ignored by `.gitignore`; check anyway).
* If the private key file/secret is lost but you still hold the backup: restore it (mode 600), keep the same `LICENSING_SIGNING_KEY_ID`, restart. The server refuses to start if the pair does not match.
* If there is **no** backup: generate a new pair (`KeyGenTool`), publish a desktop build trusting the new public key, and expect every existing install to need that update. Treat it as an emergency rotation (`KEY_ROTATION.md`).
* Suspected theft: emergency rotation immediately; revocation is separate and server-side.

## 4. Rotation
* Signing key: `KEY_ROTATION.md` (routine and emergency).
* Pepper: only when no codes are outstanding (or revoke and reissue them); then set the new `LICENSING_CODE_PEPPER_BASE64`.
* DB password: change it in PostgreSQL, then in `LICENSING_DB_PASSWORD`, redeploy; confirm health.
* Admin tokens: `AdminTokenTool` prints a new token (once) and its hash. Put the hash in `LICENSING_ADMIN_CREDENTIALS_n_TOKEN_SHA256`, remove the old credential entry, redeploy. A token cannot be revoked without a restart.

## 5. Admin credential recovery
There is no password reset and no database-stored credential. If every admin token is lost: run `AdminTokenTool`, set the new hash as a new credential in the server environment, redeploy, sign in to the portal with the new token, then remove the old entry. Whoever can edit the server environment can do this; protect that access accordingly. After ten failed attempts a credential is locked out for a period (HTTP 429 with `Retry-After`); wait, or redeploy to reset the counter.

## 6. Diagnosing an unavailable licensing service (without exposing customer credentials)
Work from the outside in; stop at the first failure.
1. Desktop shows "licensing unavailable": expected during any outage; no new session can start and a running one is not cut off. Nothing to do on the client.
2. From your machine: `curl -sS -o /dev/null -w '%{http_code}\n' https://<host>/actuator/health` (expect `200`). Connection error = DNS/TLS/host; `403` on API routes over HTTP = HTTPS enforcement working as designed; `502/503` = proxy up, app down.
3. `deploy/verify-deployment.sh` in its default read-only mode (no `CONFIRM_ISSUE`).
4. Host logs: look for start-up failures (`no signing key configured`, `...is required`, Flyway errors, DB connection refused). These messages never contain secrets; **do not** paste request bodies, `Authorization` headers or activation codes into anything.
5. Database: can the service user connect; free disk; connection limit; Flyway history intact.
6. Clock: device proofs and entitlements are time-checked. A server or client clock off by more than a few minutes causes proof/`CLOCK` failures that look like denials.
7. Wrong issuer/key after a deploy: desktop rejects every entitlement as invalid. Compare `LICENSING_ISSUER` and `/api/v1/entitlement-keys` with the desktop build's configured issuer and trusted key id (public values only).

## 7. After any recovery
Run `deploy/verify-deployment.sh`; confirm one desktop can activate with a **test** license and that suspending it from the portal is reflected on the next session start.
