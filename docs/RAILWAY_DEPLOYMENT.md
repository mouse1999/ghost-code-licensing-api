# Deploying the licensing API on Railway (Phase 132)

**Status: prepared, NOT deployed, NOT verified on Railway.** The files below were written without access to Railway, Maven Central or Docker, so the first Railway build and start are the first real build and start. Nothing here is evidence that a deployment works. Facts taken from Railway's own documentation are marked **[docs]**; anything the documentation did not state is marked **[verify on first deploy]** and must not be assumed.

## 0. Go / no-go gates (in this order)

1. `mvn -B clean verify` passes in `licensing-api/` and in the desktop project, on a machine with Maven Central. The Dockerfile repeats it inside the image and does **not** skip tests, so a failing test stops the deployment.
2. Note that the server project has **no Spring context test** (no `@SpringBootTest`), so a green build does not prove Spring wiring or Flyway. The first start on Railway is that test: read the deploy log for `Started LicensingApplication` and for Flyway applying `V1` and `V2`.
3. Deploy to Railway and get a running service (milestone A: *API deployed*).
4. Run `deploy/verify-deployment.sh` and the manual checks in section 7 (milestone B: *ready for desktop enforcement* also needs the Windows activation flow).

Do not point any distributed desktop build at the API before milestone B.

## 1. Files in this project

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build (Maven + Temurin 21), runs the full tests, JRE-only unprivileged runtime. **[docs]** Railway builds with a Dockerfile whenever one exists. |
| `docker-entrypoint.sh` | Fail-closed launcher: refuses unsafe or missing configuration, turns the environment-variable secrets into mode-600 key files, binds the platform port. Tested with a stub `java` (22 cases) and with the server's own `SigningKeyRing`. |
| `railway.json` | Build/deploy settings. **[docs]** keys `build.builder`, `build.dockerfilePath`, `deploy.healthcheckPath`, `healthcheckTimeout`, `restartPolicyType`, `restartPolicyMaxRetries`. **[docs] Railway marks config-as-code files as legacy, supported until 2026-12-01.** Set the same values in the dashboard so nothing depends on this file. |
| `deploy/verify-deployment.sh` | Black-box checks of the deployed API (section 7). |

Service root: the `licensing-api/` directory (its own repository, or a monorepo service with root directory `licensing-api`). The desktop application is never deployed as a server.

## 2. Railway services

1. One **PostgreSQL** service. Do not delete, recreate or reset it to fix a deployment problem; deployments only read and migrate it.
2. One **API** service built from `licensing-api/`. Keep it at **one replica**: the rate limiters and the nonce cache are in memory, so a second replica would double every limit and weaken replay protection.
3. Generate a public domain for the API service. **[docs]** Railway provisions free TLS certificates for public domains.

## 3. Environment variables (names only; never commit values)

Set these on the **API service**. Mark secrets as sealed/secret in the dashboard where available.

| Variable | Content | Secret |
|---|---|---|
| `LICENSING_DB_URL` | `jdbc:postgresql://<host>:<port>/<database>` built from the Postgres service's variables | no |
| `LICENSING_DB_USER` | the database user | yes |
| `LICENSING_DB_PASSWORD` | the database password | **yes** |
| `LICENSING_CODE_PEPPER_BASE64` | base64 of ≥ 32 random bytes (from `KeyGenTool`) | **yes, back it up separately** |
| `LICENSING_SIGNING_KEY_ID` | e.g. `2026-a`; must equal the key id in the desktop's `trusted-keys.properties` | no |
| `LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64` | base64 of the **entire** `<kid>.key.pem` file | **yes** |
| `LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64` | base64 of `<kid>.pub.pem` | no |
| `LICENSING_VERIFY_ONLY_KEYS` | only during rotation: `kid=base64pem,kid2=base64pem` | no |
| `LICENSING_ISSUER` | `https://<your public domain>`, no trailing slash; must equal the desktop's `issuer` | no |
| `LICENSING_TRUSTED_PROXIES` | Java regex of the proxy addresses allowed to set `X-Forwarded-*` (section 4). **Required, no default.** | no |
| `LICENSING_ADMIN_CREDENTIALS_0_ID` | e.g. `ops` | no |
| `LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256` | 64-hex SHA-256 of the admin token (from `AdminTokenTool`); **never the token** | semi |
| `LICENSING_ADMIN_CREDENTIALS_0_SCOPES` | comma list of `LICENSE_ISSUE,LICENSE_READ,LICENSE_LIFECYCLE,AUDIT_READ` | no |

Never set: `SPRING_PROFILES_ACTIVE=dev`, `LICENSING_SECURITY_REQUIRE_HTTPS=false`, `LICENSING_SIGNING_ALLOW_EPHEMERAL=true`. The entrypoint refuses to start if any of them is present. There is no production profile file: the base `application.yml` is the production configuration (HTTPS required, no ephemeral key, no default secrets).

**Database variables.** **[docs, from a Railway community thread, not an official page]** the Postgres service exposes `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, and other services can reference them as `${{<Postgres service name>.PGHOST}}`. Railway's `DATABASE_URL` is not a JDBC URL, so build `LICENSING_DB_URL` as `jdbc:postgresql://${{<name>.PGHOST}}:${{<name>.PGPORT}}/${{<name>.PGDATABASE}}` and reference `PGUSER`/`PGPASSWORD` for the other two. Whether `PGHOST` is the private or the public host, and whether the connection needs `?sslmode=...`, is **[verify on first deploy]**: prefer the private network host, and if the database requires TLS add the sslmode the Railway database documentation specifies.

**Port.** The entrypoint listens on `LICENSING_PORT` if set, otherwise `PORT`, otherwise 8080. Railway's documentation pages I could read did not state how `PORT` is provided **[verify on first deploy]**. If the public domain returns 502 while the log says the server started, set `LICENSING_PORT` to the port the domain targets.

## 4. HTTPS and the trusted proxy (the part most likely to need adjustment)

The server refuses any request that did not arrive over TLS *as seen after* the proxy's `X-Forwarded-Proto` is applied, and Tomcat applies that header **only** for requests from `LICENSING_TRUSTED_PROXIES`. Railway's documentation I could read did not state which source addresses its edge uses, whether it sends `X-Forwarded-Proto`/`X-Forwarded-For`, or whether `PORT` is injected **[verify on first deploy]**. Two things depend on this setting:

- **Wrong (too narrow):** every request except `/actuator/health` is refused with `403 HTTPS_REQUIRED`. Fail-closed and visible.
- **Wrong in a quieter way:** the rate limiters key on the connection's remote address. If the proxy is not trusted, every customer shares the proxy's address, so one abuser can exhaust the activation limit for everyone and 10 bad admin tokens per minute lock the administrator out. **Required test:** send 11 requests with an invalid admin token from one network, then a valid admin request from a *different* network (for example a phone hotspot). It must succeed. A `429` means the real client address is not being recovered; fix `LICENSING_TRUSTED_PROXIES` before going live.

Starting value to try (an assumption, not a Railway fact): private and carrier-grade-NAT ranges, `10\..*|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\..*|172\.(1[6-9]|2[0-9]|3[01])\..*|192\.168\..*|fd[0-9a-f:]*|::1|127\..*`. Replace it with Railway's published edge ranges as soon as you have them. Never use a pattern that trusts every address (`.*`): the entrypoint rejects that form, because it would let any caller forge `X-Forwarded-Proto`.

## 5. First deploy, redeploy, migrations

1. Create the services and variables (sections 2–3). Deploy.
2. Read the deploy log. A healthy first start shows Flyway migrating the empty database to version 2 and `Started LicensingApplication`. A refusal prints `STARTUP REFUSED: <reason>` (exit code 78) and never prints a secret. **[docs]** the healthcheck path `/actuator/health` is used to confirm a deployment; the server exempts it from HTTPS enforcement.
3. Migrations run automatically at start (Flyway, `common` then `postgresql`). `V1` is the schema, `V2` makes `audit_event` append-only. Flyway records applied versions, so redeploys do not repeat them. Never edit an applied migration: add `V3__...sql`.
4. To redeploy: push a new version. Whether the previous container keeps serving until the new one passes its healthcheck (zero-downtime) is **[verify on first deploy]**; Railway's config reference lists an `overlapSeconds` setting but I did not confirm the default behaviour. To confirm migrations after a deploy, connect to the database and run `SELECT version, success FROM flyway_schema_history ORDER BY installed_rank;` (every row `success = t`).
5. Rebuilding the API service never touches stored licenses: they live only in PostgreSQL.

## 6. Operations

**Logs.** Use Railway's deploy logs. They contain no activation code, token, pepper or key. Storage failures log only the SQLState (the driver's error detail contains the failing row, including the customer's e-mail, and is deliberately not logged). If you add log shipping, keep it that way. `AdminAuthFilter` logs the requested path on rejected admin calls.

**Distinguishing an outage from an invalid license.** `GET /actuator/health` returning anything but `200 {"status":"UP"}` (or no answer, or 5xx) is a platform/database problem. A reachable API answering `401/403` with `INVALID_CREDENTIALS`, `LICENSE_SUSPENDED`, `LICENSE_REVOKED`, `LICENSE_EXPIRED` or `DEVICE_NOT_REGISTERED` is a license decision. The desktop treats an unreachable or 5xx server as "licensing unavailable" (new protected sessions are refused, a running one is not cut off) and a definite refusal as a denial (a running session is stopped).

**Rotating admin credentials.** Create a new token with `AdminTokenTool`. Add it as `LICENSING_ADMIN_CREDENTIALS_1_ID/_TOKEN_SHA256/_SCOPES` next to the old one, redeploy, and confirm the new token works with `verify-deployment.sh`. Then move the new credential into slot `0` (the entrypoint requires slot `0`), delete the `_1_` variables and redeploy; the old token stops working at that redeploy. If a token is exposed, do the same immediately and drop the old one at once.

**Rotating the signing key.** Follow `docs/KEY_ROTATION.md`, with these Railway specifics: generate the new pair offline with `KeyGenTool`; ship a desktop build trusting both public keys first; then set `LICENSING_SIGNING_KEY_ID`, `LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64`, `LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64` to the new key and put the old public key in `LICENSING_VERIFY_ONLY_KEYS` (`oldkid=base64pem`). Entitlements issued under the old key keep verifying until they expire (default 7 days). The private key is never given to the desktop.

**The pepper.** If `LICENSING_CODE_PEPPER_BASE64` is lost or changed, every unredeemed activation code stops working and cannot be recovered. Store it in your password manager, separately from the database backups.

**Backups and recovery.** Railway's backup features were not documented in the pages I could read, so check the current Railway documentation and enable whatever it offers, and independently take your own `pg_dump -Fc` of the licensing database on a schedule you control, stored encrypted and away from Railway. Restore into a **new, empty** database, check it (`SELECT count(*) FROM license;`, `flyway_schema_history`), then repoint `LICENSING_DB_URL` and redeploy. Do not drop or overwrite the production database to recover. After a restore, the signing key, pepper and admin hashes come from the environment, not the database.

## 7. Verifying the deployed service

Run from your own computer (never from the server). It needs `curl` and, for the key comparison, `base64`:

```
BASE_URL=https://<domain> ADMIN_TOKEN=<token> EXPECTED_KID=<kid> \
EXPECTED_PUBLIC_KEY_FILE=<kid>.pub.pem LIMITED_TOKEN=<read-only token> \
CONFIRM_ISSUE=yes TEST_EMAIL=<throw-away test address> deploy/verify-deployment.sh
```

It checks health, that plain HTTP is not served, that the advertised key id and public key equal the desktop's trusted key, that admin endpoints reject missing, invalid and under-scoped credentials and twelve path variations (`;x`, `%2e%2e`, double slash, trailing slash, and others) without data, that error bodies leak nothing, and, with `CONFIRM_ISSUE=yes`, issue → read → suspend → reinstate → revoke → audit. **Issuing stores a real test record for `TEST_EMAIL` and revocation is permanent: use a throw-away address.** The script was tested only against a local mock, not against this API.

Not covered by the script, and still **unverified** until done on Windows: activation with a device-key proof, entitlement signature verification, restart revalidation, wrong-key and device-limit refusals, expiry (time-based; cannot be forced through the API), offline refusal, the DSA HTTP guard, and all four mode-start gates. The rate-limit test in section 4 is also manual.

## 8. Desktop production configuration (separate from development)

The desktop reads `interview-assistant.licensing.base-url` and `issuer` from `application.yml` placeholders (`LICENSING_BASE_URL`, `LICENSING_ISSUER`), which end users will not have. A distributed build therefore needs the public values written into the packaged `application.yml`, and the server's **public** key in `src/main/resources/licensing/trusted-keys.properties` as `<kid>=<base64 public key>`. None of these is secret. Rules:

- `base-url` is the Railway `https://` URL and `issuer` equals the server's `LICENSING_ISSUER` exactly; the `kid` equals `LICENSING_SIGNING_KEY_ID`. Check with `EXPECTED_PUBLIC_KEY_FILE` above before building.
- Only the public key goes into the desktop. The private key never leaves the server environment.
- Enforcement cannot be switched off: with any of the three values missing, every protected mode is refused ("Licensing is not configured in this build"). A malformed key stops the application at start-up.
- Do not distribute the production-configured build until milestone B is reached. The packaging script has **no automated check** that these three values are present and consistent; verify them by hand until one is added.
