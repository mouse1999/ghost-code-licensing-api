# Phase 132 — Railway deployment and production verification

## Verdict

**Nothing was deployed. Milestone A (API deployed) not reached. Milestone B (ready for desktop enforcement) not reached.**
The mandatory pre-deployment gate failed, and Railway itself is unreachable from my environment. The spec says to finish only safe preparatory work in that case and not to claim a deployment; that is what this is. Do not switch any user or any distributed desktop build to an API on the strength of this report.

| Item | Status |
|---|---|
| `mvn -B clean verify`, licensing-api | **Blocked** (not run) |
| `mvn -B clean verify`, desktop | **Blocked** (not run) |
| Railway project, PostgreSQL service, deployment | **Not done** (no access) |
| Flyway against a deployed database | **Not done** |
| Real HTTP lifecycle against a deployed API | **Not done** |
| Windows activation against a deployed API | **Not done** |
| Deployment files, entrypoint, runbook, verification script | **Written; partly tested locally (below)** |

---

## 1. Pre-deployment gate: blocked, exact record

`mvn -q -B -DskipTests compile` in `licensing-api/` (retried this phase):

```
[FATAL] Non-resolvable parent POM for com.interviewassistant:licensing-api:0.1.0-SNAPSHOT: ...
org.springframework.boot:spring-boot-starter-parent:pom:4.1.0 (absent): Could not transfer artifact ...
from/to central (https://repo.maven.apache.org/maven2): repo.maven.apache.org: Name or service not known
```

Cause per the session proxy: `repo.maven.apache.org:443 — gateway answered 403 to CONNECT (policy denial)`. I did not route around it. Consequently `LicenseHttpGuard`, `LicenseWebConfiguration`, `AdminController` and `ApiExceptionHandler` have **still never been compiled against the real frameworks**, and no Spring startup or Flyway run happened. Phase 131's two uncompiled server edits remain uncompiled.

## 2. Railway: not reachable

The proxy also denies `backboard.railway.app:443` and `railway.com:443` (the same 403 policy denial). There is no Railway CLI, and I have no Railway credentials or project. So I did not and could not create a project, provision PostgreSQL, set variables, deploy, or read a log. I did not use the development profile or any workaround.

I could read parts of Railway's documentation through the search tools. Confirmed **[docs]**: config-as-code keys (`build.builder` = `RAILPACK`/`DOCKERFILE`, `dockerfilePath`, `deploy.healthcheckPath`, `healthcheckTimeout`, `restartPolicyType`, `restartPolicyMaxRetries`), "Railway always builds with a Dockerfile if one exists", free TLS certificates for public domains, and the Postgres variable names `PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE` (from a community thread, not an official page). **One thing worth knowing now:** that same page says config-as-code files are legacy, supported only until **2026-12-01**, four weeks away, so the dashboard should hold the same settings.

**Not stated in any page I could read, and therefore not assumed:** how `PORT` is provided, whether the edge sends `X-Forwarded-Proto`/`X-Forwarded-For`, the edge's source addresses, Railway's native backup features, zero-downtime redeploy behaviour, and whether `PGHOST` is the private or public host. Each is marked **[verify on first deploy]** in the runbook.

## 3. What I prepared (all in `licensing-api/`)

- `Dockerfile` + `.dockerignore`: multi-stage Maven/Temurin 21 build running the **full test suite** (no `-DskipTests`, so a failing test blocks deployment), JRE-only unprivileged runtime. **Untested**: no Docker daemon here.
- `docker-entrypoint.sh`: a fail-closed launcher. It refuses to start with the `dev` profile, disabled HTTPS, an ephemeral signing key, a non-`https` issuer, a non-PostgreSQL URL, a raw token where a hash is required, a placeholder hash, a trust-everything proxy pattern, a short pepper, an invalid key id, a bad or wrong-type PEM, or any missing required variable. It writes the signing key (delivered as an environment variable, since Railway has no secret files) to a mode-600 file in a mode-700 directory, removes the base64 copies from the server's environment, and binds `LICENSING_PORT`, else `PORT`, else 8080. It never prints a secret.
- `railway.json`: build/deploy settings using only documented keys.
- `docs/RAILWAY_DEPLOYMENT.md`: services, variables (names only), the trusted-proxy problem, first deploy, migrations, redeploy, log inspection, credential and signing-key rotation, backup and restore without touching production data, outage-versus-license distinction, desktop production configuration.
- `deploy/verify-deployment.sh`: black-box checks of a deployed API (below).
- `deploy/test-entrypoint.sh`: reproducible entrypoint tests.

No application code, framework version, policy or scope was changed this phase.

## 4. What was actually tested, and how

| Check | Environment | Result |
|---|---|---|
| Entrypoint: 3 launches + 17 refusals | `sh`/`dash` with a stub `java`, throw-away keys | 20/20 pass, **no secret value appeared in any output** |
| Entrypoint output accepted by the server's own `SigningKeyRing.load` (sign/verify probe, permission check) | real server crypto classes, keys from `KeyGenTool` and from `openssl` | loads; a mode-644 key is **refused**; a mismatched public key is **refused** |
| `verify-deployment.sh` logic | **local TLS mock written by me**, one correct mode, one with a planted `;x` path bypass and an error leak | correct mock: 32/32, exit 0; vulnerable mock: exit 1, flagged both planted bypasses, the 500, and the leaked internals; a token was never printed |
| Everything above against the real API, PostgreSQL, Spring or Railway | — | **not done** |

The checker run against a mock proves the script can tell good from bad. It says nothing about the real API. Two bugs in my own script were found and fixed by that test (a doubled `000000` status on connection failure, and a mock that lacked a limited-scope token).

## 5. Findings that matter for deployment

1. **The server has no Spring context test.** No `@SpringBootTest` exists in `licensing-api`, so a green `mvn verify` would not exercise bean wiring, `@ConfigurationProperties` binding or Flyway. The first real start is the first test of those. I did not add an untested context test that could block a build for the wrong reason.
2. **Trusted-proxy setting is a go-live gate.** The rate limiter keys on the connection's remote address, which equals the real client only when the proxy is in `LICENSING_TRUSTED_PROXIES`. If it is not, every customer shares one bucket: anyone can lock the administrator out with 10 bad tokens a minute, and 10 activations a minute are shared by all customers. The runbook gives a required two-network test; Railway's edge addresses are unknown to me. The entrypoint has no default for this variable on purpose.
3. **Signing key needs an environment-variable path.** The server reads the key only from a file and refuses a group/other-readable one; the entrypoint bridges this with no server code change (tested above).
4. **A production build of the desktop has no URL baked in.** `base-url` and `issuer` are read from `LICENSING_BASE_URL`/`LICENSING_ISSUER`, which end users will not have, and `trusted-keys.properties` is empty. Until all three are written into the packaged build, every protected mode is refused (designed fail-closed, tested on the shim in Phase 130). The packaging script has no automated check for this; the runbook lists the manual steps. I did not guess a URL.
5. **Single replica required** (in-memory rate limits and replay cache).
6. Config-as-code deprecation date (section 2).

## 6. Secrets and keys: what is and is not configured

None of the production secrets, signing keys, admin credentials, pepper or public keys has been generated, configured or deployed by me. The desktop's `trusted-keys.properties` is still empty. No private key, token or pepper was committed or printed (test keys were throw-away values in a temporary directory).

## 7. Outstanding blockers, with exact next steps

1. On a machine with Maven Central: `cd licensing-api && mvn -B clean verify`, then the same in the desktop project. Fix compile errors first in the four never-compiled files.
2. Generate production material **on your own machine**: `KeyGenTool <kid> <dir>` (private key, public key, pepper), `AdminTokenTool` (admin token and its hash). Keep the private key, pepper and token in a password manager.
3. Create the Railway project, a PostgreSQL service and the API service (root `licensing-api/`), set the variables in the runbook, generate a public domain, deploy.
4. Read the deploy log for the Flyway migration to version 2 and the start-up line; resolve every `[verify on first deploy]` item.
5. Run `deploy/verify-deployment.sh` (use a throw-away `TEST_EMAIL`), then the two-network rate-limit test.
6. Write the Railway URL, issuer and public key (matching key id) into the desktop build, rebuild on Windows, and run the activation, restart, suspend/revoke, offline and four-mode checks. Only then is the system ready for desktop enforcement.

I have not started Phase 133.
