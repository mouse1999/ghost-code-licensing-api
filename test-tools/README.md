# Phase 134 test tooling (sandbox without Maven Central)

None of this ships with the product and none of it replaces `mvn verify`. It exists so that as much as possible could be executed for real
while Maven Central, npm and PyPI were unreachable.

| Folder | What it is | What it is NOT |
|---|---|---|
| `pgbridge/` | ~200-line JDBC driver speaking the PostgreSQL wire protocol (trust auth, simple queries, client-side parameter substitution) | pgjdbc. It proves nothing about server-side binding, SSL, pooling or driver quirks |
| `httpharness/` | JDK HTTP server dispatching to the REAL `AdminController`/`ClientController`/`Dtos` and services on PostgreSQL; routing/arg binding read from the controllers' own annotations; small JSON mapper; small Bean-Validation interpreter; copies of the two filters' and the exception handler's behaviour | Spring MVC, Jackson, Hibernate Validator, or the real filters |
| `stubs/` | annotation-only Spring/Jakarta types so the web classes compile | Spring |
| `shim/` | JUnit-5 API subset + `MiniRunner` | JUnit |
| `desktop-compat/` | the Phase 129/130 desktop-against-server tests, re-pointed at the harness, plus `Phase134LifecycleDesktopTest` | Windows/DPAPI |
| `portal-e2e/` | Node/Playwright: `contract.js` (HTTP contract, scopes, validation, idempotency, error safety), `portal-e2e.js` (the real portal in Chromium), `rl.js` (admin lockout) | |
| `pg-cluster.sh`, `pg-migration-check.sh` | throw-away PostgreSQL 16 cluster; V1/V2 applied with psql (not Flyway), upgrade-with-data check | Flyway |

`run-all.sh` builds and runs everything (needs JDK 21, PostgreSQL 16 binaries, Node + Playwright, root for `su postgres`, and the desktop project at `../merged` or `DESKTOP=`).
The server tests also run on a real database under Maven: set `-Dlicensing.test.pgUrl=jdbc:postgresql://host:5432/postgres` (and `licensing.test.pgUser`) with a migrated template database `lic_tmpl`; `PgSupport`/`PostgresStoreTest` then use the real pgjdbc driver. Without the property they do nothing.
