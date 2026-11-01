#!/usr/bin/env bash
# Phase 134 verification runner (sandbox without Maven Central). Run as root (it uses `su postgres` for the throw-away cluster) or adapt.
# Everything is compiled with javac against test-only stand-ins: shim/ (JUnit-5 API subset), stubs/ (annotation-only Spring/Jakarta),
# pgbridge/ (minimal PostgreSQL wire-protocol JDBC driver), httpharness/ (HTTP server over the REAL controllers). See PHASE_134_REPORT.md.
set -uo pipefail
T="$(cd "$(dirname "$0")" && pwd)"; R="$T/.."; W="${WORK:-$(mktemp -d)}"; D="${DESKTOP:-$R/../merged}"; PORTAL="$R/src/main/resources/portal"
M="$W/shim"; mkdir -p "$W"/{shim,sc,st,stub,hh,pgb,dc,dct,dit}
javac -proc:none -d "$M" $(find "$T/shim/src" -name '*.java') 2>&1 | grep -v "Picked up"
javac -proc:none -d "$W/sc" $(find "$R/src/main/java/com/interviewassistant/licensing" -name '*.java' ! -path '*/web/*' ! -path '*/store/Jdbc*' ! -path '*/tools/*') 2>&1 | grep -v "Picked up\|^Note"
javac -proc:none -d "$W/sc" -cp "$W/sc" "$R"/src/main/java/com/interviewassistant/licensing/store/Jdbc*.java 2>&1 | grep -v "Picked up\|^Note"
javac -proc:none -d "$W/st" -cp "$W/sc:$M" $(find "$R/src/test/java" -name '*.java' ! -name 'JdbcLicenseStoreIT.java') 2>&1 | grep -v "Picked up\|^Note"
javac -proc:none -d "$W/pgb" "$T/pgbridge/PgBridgeDriver.java" 2>&1 | grep -v "Picked up"
WEB="$R/src/main/java/com/interviewassistant/licensing/web"
javac -proc:none -parameters -d "$W/stub" -cp "$W/sc" $(find "$T/stubs/src" -name '*.java') $WEB/Dtos.java $WEB/AdminController.java $WEB/ClientController.java $WEB/PortalController.java $WEB/LicensingProperties.java $WEB/ClientAddress.java 2>&1 | grep -v "Picked up"
javac -proc:none -parameters -d "$W/hh" -cp "$W/sc:$W/stub:$W/pgb" "$T/httpharness/HttpHarness.java" 2>&1 | grep -v "Picked up"
javac -proc:none -d "$W/dc" $(find $D/src/main/java/com/interviewassistant/licenseclient -name '*.java' ! -path '*/licenseclient/ui/*' ! -name LicenseHttpGuard.java ! -name LicenseSessionMonitor.java) $D/src/main/java/com/interviewassistant/session/InterviewMode.java $D/src/main/java/com/interviewassistant/credentials/CredentialStore.java $D/src/main/java/com/interviewassistant/credentials/CredentialStoreException.java 2>&1 | grep -v "Picked up\|^Note"
javac -proc:none -d "$W/dct" -cp "$W/dc:$M" $(find $D/src/test/java/com/interviewassistant/licenseclient/support -name '*.java') 2>&1 | grep -v "Picked up\|^Note"
javac -proc:none -parameters -d "$W/dit" -cp "$W/sc:$W/stub:$W/hh:$W/pgb:$W/dc:$W/dct:$M" $(find "$T/desktop-compat/src" -name '*.java') 2>&1 | grep -v "Picked up\|^Note"
echo "== 1. server tests, in-memory store"; java -cp "$W/sc:$W/st:$M" minirunner.MiniRunner "$W/st" 2>&1 | grep "====\|FAIL\|^  "
rm -rf /tmp/pgsrc && mkdir -p /tmp/pgsrc && cp -r "$R" /tmp/pgsrc/licensing-api && chmod -R a+rX /tmp/pgsrc && chown -R postgres /tmp/pgsrc
su postgres -c "/tmp/pgsrc/licensing-api/test-tools/pg-cluster.sh start" | tail -1
PGURL=jdbc:pgbridge://127.0.0.1:55434/postgres
echo "== 2. same server tests + PostgreSQL persistence tests, real JdbcLicenseStore on PostgreSQL"
(cd /tmp && java -Djdbc.drivers=pgbridge.PgBridgeDriver -Dlicensing.test.pgUrl=$PGURL -cp "$W/sc:$W/st:$M:$W/pgb" minirunner.MiniRunner "$W/st" 2>&1 | grep "====\|FAIL\|^  ")
echo "== 3. desktop client against real controllers + PostgreSQL"
for t in RealServerIntegrationTest EnforcementRealServerIntegrationTest Phase134LifecycleDesktopTest; do
  (cd /tmp && java -Djdbc.drivers=pgbridge.PgBridgeDriver -Dlicensing.test.pgUrl=$PGURL -Dlicensing.portalDir="$PORTAL" -cp "$W/dit:$W/sc:$W/stub:$W/hh:$W/pgb:$W/dc:$W/dct:$M" minirunner.MiniRunner "$W/dit" $t 2>&1 | grep "====\|FAIL\|^  "); done
echo "== 4. HTTP contract + real portal in Chromium"
run_harness() { # $1 = admin-auth-failure limit, rest = command
  lim=$1; shift
  java -Dharness.adminFailLimit=$lim -Djdbc.drivers=pgbridge.PgBridgeDriver -cp "$W/sc:$W/stub:$W/hh:$W/pgb" com.interviewassistant.licensing.web.HttpHarness 8181 $PGURL postgres "$W/hout" "$PORTAL" > "$W/run.log" 2>&1 &
  hp=$!; for i in $(seq 1 50); do grep -q "harness up" "$W/run.log" && break; sleep 0.2; done
  (cd "$T/portal-e2e" && HOUT="$W/hout/harness.json" NODE_PATH="$(npm root -g)" "$@"); rc=$?; kill $hp 2>/dev/null; wait $hp 2>/dev/null; cat "$W/run.log" >> "$W/harness.log"; return $rc; }
mkdir -p "$W/hout"; : > "$W/harness.log"
run_harness 1000 node contract.js | grep "passed\|FAIL"
run_harness 1000 node portal-e2e.js | grep "passed\|FAIL"
run_harness 10 node rl.js | tail -1
echo "-- secrets in the server log of the last two runs:"; grep -c -E "Bearer|activationCode|eyJ|[A-Za-z0-9_-]{43}" "$W/harness.log" || true; echo "(log lines: $(wc -l < "$W/harness.log"))"
echo "== 5. migrations (psql, not Flyway)"
su postgres -c "/tmp/pgsrc/licensing-api/test-tools/pg-migration-check.sh" 2>&1 | grep -c PASS; su postgres -c "/tmp/pgsrc/licensing-api/test-tools/pg-migration-check.sh" 2>&1 | grep FAIL
su postgres -c "/tmp/pgsrc/licensing-api/test-tools/pg-cluster.sh stop"
