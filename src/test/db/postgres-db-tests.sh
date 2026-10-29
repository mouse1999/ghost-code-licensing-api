#!/usr/bin/env bash
# Database-level tests against a REAL PostgreSQL server. Run as a PostgreSQL superuser (e.g. the "postgres" OS user):
#   ./postgres-db-tests.sh run       creates database lic_dbtest, applies the real migrations, runs every check
#   ./postgres-db-tests.sh verify    after you restart the server: checks the data written by "run" is still there
# The SQL statements below are copied verbatim from JdbcLicenseStore (reserveDeviceSlot, updateLicense, insertDevice ...).
set -u
DB=lic_dbtest
MIG="$(cd "$(dirname "$0")/../../main/resources/db/migration" && pwd)"
PASS=0; FAIL=0
q()   { psql -X -q -t -A -v ON_ERROR_STOP=1 -d "$DB" -c "$1" 2>&1; }
ok()  { PASS=$((PASS+1)); echo "PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL  $1  ($2)"; }
expect_eq()  { [ "$2" = "$3" ] && ok "$1" || bad "$1" "expected '$3' got '$2'"; }
expect_err() { # name, sql, pattern
  out=$(q "$2"); echo "$out" | grep -qi "$3" && ok "$1" || bad "$1" "no error matching '$3': $out"; }

if [ "${1:-}" = "verify" ]; then
  expect_eq "rows survive a server restart (licenses)" "$(q "select count(*) from license")" "6"
  expect_eq "rows survive a server restart (audit)"    "$(q "select count(*) from audit_event")" "$(cat /tmp/lic_audit_count 2>/dev/null)"
  expect_eq "device counter survives restart"          "$(q "select active_device_count from license where customer_email='race@example.com'")" "3"
  expect_err "append-only trigger still present after restart" "delete from audit_event" "append-only"
  echo "==== verify: $((PASS+FAIL)) checks, $PASS passed, $FAIL failed ===="; [ $FAIL -eq 0 ]; exit $?
fi

psql -X -q -c "drop database if exists $DB" -c "create database $DB" >/dev/null 2>&1
for f in "$MIG"/common/V1__*.sql "$MIG"/postgresql/V2__*.sql; do
  psql -X -q -v ON_ERROR_STOP=1 -d "$DB" -f "$f" >/dev/null 2>&1 && ok "migration applies: $(basename "$f")" || bad "migration applies: $(basename "$f")" "error"
done

L1=11111111-1111-1111-1111-111111111111
NOW="now()"
ins() { # id email limit
  q "insert into license (id,customer_email,status,device_limit,validity_days,rights,activation_window_days,created_at,activation_deadline,updated_at) values ('$1','$2','PENDING',$3,30,'LIVE',30,$NOW,$NOW + interval '30 days',$NOW)"; }
cred() { q "insert into activation_credential (license_id,code_hash,created_at) values ('$1','$2',$NOW)"; }
H1=$(printf 'a%.0s' $(seq 64)); H2=$(printf 'b%.0s' $(seq 64)); THUMB=$(printf 'c%.0s' $(seq 64))

# ------------------------------------------------------------ constraints
ins $L1 one@example.com 1 >/dev/null; cred $L1 $H1 >/dev/null
L2=22222222-2222-2222-2222-222222222222; ins $L2 two@example.com 2 >/dev/null
expect_err "credential hash is globally unique" "insert into activation_credential values ('$L2','$H1',$NOW)" "unique\|duplicate"
cred $L2 $H2 >/dev/null
expect_err "one credential per license"        "insert into activation_credential values ('$L2','$(printf 'd%.0s' $(seq 64))',$NOW)" "unique\|duplicate"
expect_err "credential needs an existing license" "insert into activation_credential values ('99999999-9999-9999-9999-999999999999','$(printf 'e%.0s' $(seq 64))',$NOW)" "foreign key"
expect_err "e-mail must be stored lower-case"   "$(echo "insert into license (id,customer_email,status,device_limit,rights,activation_window_days,created_at,activation_deadline,updated_at) values ('33333333-3333-3333-3333-333333333333','UP@Example.com','PENDING',1,'LIVE',30,$NOW,$NOW,$NOW)")" "ck_license_email_lower"
expect_err "status must be a known value"       "update license set status='HACKED' where id='$L1'" "ck_license_status"
expect_err "device limit cannot be 0"           "update license set device_limit=0 where id='$L1'" "ck_license_device_limit\|ck_license_device_count"
expect_err "device limit cannot exceed 10"      "update license set device_limit=11 where id='$L1'" "ck_license_device_limit"
expect_err "active counter cannot exceed limit (CHECK)" "update license set active_device_count=2 where id='$L1'" "ck_license_device_count"
expect_err "ACTIVE requires an activation time" "update license set status='ACTIVE' where id='$L1'" "ck_license_activated"
q "insert into device_registration values ('aaaaaaaa-0000-0000-0000-000000000001','$L1','pk','$THUMB',null,'x',$NOW,'ACTIVE',null)" >/dev/null
expect_err "a device key registers once per license" "insert into device_registration values ('aaaaaaaa-0000-0000-0000-000000000002','$L1','pk','$THUMB',null,'x',$NOW,'ACTIVE',null)" "uq_device_license_key\|unique"
expect_err "device needs an existing license"   "insert into device_registration values ('aaaaaaaa-0000-0000-0000-000000000003','99999999-9999-9999-9999-999999999999','pk','$THUMB',null,'x',$NOW,'ACTIVE',null)" "foreign key"
expect_err "audit outcome is constrained"       "insert into audit_event (occurred_at,actor,action,outcome,detail) values ($NOW,'a','X','MAYBE','')" "ck_audit_outcome"

# ------------------------------------------------------------ concurrency: device slots (SQL of JdbcLicenseStore.reserveDeviceSlot)
L3=33333333-3333-3333-3333-333333333330; ins $L3 race@example.com 3 >/dev/null
RES="update license set active_device_count = active_device_count + 1, updated_at = $NOW, version = version + 1 where id = '$L3' and status in ('PENDING','ACTIVE') and active_device_count < device_limit returning 1"
rm -f /tmp/lic_slot_*; for i in $(seq 40); do ( psql -X -q -t -A -d "$DB" -c "$RES" > /tmp/lic_slot_$i 2>&1 ) & done; wait
WON=$(cat /tmp/lic_slot_* | grep -c '^1$'); LOST=$(find /tmp -maxdepth 1 -name 'lic_slot_*' -empty | wc -l)
expect_eq "40 parallel sessions: exactly 3 slots granted" "$WON" "3"
expect_eq "40 parallel sessions: 37 refused, none errored" "$LOST" "37"
expect_eq "final counter equals the limit"  "$(q "select active_device_count from license where id='$L3'")" "3"

# a suspended/revoked license grants no slot even if the counter has room
L4=44444444-4444-4444-4444-444444444440; ins $L4 sus@example.com 3 >/dev/null; q "update license set status='SUSPENDED' where id='$L4'" >/dev/null
expect_eq "no slot for a SUSPENDED license" "$(q "update license set active_device_count = active_device_count + 1 where id = '$L4' and status in ('PENDING','ACTIVE') and active_device_count < device_limit returning 1")" ""

# ------------------------------------------------------------ concurrency: optimistic version (JdbcLicenseStore.updateLicense)
L5=55555555-5555-5555-5555-555555555550; ins $L5 ver@example.com 1 >/dev/null
UPD="update license set status='SUSPENDED', suspended_at=$NOW, updated_at=$NOW, version = version + 1 where id='$L5' and version = 0 returning 1"
rm -f /tmp/lic_ver_*; for i in $(seq 25); do ( psql -X -q -t -A -d "$DB" -c "$UPD" > /tmp/lic_ver_$i 2>&1 ) & done; wait
expect_eq "25 parallel updates at version 0: exactly 1 wins" "$(cat /tmp/lic_ver_* | grep -c '^1$')" "1"
expect_eq "version advanced exactly once" "$(q "select version from license where id='$L5'")" "1"

# ------------------------------------------------------------ concurrency: same device key registered in parallel
L6=66666666-6666-6666-6666-666666666660; ins $L6 dup@example.com 5 >/dev/null
rm -f /tmp/lic_dev_*; for i in $(seq 15); do
  ( psql -X -q -d "$DB" -c "insert into device_registration values (gen_random_uuid(),'$L6','pk','$THUMB',null,'x',$NOW,'ACTIVE',null)" > /tmp/lic_dev_$i 2>&1 ) & done; wait
expect_eq "15 parallel registrations of one key: exactly 1 row" "$(q "select count(*) from device_registration where license_id='$L6'")" "1"
expect_eq "the other 14 hit the unique constraint (SQLSTATE 23505)" "$(cat /tmp/lic_dev_* | grep -ci 'duplicate key')" "14"

# ------------------------------------------------------------ concurrency: identity ids under parallel audit writes
rm -f /tmp/lic_aud_*; for i in $(seq 30); do ( psql -X -q -d "$DB" -c "insert into audit_event (occurred_at,actor,action,license_id,outcome,detail) values ($NOW,'t','ACTIVATION','$L1','SUCCESS','n=$i')" > /tmp/lic_aud_$i 2>&1 ) & done; wait
expect_eq "30 parallel audit inserts all stored" "$(q "select count(*) from audit_event where actor='t'")" "30"
expect_eq "audit ids are unique" "$(q "select count(distinct id) from audit_event")" "$(q "select count(*) from audit_event")"

# ------------------------------------------------------------ audit trail is append-only (V2 triggers)
expect_err "audit UPDATE is rejected"   "update audit_event set detail='tampered'" "append-only"
expect_err "audit DELETE is rejected"   "delete from audit_event" "append-only"
expect_err "audit TRUNCATE is rejected" "truncate audit_event" "append-only"
expect_eq  "audit rows unchanged after the attempts" "$(q "select count(*) from audit_event where detail='tampered'")" "0"

# ------------------------------------------------------------ what the database holds for a credential
expect_eq "credential column holds only a 64-char hash" "$(q "select max(length(code_hash)) from activation_credential")" "64"

q "select count(*) from audit_event" > /tmp/lic_audit_count
q "select count(*) from license" >/dev/null
echo "==== run: $((PASS+FAIL)) checks, $PASS passed, $FAIL failed ===="; [ $FAIL -eq 0 ]
