#!/usr/bin/env bash
# Phase 134: applies the migrations with psql (NOT Flyway) to (a) a clean database and (b) an existing V1 database that already holds
# data, then checks that data survives and the V2 append-only guarantees hold. Requires the cluster from pg-cluster.sh (port PGPORT).
set -euo pipefail
PORT="${PGPORT:-55434}"; M="$(cd "$(dirname "$0")/.." && pwd)/src/main/resources/db/migration"; U="$(id -un)"
P="psql -h 127.0.0.1 -p $PORT -U $U -X -q -t -A -v ON_ERROR_STOP=1"
FAIL=0; check(){ if [ "$2" = "$3" ]; then echo "PASS $1"; else echo "FAIL $1: expected [$3] got [$2]"; FAIL=1; fi; }
$P -d postgres -c "DROP DATABASE IF EXISTS mig_clean" -c "DROP DATABASE IF EXISTS mig_upgrade" -c "CREATE DATABASE mig_clean" -c "CREATE DATABASE mig_upgrade"
ls "$M"/common "$M"/postgresql | tr '\n' ' '; echo
# (a) clean
for f in "$M"/common/V1__licensing_core.sql "$M"/postgresql/V2__audit_append_only.sql; do $P -d mig_clean -f "$f"; done
check "clean database: all tables present" "$($P -d mig_clean -c "select string_agg(table_name,',' order by table_name) from information_schema.tables where table_schema='public'")" "activation_credential,audit_event,device_registration,issuance_request,license"
$P -d mig_clean -c "INSERT INTO audit_event (occurred_at,actor,action,license_id,outcome,detail) VALUES (now(),'t','SEED',NULL,'SUCCESS','seed')"   # row-level guards need a row to act on
# (b) existing V1 database with data, then V2
$P -d mig_upgrade -f "$M/common/V1__licensing_core.sql"
$P -d mig_upgrade -c "INSERT INTO license (id,customer_email,status,device_limit,rights,activation_window_days,created_at,activation_deadline,updated_at) VALUES ('00000000-0000-0000-0000-0000000000aa','old@example.com','PENDING',1,'LIVE',30,now(),now()+interval '30 days',now())" \
  -c "INSERT INTO audit_event (occurred_at,actor,action,license_id,outcome,detail) VALUES (now(),'admin:x','LICENSE_ISSUED','00000000-0000-0000-0000-0000000000aa','SUCCESS','pre-V2 row')"
check "pre-V2 audit rows are mutable (V2 not yet applied)" "$($P -d mig_upgrade -c "update audit_event set detail='edited' returning detail")" "edited"
$P -d mig_upgrade -c "update audit_event set detail='pre-V2 row'"
$P -d mig_upgrade -f "$M/postgresql/V2__audit_append_only.sql"
check "upgrade keeps the license row" "$($P -d mig_upgrade -c "select customer_email from license")" "old@example.com"
check "upgrade keeps the audit row" "$($P -d mig_upgrade -c "select detail from audit_event")" "pre-V2 row"
for db in mig_clean mig_upgrade; do
  for sql in "UPDATE audit_event SET detail='x'" "DELETE FROM audit_event" "TRUNCATE audit_event"; do
    $P -d $db -c "$sql" >/dev/null 2>&1 && { echo "FAIL $db not append-only: $sql"; FAIL=1; } || echo "PASS $db refuses: $sql"; done
  $P -d $db -c "INSERT INTO audit_event (occurred_at,actor,action,license_id,outcome,detail) VALUES (now(),'t','X',NULL,'SUCCESS','new')" && echo "PASS $db still accepts appends"
done
exit $FAIL
