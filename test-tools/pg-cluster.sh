#!/usr/bin/env bash
# Starts (start) or stops (stop) a throw-away PostgreSQL 16 cluster for the Phase 134 integration checks and builds the migrated
# template database "lic_tmpl" (V1 + V2 applied with psql, standing in for Flyway). Must run as a non-root user.
set -euo pipefail
PGBIN="${PGBIN:-/usr/lib/postgresql/16/bin}"; PORT="${PGPORT:-55434}"; D="${PGDIR:-/tmp/pg134}"
M="$(cd "$(dirname "$0")/.." && pwd)/src/main/resources/db/migration"
case "${1:-}" in
 start)
  rm -rf "$D"; mkdir -p "$D"; "$PGBIN/initdb" -D "$D/data" -A trust -E UTF8 >/dev/null
  "$PGBIN/pg_ctl" -D "$D/data" -o "-p $PORT -k $D -c listen_addresses=127.0.0.1 -c max_connections=200" -l "$D/pg.log" -w start >/dev/null
  P="psql -h 127.0.0.1 -p $PORT -U $(id -un) -X -q -v ON_ERROR_STOP=1"
  $P -d postgres -c "CREATE DATABASE lic_tmpl"
  for f in "$M"/common/V1__licensing_core.sql "$M"/postgresql/V2__audit_append_only.sql; do $P -d lic_tmpl -f "$f"; done
  echo "ready on 127.0.0.1:$PORT user $(id -un)";;
 stop) "$PGBIN/pg_ctl" -D "$D/data" -m immediate stop >/dev/null 2>&1 || true;;
 *) echo "usage: $0 start|stop"; exit 2;;
esac
