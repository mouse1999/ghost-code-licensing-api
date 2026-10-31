#!/usr/bin/env bash
# Phase 132: black-box checks of a DEPLOYED licensing API. Run it from your own machine against the real https URL.
#
#   BASE_URL=https://licensing.example.com  ADMIN_TOKEN=ia_adm_...  EXPECTED_KID=2026-a \
#   [EXPECTED_PUBLIC_KEY_FILE=path/to/2026-a.pub.pem] [LIMITED_TOKEN=<token whose scopes lack LICENSE_ISSUE>] \
#   [CONFIRM_ISSUE=yes TEST_EMAIL=you+test@example.com]  ./verify-deployment.sh
#
# Without CONFIRM_ISSUE=yes it only reads. WITH it, it issues ONE real test license (a stored record for TEST_EMAIL), then
# suspends, reinstates and revokes it - revocation is permanent, so use a throw-away test e-mail, never a customer's.
# Tokens go to curl through a private header file, never the command line, and are never printed.
# NOT covered here (needs the desktop): activation with a device-key proof, entitlement signature, restart validation, expiry.
set -u
: "${BASE_URL:?set BASE_URL (https://...)}"; : "${ADMIN_TOKEN:?set ADMIN_TOKEN}"; : "${EXPECTED_KID:?set EXPECTED_KID}"
case "$BASE_URL" in https://*) ;; *) echo "BASE_URL must be https://"; exit 2 ;; esac
BASE_URL="${BASE_URL%/}"; umask 077; W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
printf 'Authorization: Bearer %s\n' "$ADMIN_TOKEN" > "$W/admin.h"
[ -n "${LIMITED_TOKEN:-}" ] && printf 'Authorization: Bearer %s\n' "$LIMITED_TOKEN" > "$W/limited.h"
printf 'Authorization: Bearer ia_adm_%s\n' "not-a-real-token-0000000000000000" > "$W/bad.h"
pass=0; failn=0; skip=0
ok()   { pass=$((pass+1)); printf 'PASS  %s\n' "$1"; }
bad()  { failn=$((failn+1)); printf 'FAIL  %s\n' "$1"; }
skp()  { skip=$((skip+1)); printf 'SKIP  %s\n' "$1"; }
# req METHOD PATH [header-file|-] [json-body] [extra curl args...]  -> sets CODE, BODY (file $W/body)
req() { m="$1"; p="$2"; h="${3:--}"; d="${4:-}"; shift 4 2>/dev/null || shift $#
  args=(-sS --max-time 30 --path-as-is -X "$m" -o "$W/body" -w '%{http_code}' -H 'Accept: application/json')
  [ "$h" != "-" ] && args+=(-H "@$h")
  [ -n "$d" ] && args+=(-H 'Content-Type: application/json' --data "$d")
  CODE=$(curl "${args[@]}" "$@" "$BASE_URL$p" 2>/dev/null); [ -n "$CODE" ] || CODE=000; }   # curl -w already prints 000 on a failed connection
code_in() { case " $2 " in *" $1 "*) return 0 ;; esac; return 1; }

echo "== service"
req GET /actuator/health; [ "$CODE" = 200 ] && grep -q '"UP"' "$W/body" && ok "health is UP" || bad "health: HTTP $CODE (an outage, not a license problem)"
c=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "http://${BASE_URL#https://}/api/v1/entitlement-keys" 2>/dev/null); [ -n "$c" ] || c=000
code_in "$c" "301 302 307 308 403 000 404" && ok "plain http is not served as data (HTTP $c)" || bad "plain http answered $c"

echo "== signing key"
req GET /api/v1/entitlement-keys
if [ "$CODE" = 200 ] && grep -q "\"kid\" *: *\"$EXPECTED_KID\"" "$W/body"; then ok "server advertises kid $EXPECTED_KID"; else bad "kid $EXPECTED_KID not advertised (HTTP $CODE)"; fi
if [ -n "${EXPECTED_PUBLIC_KEY_FILE:-}" ]; then
  want=$(grep -v '^-----' "$EXPECTED_PUBLIC_KEY_FILE" | tr -d '\n' | base64 -d 2>/dev/null | tail -c 32 | base64 -w0 | tr '+/' '-_' | tr -d '=')
  grep -q "\"x\" *: *\"$want\"" "$W/body" && ok "server public key equals the desktop's trusted key" || bad "server public key differs from the desktop's trusted key"
else skp "public key comparison (set EXPECTED_PUBLIC_KEY_FILE)"; fi

echo "== admin authentication (no credential, bad credential, path variations)"
req GET /api/v1/admin/licenses; code_in "$CODE" "401" && grep -q UNAUTHENTICATED "$W/body" && ok "no token -> 401" || bad "no token -> HTTP $CODE"
req GET /api/v1/admin/licenses "$W/bad.h"; [ "$CODE" = 401 ] && ok "invalid token -> 401" || bad "invalid token -> HTTP $CODE"
for p in "/api/v1/admin;x=1/licenses" "/api/v1/admin/;x/licenses" "/api/v1/foo/%2e%2e/admin/licenses" "/api/v1/foo/../admin/licenses" \
         "//api/v1/admin/licenses" "/api/v1/admin%2flicenses" "/api/v1/admin/licenses/" "/api/v1/admin/licenses.json" "/api/v1/Admin/licenses" \
         "/api/v1/admin/%2e/licenses" "/api/v1/admin/licenses;jsessionid=x" "/api/v1/./admin/licenses"; do
  req GET "$p"
  if code_in "$CODE" "400 401 403 404 405"; then ok "no data without a token: $p -> $CODE"; else bad "BYPASS SUSPECTED: $p -> HTTP $CODE"; fi
done
req POST /api/v1/admin/licenses - '{"customerEmail":"x@example.com","paymentVerified":true,"policy":{"deviceLimit":1,"rights":["DSA"]}}' -H 'Idempotency-Key: aaaaaaaaaaaaaaaaaaaa'
code_in "$CODE" "401" && ok "issuing without a token -> 401" || bad "issuing without a token -> HTTP $CODE"
if [ -n "${LIMITED_TOKEN:-}" ]; then
  req POST /api/v1/admin/licenses "$W/limited.h" '{"customerEmail":"x@example.com","paymentVerified":true,"policy":{"deviceLimit":1,"rights":["DSA"]}}' -H 'Idempotency-Key: bbbbbbbbbbbbbbbbbbbb'
  [ "$CODE" = 403 ] && grep -q FORBIDDEN "$W/body" && ok "token without LICENSE_ISSUE -> 403" || bad "token without LICENSE_ISSUE -> HTTP $CODE"
else skp "scope check (set LIMITED_TOKEN)"; fi

echo "== client endpoints cannot do admin work, errors are generic"
req POST /api/v1/client/activate - '{}'; code_in "$CODE" "400 401" && ok "empty activation refused ($CODE)" || bad "empty activation -> HTTP $CODE"
grep -Eq 'Exception|at com\.|org\.springframework|SQLState|stack' "$W/body" && bad "error body leaks internals" || ok "error body is generic"
req GET /api/v1/does-not-exist; grep -Eq 'Whitelabel|Exception|at com\.' "$W/body" && bad "unknown route leaks a framework page" || ok "unknown route is generic ($CODE)"
req POST /api/v1/client/licenses - '{}'; code_in "$CODE" "404 405 401 403" && ok "no issuing route under /client ($CODE)" || bad "/client/licenses -> HTTP $CODE"

echo "== lifecycle (issue, read, suspend, reinstate, revoke) and audit"
if [ "${CONFIRM_ISSUE:-}" = yes ] && [ -n "${TEST_EMAIL:-}" ]; then
  key="p132-$(date +%s)-$RANDOM$RANDOM"
  req POST /api/v1/admin/licenses "$W/admin.h" "{\"customerEmail\":\"$TEST_EMAIL\",\"paymentVerified\":true,\"paymentReference\":\"phase132-test\",\"policy\":{\"deviceLimit\":1,\"validityDays\":30,\"rights\":[\"LIVE\",\"DSA\"],\"activationWindowDays\":7}}" -H "Idempotency-Key: $key"
  id=$(sed -n 's/.*"license" *: *{[^}]*"id" *: *"\([0-9a-f-]\{36\}\)".*/\1/p' "$W/body" | head -1)
  if [ "$CODE" = 201 ] && [ -n "$id" ]; then ok "issued test license (code shown once by the API, not printed here)"; else bad "issue -> HTTP $CODE"; id=""; fi
  if [ -n "$id" ]; then
    req GET "/api/v1/admin/licenses/$id" "$W/admin.h"; grep -q '"PENDING"' "$W/body" && ok "read: PENDING" || bad "read -> HTTP $CODE"
    req POST "/api/v1/admin/licenses/$id/suspend" "$W/admin.h" '{"reason":"phase132 test"}'; grep -q '"SUSPENDED"' "$W/body" && ok "suspend" || bad "suspend -> HTTP $CODE"
    req POST "/api/v1/admin/licenses/$id/reinstate" "$W/admin.h" '{"reason":"phase132 test"}'; grep -q '"PENDING"' "$W/body" && ok "reinstate (back to PENDING: never activated)" || bad "reinstate -> HTTP $CODE"
    req POST "/api/v1/admin/licenses/$id/revoke" "$W/admin.h" '{"reason":"phase132 test"}'; grep -q '"REVOKED"' "$W/body" && ok "revoke" || bad "revoke -> HTTP $CODE"
    req POST "/api/v1/admin/licenses/$id/revoke" "$W/admin.h" '{}'; [ "$CODE" = 409 ] && ok "second revoke refused (409)" || bad "second revoke -> HTTP $CODE"
    req GET "/api/v1/admin/licenses/$id/audit" "$W/admin.h"; n=$(grep -o '"action"' "$W/body" | wc -l); [ "$CODE" = 200 ] && [ "$n" -ge 4 ] && ok "audit trail has $n events" || bad "audit -> HTTP $CODE, $n events"
    req GET "/api/v1/admin/licenses/$id/audit" "$W/admin.h"; grep -Eq 'ia_adm_|activationCode|[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' "$W/body" && bad "audit exposes a credential" || ok "audit shows no credential"
  fi
else skp "lifecycle (set CONFIRM_ISSUE=yes and TEST_EMAIL; it stores a real test record and revokes it)"; fi

echo; echo "passed=$pass failed=$failn skipped=$skip"; [ "$failn" -eq 0 ]
