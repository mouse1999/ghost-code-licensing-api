#!/usr/bin/env bash
# Tests docker-entrypoint.sh with a stub `java` and throw-away keys. Needs bash, openssl (Ed25519), base64, sha256sum. Changes nothing outside a temp dir.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"; EP="$HERE/docker-entrypoint.sh"; T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/out"
openssl genpkey -algorithm ed25519 -out "$T/k.pem" 2>/dev/null; openssl pkey -in "$T/k.pem" -pubout -out "$T/p.pem" 2>/dev/null
PRIV=$(base64 -w0 "$T/k.pem"); PUB=$(base64 -w0 "$T/p.pem"); PEPPER=$(head -c 32 /dev/urandom | base64 -w0); TOK=$(printf 'throwaway' | sha256sum | cut -d' ' -f1)
cat > "$T/bin/java" <<'EOS'
#!/bin/sh
echo "JAVA-STARTED port=$LICENSING_PORT keymode=$(stat -c %a "$LICENSING_SIGNING_PRIVATE_KEY_FILE") dirmode=$(stat -c %a "$(dirname "$LICENSING_SIGNING_PRIVATE_KEY_FILE")") b64inenv=${LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64:+LEAK}"
EOS
chmod +x "$T/bin/java"
base=("PATH=$T/bin:/usr/bin:/bin" "LICENSING_DB_URL=jdbc:postgresql://db:5432/l" "LICENSING_DB_USER=u" "LICENSING_DB_PASSWORD=pw-SECRET" "LICENSING_CODE_PEPPER_BASE64=$PEPPER"
 "LICENSING_SIGNING_KEY_ID=2026-t" "LICENSING_ISSUER=https://licensing.example.com" 'LICENSING_TRUSTED_PROXIES=10\..*' "LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64=$PRIV"
 "LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64=$PUB" "LICENSING_ADMIN_CREDENTIALS_0_ID=ops" "LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256=$TOK" "LICENSING_ADMIN_CREDENTIALS_0_SCOPES=LICENSE_ISSUE")
pass=0; fail=0
t() { exp="$1"; name="$2"; shift 2; out=$(env -i "${base[@]}" "$@" sh "$EP" 2>&1); rc=$?
  leak=0; for s in "pw-SECRET" "$PEPPER" "$TOK" "$PRIV" "BEGIN PRIVATE"; do case "$out" in *"$s"*) leak=1 ;; esac; done
  want=78; [ "$exp" = ok ] && want=0
  if [ $rc -eq $want ] && [ $leak -eq 0 ]; then pass=$((pass+1)); r=PASS; else fail=$((fail+1)); r="FAIL(rc=$rc leak=$leak)"; fi
  printf '%-14s %-44s %s\n' "$r" "$name" "$(printf '%s' "$out" | head -1 | cut -c1-90)"; }
t ok "happy path, platform PORT" PORT=3456
t ok "explicit LICENSING_PORT wins" PORT=3456 LICENSING_PORT=9000
t ok "verify-only key accepted" "LICENSING_VERIFY_ONLY_KEYS=2025-a=$PUB"
t no "dev profile" SPRING_PROFILES_ACTIVE=dev
t no "dev among profiles" SPRING_PROFILES_ACTIVE=prod,dev
t no "HTTPS enforcement off" LICENSING_SECURITY_REQUIRE_HTTPS=false
t no "ephemeral signing key" LICENSING_SIGNING_ALLOW_EPHEMERAL=true
t no "http issuer" LICENSING_ISSUER=http://licensing.example.com
t no "issuer trailing slash" LICENSING_ISSUER=https://licensing.example.com/
t no "non-postgres db url" LICENSING_DB_URL=mysql://x
t no "raw token instead of hash" LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256=ia_adm_raw
t no "placeholder zero hash" LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256=$(printf '0%.0s' $(seq 64))
t no "trust-everything proxies" 'LICENSING_TRUSTED_PROXIES=.*'
t no "short pepper" LICENSING_CODE_PEPPER_BASE64=c2hvcnQ=
t no "bad key id" 'LICENSING_SIGNING_KEY_ID=../evil'
t no "non-base64 private key" 'LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64=!!!'
t no "public key given as private" "LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64=$PUB"
t no "missing DB password" LICENSING_DB_PASSWORD=
t no "non-numeric port" PORT=abc
t no "verify-only path traversal" "LICENSING_VERIFY_ONLY_KEYS=../../x=$PUB"
echo; echo "passed=$pass failed=$fail"; [ $fail -eq 0 ]
