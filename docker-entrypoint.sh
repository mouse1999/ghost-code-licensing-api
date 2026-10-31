#!/bin/sh
# Production entrypoint for the licensing API (Phase 132).
#
# Fail-closed launcher: it refuses to start the server when required production configuration is missing or unsafe, and it turns
# the secrets that a platform delivers as environment variables into the permission-restricted key files the server requires.
# No secret value is ever printed. Exit code 78 = configuration error.
set -eu
umask 077

fail() { echo "STARTUP REFUSED: $1" >&2; exit 78; }
need() { eval "v=\${$1:-}"; [ -n "$v" ] || fail "required variable $1 is not set"; }

# --- never run development settings in production -------------------------------------------------------------------------------
case ",${SPRING_PROFILES_ACTIVE:-}," in *,dev,*) fail "the 'dev' profile must not be active in production" ;; esac
for name in LICENSING_SECURITY_REQUIRE_HTTPS; do
  eval "v=\${$name:-true}"
  case "$v" in true|TRUE|True) ;; *) fail "$name must not disable HTTPS enforcement" ;; esac
done
for name in LICENSING_SIGNING_ALLOW_EPHEMERAL LICENSING_SIGNING_ALLOWEPHEMERAL; do
  eval "v=\${$name:-false}"
  case "$v" in false|FALSE|False) ;; *) fail "a throw-away signing key is not allowed in production" ;; esac
done

# --- required configuration -----------------------------------------------------------------------------------------------------
for name in LICENSING_DB_URL LICENSING_DB_USER LICENSING_DB_PASSWORD LICENSING_CODE_PEPPER_BASE64 LICENSING_SIGNING_KEY_ID \
            LICENSING_ISSUER LICENSING_TRUSTED_PROXIES LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64 LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64 \
            LICENSING_ADMIN_CREDENTIALS_0_ID LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256 LICENSING_ADMIN_CREDENTIALS_0_SCOPES; do
  need "$name"
done

case "$LICENSING_DB_URL" in jdbc:postgresql://*) ;; *) fail "LICENSING_DB_URL must be a jdbc:postgresql:// URL" ;; esac
case "$LICENSING_ISSUER" in https://*) ;; *) fail "LICENSING_ISSUER must be the public https:// URL of this service" ;; esac
case "$LICENSING_ISSUER" in *[[:space:]]*|*/) fail "LICENSING_ISSUER must have no whitespace and no trailing slash" ;; esac
printf '%s' "$LICENSING_SIGNING_KEY_ID" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || fail "LICENSING_SIGNING_KEY_ID has an invalid format"
printf '%s' "$LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256" | grep -Eq '^[0-9a-fA-F]{64}$' \
  || fail "LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256 must be the 64-hex SHA-256 of the token (never the token itself)"
case "$LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256" in 0000000000000000000000000000000000000000000000000000000000000000) fail "admin token hash is a placeholder" ;; esac
# A proxy pattern that matches everything would let any client forge X-Forwarded-Proto and defeat HTTPS enforcement.
case "$LICENSING_TRUSTED_PROXIES" in '.*'|'.+'|'(.*)'|'^.*$') fail "LICENSING_TRUSTED_PROXIES must not trust every address" ;; esac
printf '%s' "$LICENSING_CODE_PEPPER_BASE64" | base64 -d 2>/dev/null | wc -c | grep -Eq '^[[:space:]]*(3[2-9]|[4-9][0-9]|[1-9][0-9]{2,})$' \
  || fail "LICENSING_CODE_PEPPER_BASE64 must be base64 of at least 32 bytes"

# --- key material: environment -> private files (mode 600, in a private directory, gone when the container stops) -----------------
KEYDIR="$(mktemp -d /tmp/licensing-keys.XXXXXX)"; chmod 700 "$KEYDIR"
decode_pem() { # $1 = variable name, $2 = target file, $3 = expected PEM header
  printf '%s' "$(eval "printf '%s' \"\${$1}\"")" | base64 -d > "$2" 2>/dev/null || fail "$1 is not valid base64"
  chmod 600 "$2"
  head -n 1 "$2" | grep -q "^-----BEGIN $3-----\$" || fail "$1 is not a PEM '$3'"
}
decode_pem LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64 "$KEYDIR/signing.key.pem" "PRIVATE KEY"
decode_pem LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64 "$KEYDIR/signing.pub.pem" "PUBLIC KEY"
export LICENSING_SIGNING_PRIVATE_KEY_FILE="$KEYDIR/signing.key.pem"
export LICENSING_SIGNING_PUBLIC_KEY_FILE="$KEYDIR/signing.pub.pem"

# Retired public keys that must still verify existing entitlements during a rotation: "kid=base64pem,kid2=base64pem".
if [ -n "${LICENSING_VERIFY_ONLY_KEYS:-}" ]; then
  mkdir "$KEYDIR/verify-only"; chmod 700 "$KEYDIR/verify-only"
  OLD_IFS="$IFS"; IFS=','
  for pair in $LICENSING_VERIFY_ONLY_KEYS; do
    kid="${pair%%=*}"; body="${pair#*=}"
    printf '%s' "$kid" | grep -Eq '^[A-Za-z0-9._-]{1,64}$' || fail "LICENSING_VERIFY_ONLY_KEYS contains an invalid key id"
    printf '%s' "$body" | base64 -d > "$KEYDIR/verify-only/$kid.pub.pem" 2>/dev/null || fail "a LICENSING_VERIFY_ONLY_KEYS entry is not valid base64"
    head -n 1 "$KEYDIR/verify-only/$kid.pub.pem" | grep -q '^-----BEGIN PUBLIC KEY-----$' || fail "a LICENSING_VERIFY_ONLY_KEYS entry is not a PEM PUBLIC KEY"
  done
  IFS="$OLD_IFS"
  export LICENSING_SIGNING_VERIFY_ONLY_DIR="$KEYDIR/verify-only"
fi
# The base64 copies are no longer needed by the server; do not leave extra copies in its environment.
unset LICENSING_SIGNING_PRIVATE_KEY_PEM_BASE64 LICENSING_SIGNING_PUBLIC_KEY_PEM_BASE64 LICENSING_VERIFY_ONLY_KEYS

# --- listen on the platform's port (LICENSING_PORT wins if set explicitly), on all interfaces --------------------------------------
export LICENSING_PORT="${LICENSING_PORT:-${PORT:-8080}}"
printf '%s' "$LICENSING_PORT" | grep -Eq '^[0-9]{2,5}$' || fail "the listening port is not a number"

# JAVA_OPTS may add flags; the secrets never appear on the command line.
# shellcheck disable=SC2086
exec java -XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError ${JAVA_OPTS:-} -jar /app/app.jar
