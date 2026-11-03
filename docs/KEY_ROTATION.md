# Entitlement signing keys and rotation

* Algorithm: Ed25519 (JDK 21 native, no extra crypto library). Token format: JWS compact (`alg: EdDSA`), key id in the `kid` header.
* The **private** key lives only on the licensing server (file, mode 600, owned by the service user). It is never sent to a client,
  never put in the installer, never logged, and `SigningKeyRing` exposes no accessor for it. On start-up the server signs and
  verifies a probe with the pair and refuses to run if they do not match; it also refuses a private key file readable by group/others.
* The **public** key is distributed to the desktop app **at build time** (Phase 129). The `/api/v1/entitlement-keys` endpoint exists
  for operators, not for trust bootstrapping: a client that adopted keys it first saw over the network could be handed an attacker's key.

## Routine rotation (e.g. yearly, or after any suspected exposure of the server)
1. `KeyGenTool 2027-a <dir>` → new `2027-a.key.pem` / `2027-a.pub.pem`.
2. Ship a desktop release that trusts **both** `2026-a` and `2027-a` public keys. Wait until adoption is high enough.
3. Put the old public key in the verify-only directory (`LICENSING_SIGNING_VERIFY_ONLY_DIR/2026-a.pub.pem`), point
   `LICENSING_SIGNING_KEY_ID/PRIVATE_KEY_FILE/PUBLIC_KEY_FILE` at the new key, restart. New tokens carry `kid=2027-a`; tokens already
   issued under `2026-a` still verify until they expire (default 7 days).
4. After the longest token lifetime has passed and old desktop builds are out of use, delete the old public key from the directory and from the next desktop release.

## Emergency rotation (private key suspected stolen)
Do steps 1 and 3 immediately **without** keeping the old key in the verify-only directory: every token signed by the old key stops
verifying on updated clients. Desktop builds that only know the old key must be updated — plan for this when choosing how clients
behave when they cannot verify (Phase 129). Rotation never changes license state; revocation is separate and server-side.

## Activation-code pepper
`LICENSING_CODE_PEPPER_BASE64` keys the hash of activation codes. Changing it makes every outstanding (unredeemed) code unusable.
Rotate only when no codes are outstanding, or revoke and reissue them.
