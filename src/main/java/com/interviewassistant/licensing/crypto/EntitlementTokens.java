package com.interviewassistant.licensing.crypto;

import com.interviewassistant.licensing.domain.Entitlement;
import com.interviewassistant.licensing.domain.LicenseRight;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Signs and verifies entitlements as JWS compact tokens (RFC 7515) with the EdDSA algorithm on Ed25519 (RFC 8037):
 * {@code base64url(header) "." base64url(payload) "." base64url(signature)}. This is the established format, not a custom one:
 * the desktop application may verify with any JWS library or with the JDK alone.
 *
 * <p>Header: {@code {"alg":"EdDSA","kid":"<key id>","typ":"ia-entitlement+jwt"}}. The signature covers the exact ASCII bytes of
 * {@code header "." payload}, so any change to either segment invalidates it.
 *
 * <p>Verification is strict: the algorithm must be {@code EdDSA} (so {@code none} and algorithm-confusion are impossible), the
 * key id must be one the caller trusts, the signature is checked BEFORE the payload is parsed, and unknown claims are ignored
 * only after authentication.
 */
public final class EntitlementTokens {

    public static final String TYPE = "ia-entitlement+jwt";
    private static final int MAX_TOKEN_CHARS = 4096;

    private EntitlementTokens() {
    }

    // ---------------------------------------------------------------- signing

    public static String sign(SigningKeyRing ring, Entitlement e) {
        String header = new FlatJson.Writer().str("alg", "EdDSA").str("kid", ring.activeKid()).str("typ", TYPE).build();
        List<String> rights = e.rights().stream().sorted(Comparator.naturalOrder()).map(Enum::name).toList();
        FlatJson.Writer p = new FlatJson.Writer()
                .num("ver", e.version())
                .str("iss", e.issuer())
                .str("jti", e.entitlementId().toString())
                .str("lic", e.licenseId().toString())
                .str("dev", e.deviceRegistrationId().toString())
                .str("dkt", e.deviceKeyThumbprint())
                .strings("rights", rights)
                .num("iat", e.issuedAt().getEpochSecond())
                .num("exp", e.expiresAt().getEpochSecond())
                .num("ren", e.renewAfter().getEpochSecond());
        if (e.licenseExpiresAt() != null) {
            p.num("lexp", e.licenseExpiresAt().getEpochSecond());
        }
        String signingInput = Base64Url.encode(header.getBytes(StandardCharsets.UTF_8)) + "."
                + Base64Url.encode(p.build().getBytes(StandardCharsets.UTF_8));
        byte[] sig = ring.sign(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + Base64Url.encode(sig);
    }

    // ------------------------------------------------------------ verification

    /**
     * Verifies the signature with the key named by {@code kid} (from {@code trustedKeys}), then checks the token has not
     * expired at {@code now}, and returns the claims.
     *
     * @throws EntitlementVerificationException for ANY defect; the message never contains token content
     */
    public static Entitlement verify(String token, Map<String, PublicKey> trustedKeys, Instant now) {
        if (token == null || token.length() > MAX_TOKEN_CHARS) {
            throw new EntitlementVerificationException("token missing or too long");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
            throw new EntitlementVerificationException("token is not a compact JWS");
        }
        Map<String, Object> header;
        byte[] signature;
        try {
            header = FlatJson.parse(new String(Base64Url.decode(parts[0]), StandardCharsets.UTF_8));
            signature = Base64Url.decode(parts[2]);
        } catch (IllegalArgumentException ex) {
            throw new EntitlementVerificationException("malformed token header or signature");
        }
        if (!"EdDSA".equals(header.get("alg"))) {
            throw new EntitlementVerificationException("unsupported algorithm");
        }
        if (!TYPE.equals(header.get("typ"))) {
            throw new EntitlementVerificationException("unexpected token type");
        }
        Object kid = header.get("kid");
        PublicKey key = kid instanceof String k ? trustedKeys.get(k) : null;
        if (key == null) {
            throw new EntitlementVerificationException("unknown signing key");
        }
        try {
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(key);
            v.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!v.verify(signature)) {
                throw new EntitlementVerificationException("signature does not verify");
            }
        } catch (GeneralSecurityException ex) {
            throw new EntitlementVerificationException("signature does not verify");
        }
        // Only now is the payload trusted enough to parse.
        Entitlement ent;
        try {
            ent = claims(FlatJson.parse(new String(Base64Url.decode(parts[1]), StandardCharsets.UTF_8)));
        } catch (RuntimeException ex) {
            throw new EntitlementVerificationException("malformed claims");
        }
        if (!now.isBefore(ent.expiresAt())) {
            throw new EntitlementVerificationException("entitlement has expired");
        }
        return ent;
    }

    private static Entitlement claims(Map<String, Object> c) {
        Set<LicenseRight> rights = EnumSet.noneOf(LicenseRight.class);
        for (String r : strings(c.get("rights"))) {
            rights.add(LicenseRight.valueOf(r));
        }
        Object lexp = c.get("lexp");
        return new Entitlement(
                (int) number(c.get("ver")),
                UUID.fromString(string(c.get("jti"))),
                UUID.fromString(string(c.get("lic"))),
                UUID.fromString(string(c.get("dev"))),
                string(c.get("dkt")),
                rights,
                Instant.ofEpochSecond(number(c.get("iat"))),
                Instant.ofEpochSecond(number(c.get("exp"))),
                Instant.ofEpochSecond(number(c.get("ren"))),
                lexp == null ? null : Instant.ofEpochSecond(number(lexp)),
                string(c.get("iss")));
    }

    private static String string(Object o) {
        if (o instanceof String s) {
            return s;
        }
        throw new IllegalArgumentException("expected string claim");
    }

    private static long number(Object o) {
        if (o instanceof Long n) {
            return n;
        }
        throw new IllegalArgumentException("expected numeric claim");
    }

    @SuppressWarnings("unchecked")
    private static List<String> strings(Object o) {
        if (o instanceof List<?> l) {
            return new ArrayList<>((List<String>) l);
        }
        throw new IllegalArgumentException("expected array claim");
    }

    /** Verification failed. The message is safe to log. */
    public static final class EntitlementVerificationException extends RuntimeException {
        public EntitlementVerificationException(String message) {
            super(message);
        }
    }
}
