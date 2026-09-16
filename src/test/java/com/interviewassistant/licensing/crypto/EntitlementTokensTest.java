package com.interviewassistant.licensing.crypto;

import com.interviewassistant.licensing.crypto.EntitlementTokens.EntitlementVerificationException;
import com.interviewassistant.licensing.domain.Entitlement;
import com.interviewassistant.licensing.domain.LicenseRight;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EntitlementTokensTest {

    private static final Instant NOW = Instant.parse("2026-11-01T12:00:00Z");

    private static Entitlement entitlement(Instant lexp) {
        return new Entitlement(1, UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), "ab".repeat(32),
                EnumSet.of(LicenseRight.LIVE, LicenseRight.DSA), NOW, NOW.plusSeconds(7 * 86400), NOW.plusSeconds(3 * 86400), lexp,
                "https://licensing.test");
    }

    private static String b64(String s) {
        return Base64Url.encode(s.getBytes(StandardCharsets.UTF_8));
    }

    private static String fromB64(String s) {
        return new String(Base64Url.decode(s), StandardCharsets.UTF_8);
    }

    @Test
    void signedEntitlementVerifiesAndRoundTripsEveryClaim() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        Entitlement e = entitlement(NOW.plusSeconds(365L * 86400));
        String token = EntitlementTokens.sign(ring, e);
        assertEquals(3, token.split("\\.").length, "compact JWS");
        Entitlement back = EntitlementTokens.verify(token, ring.publicKeys(), NOW.plusSeconds(60));
        assertEquals(e, back);
    }

    @Test
    void headerNamesTheStandardAlgorithmAndKeyId() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("my-key.2026");
        String header = fromB64(EntitlementTokens.sign(ring, entitlement(null)).split("\\.")[0]);
        Map<String, Object> h = FlatJson.parse(header);
        assertEquals("EdDSA", h.get("alg"));
        assertEquals("my-key.2026", h.get("kid"));
        assertEquals(EntitlementTokens.TYPE, h.get("typ"));
    }

    @Test
    void licenseWithoutAnEndOmitsTheClaim() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String token = EntitlementTokens.sign(ring, entitlement(null));
        assertFalse(fromB64(token.split("\\.")[1]).contains("lexp"));
        assertNull(EntitlementTokens.verify(token, ring.publicKeys(), NOW).licenseExpiresAt());
    }

    @Test
    void anyChangeToThePayloadInvalidatesTheSignature() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String[] p = EntitlementTokens.sign(ring, entitlement(null)).split("\\.");
        String payload = fromB64(p[1]);
        // Upgrade rights, extend expiry, swap licence id: each tampered token must be refused.
        String[] tampered = {
                payload.replace("\"DSA\"", "\"AI_LIVE\""),
                payload.replaceFirst("\"exp\":\\d+", "\"exp\":9999999999"),
                payload.replaceFirst("\"lic\":\"[^\"]+\"", "\"lic\":\"" + UUID.randomUUID() + "\""),
                payload + " ",
        };
        for (String t : tampered) {
            assertNotEquals(payload, t);
            String token = p[0] + "." + b64(t) + "." + p[2];
            assertThrows(EntitlementVerificationException.class, () -> EntitlementTokens.verify(token, ring.publicKeys(), NOW));
        }
    }

    @Test
    void flippingASingleSignatureBitIsRejected() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String[] p = EntitlementTokens.sign(ring, entitlement(null)).split("\\.");
        byte[] sig = Base64Url.decode(p[2]);
        sig[10] ^= 0x01;
        String token = p[0] + "." + p[1] + "." + Base64Url.encode(sig);
        assertThrows(EntitlementVerificationException.class, () -> EntitlementTokens.verify(token, ring.publicKeys(), NOW));
    }

    @Test
    void aTokenSignedByAnotherKeyIsRejectedEvenWithTheSameKid() {
        SigningKeyRing real = SigningKeyRing.ephemeral("k1");
        SigningKeyRing attacker = SigningKeyRing.ephemeral("k1");
        String forged = EntitlementTokens.sign(attacker, entitlement(null));
        assertThrows(EntitlementVerificationException.class, () -> EntitlementTokens.verify(forged, real.publicKeys(), NOW));
    }

    @Test
    void unknownKidAndAlgorithmDowngradesAreRejected() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String[] p = EntitlementTokens.sign(ring, entitlement(null)).split("\\.");
        String unknownKid = b64("{\"alg\":\"EdDSA\",\"kid\":\"other\",\"typ\":\"" + EntitlementTokens.TYPE + "\"}") + "." + p[1] + "." + p[2];
        String none = b64("{\"alg\":\"none\",\"kid\":\"k1\",\"typ\":\"" + EntitlementTokens.TYPE + "\"}") + "." + p[1] + ".";
        String none2 = b64("{\"alg\":\"none\",\"kid\":\"k1\",\"typ\":\"" + EntitlementTokens.TYPE + "\"}") + "." + p[1] + "." + p[2];
        String hs256 = b64("{\"alg\":\"HS256\",\"kid\":\"k1\",\"typ\":\"" + EntitlementTokens.TYPE + "\"}") + "." + p[1] + "." + p[2];
        String wrongType = b64("{\"alg\":\"EdDSA\",\"kid\":\"k1\",\"typ\":\"JWT\"}") + "." + p[1] + "." + p[2];
        for (String t : new String[] {unknownKid, none, none2, hs256, wrongType}) {
            assertThrows(EntitlementVerificationException.class, () -> EntitlementTokens.verify(t, ring.publicKeys(), NOW));
        }
    }

    @Test
    void malformedTokensAreRejectedWithoutLeakingContent() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String good = EntitlementTokens.sign(ring, entitlement(null));
        for (String t : new String[] {null, "", "a.b", "a.b.c.d", "...", good + ".x", good.substring(0, good.length() - 5),
                "x".repeat(5000), "not a token at all"}) {
            EntitlementVerificationException ex = assertThrows(EntitlementVerificationException.class,
                    () -> EntitlementTokens.verify(t, ring.publicKeys(), NOW));
            assertFalse(ex.getMessage().contains(good));
        }
    }

    @Test
    void expiredEntitlementIsRejectedEvenWithAGoodSignature() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        String token = EntitlementTokens.sign(ring, entitlement(null));
        assertDoesNotThrow(() -> EntitlementTokens.verify(token, ring.publicKeys(), NOW.plusSeconds(7 * 86400 - 1)));
        assertThrows(EntitlementVerificationException.class,
                () -> EntitlementTokens.verify(token, ring.publicKeys(), NOW.plusSeconds(7 * 86400)));
    }

    @Test
    void rotationOldTokensVerifyWhileTheOldPublicKeyIsStillTrusted() {
        SigningKeyRing v1 = SigningKeyRing.ephemeral("2026-a");
        String oldToken = EntitlementTokens.sign(v1, entitlement(null));

        KeyPair next = PemKeys.generateEd25519();
        SigningKeyRing v2 = new SigningKeyRing("2026-b", next.getPrivate(), next.getPublic(),
                Map.of("2026-a", v1.publicKeys().get("2026-a")));
        String newToken = EntitlementTokens.sign(v2, entitlement(null));

        assertDoesNotThrow(() -> EntitlementTokens.verify(oldToken, v2.publicKeys(), NOW), "old token, key still trusted");
        assertDoesNotThrow(() -> EntitlementTokens.verify(newToken, v2.publicKeys(), NOW));
        assertEquals("2026-b", FlatJson.parse(fromB64(newToken.split("\\.")[0])).get("kid"));

        // After the old key is retired from the trusted set, its tokens stop verifying.
        SigningKeyRing v2Only = new SigningKeyRing("2026-b", next.getPrivate(), next.getPublic(), Map.of());
        assertThrows(EntitlementVerificationException.class, () -> EntitlementTokens.verify(oldToken, v2Only.publicKeys(), NOW));
    }

    @Test
    void mismatchedKeyPairIsRefusedAtStartup() {
        KeyPair a = PemKeys.generateEd25519();
        KeyPair b = PemKeys.generateEd25519();
        assertThrows(IllegalArgumentException.class, () -> new SigningKeyRing("k1", a.getPrivate(), b.getPublic(), Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new SigningKeyRing("bad kid!", a.getPrivate(), a.getPublic(), Map.of()));
    }

    @Test
    void privateKeyIsNeverExposedByTheRing() {
        SigningKeyRing ring = SigningKeyRing.ephemeral("k1");
        for (java.lang.reflect.Method m : SigningKeyRing.class.getMethods()) {
            assertFalse(java.security.PrivateKey.class.isAssignableFrom(m.getReturnType()), m.getName());
        }
        assertFalse(ring.toString().contains("PRIVATE"));
    }

    @Test
    void pemRoundTripAndPermissionCheck() throws Exception {
        java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("keys");
        KeyPair pair = PemKeys.generateEd25519();
        java.nio.file.Path priv = dir.resolve("k1.key.pem");
        java.nio.file.Path pub = dir.resolve("k1.pub.pem");
        PemKeys.writePrivate(priv, pair.getPrivate());
        PemKeys.writePublic(pub, pair.getPublic());
        SigningKeyRing ring = SigningKeyRing.load("k1", priv, pub, null);
        String token = EntitlementTokens.sign(ring, entitlement(null));
        assertDoesNotThrow(() -> EntitlementTokens.verify(token, ring.publicKeys(), NOW));

        java.nio.file.Files.setPosixFilePermissions(priv, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----"));
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> PemKeys.readPrivate(priv));
        assertTrue(ex.getMessage().contains("chmod 600"));
    }
}
