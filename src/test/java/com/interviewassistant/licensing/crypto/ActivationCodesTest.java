package com.interviewassistant.licensing.crypto;

import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ActivationCodesTest {

    private static byte[] pepper(int fill) {
        byte[] p = new byte[32];
        java.util.Arrays.fill(p, (byte) fill);
        return p;
    }

    @Test
    void codesHaveTheDocumentedShapeAndAreUnique() {
        ActivationCodes codes = new ActivationCodes(pepper(1));
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 20_000; i++) {
            String c = codes.generate();
            assertTrue(c.matches("([0-9A-HJKMNP-TV-Z]{4}-){7}[0-9A-HJKMNP-TV-Z]{4}"), c);
            assertTrue(seen.add(c), "duplicate code generated");
            assertEquals(32, ActivationCodes.normalize(c).length());
        }
    }

    @Test
    void everyAlphabetCharacterAppearsSoAllFiveBitsAreUsed() {
        ActivationCodes codes = new ActivationCodes(pepper(1));
        Set<Character> chars = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            for (char ch : codes.generate().toCharArray()) {
                chars.add(ch);
            }
        }
        assertEquals(33, chars.size(), "32 alphabet characters plus '-'"); // catches a truncated or biased encoder
    }

    @Test
    void anyAcceptedSpellingHashesIdenticallyAndTheHashIsNotTheCode() {
        ActivationCodes codes = new ActivationCodes(pepper(2));
        String code = codes.generate();
        String hash = codes.hash(code);
        assertEquals(hash, codes.hash(code.toLowerCase()));
        assertEquals(hash, codes.hash(code.replace("-", "")));
        assertEquals(hash, codes.hash(code.replace("-", " ")));
        assertEquals(64, hash.length());
        assertTrue(hash.matches("[0-9a-f]{64}"));
        assertFalse(hash.contains(code.replace("-", "").toLowerCase().substring(0, 8)));
    }

    @Test
    void lookAlikeCharactersFoldTheCrockfordWay() {
        assertEquals(ActivationCodes.normalize("0000-1111-0000-1111-0000-1111-0000-1111"),
                ActivationCodes.normalize("OOOO-IIII-oooo-llll-0000-1111-0000-1111"));
    }

    @Test
    void hashDependsOnTheSecretPepper() {
        String code = new ActivationCodes(pepper(3)).generate();
        assertNotEquals(new ActivationCodes(pepper(3)).hash(code), new ActivationCodes(pepper(4)).hash(code));
        assertEquals(new ActivationCodes(pepper(3)).hash(code), new ActivationCodes(pepper(3)).hash(code));
    }

    @Test
    void malformedCodesAndWeakPeppersAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> ActivationCodes.normalize(null));
        assertThrows(IllegalArgumentException.class, () -> ActivationCodes.normalize(""));
        assertThrows(IllegalArgumentException.class, () -> ActivationCodes.normalize("ABCD-EFGH"));
        assertThrows(IllegalArgumentException.class, () -> ActivationCodes.normalize("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU"));
        assertThrows(IllegalArgumentException.class, () -> ActivationCodes.normalize("A".repeat(300)));
        assertThrows(IllegalArgumentException.class, () -> new ActivationCodes(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> new ActivationCodes(null));
    }

    @Test
    void referencesAreKeyedAndPurposeSeparated() {
        ActivationCodes a = new ActivationCodes(pepper(5));
        assertEquals(a.reference("email", "x@example.com"), a.reference("email", "x@example.com"));
        assertNotEquals(a.reference("email", "x@example.com"), a.reference("fingerprint", "x@example.com"));
        assertNotEquals(a.reference("email", "x@example.com"), new ActivationCodes(pepper(6)).reference("email", "x@example.com"));
    }

    @Test
    void auditEventsScrubAnythingShapedLikeAnActivationCode() {
        ActivationCodes codes = new ActivationCodes(pepper(7));
        String code = codes.generate();
        AuditEvent e = AuditEvent.of(Instant.now(), "admin:dev", AuditAction.LICENSE_ISSUED, UUID.randomUUID(),
                AuditOutcome.SUCCESS, "oops code=" + code + " and spaced " + code.replace('-', ' ') + "\nnewline");
        assertFalse(e.detail().contains(code));
        assertFalse(e.detail().contains(code.replace('-', ' ')));
        assertFalse(e.detail().contains("\n"));
        assertTrue(e.detail().contains("[redacted]"));
        // UUIDs and hex digests must survive untouched.
        String uuid = UUID.randomUUID().toString();
        String hex = "ab".repeat(32);
        AuditEvent ok = AuditEvent.of(Instant.now(), "x", AuditAction.ACTIVATION, null, AuditOutcome.SUCCESS, uuid + " " + hex);
        assertEquals(uuid + " " + hex, ok.detail());
    }

    @Test
    void auditDetailIsLengthCapped() {
        AuditEvent e = AuditEvent.of(Instant.now(), "x", AuditAction.ACTIVATION, null, AuditOutcome.SUCCESS, "z".repeat(5000));
        assertEquals(AuditEvent.MAX_DETAIL, e.detail().length());
    }
}
