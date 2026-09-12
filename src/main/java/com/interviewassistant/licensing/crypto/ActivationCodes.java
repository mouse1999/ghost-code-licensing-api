package com.interviewassistant.licensing.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.HexFormat;

/**
 * Generation, normalisation and hashing of activation codes.
 *
 * <ul>
 *   <li><b>Entropy:</b> 20 bytes (160 bits) from {@link SecureRandom}, written as 32 Crockford base32 characters in eight groups
 *       of four ({@code XXXX-XXXX-...}). Easy to read out and type; far beyond guessing range.</li>
 *   <li><b>Storage:</b> only {@code HMAC-SHA-256(pepper, normalised code)} is stored. The pepper is a server secret that is NOT in
 *       the database, so a database leak alone gives an attacker nothing to test guesses against.</li>
 *   <li>The same keyed hash is used for non-reversible references to emails and device fingerprints.</li>
 * </ul>
 */
public final class ActivationCodes {

    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    public static final int CODE_CHARS = 32;
    private static final int MIN_PEPPER_BYTES = 32;

    private final SecureRandom random;
    private final byte[] pepper;

    public ActivationCodes(byte[] pepper, SecureRandom random) {
        if (pepper == null || pepper.length < MIN_PEPPER_BYTES) {
            throw new IllegalArgumentException("the code pepper must be at least " + MIN_PEPPER_BYTES + " bytes");
        }
        this.pepper = pepper.clone();
        this.random = random;
    }

    public ActivationCodes(byte[] pepper) {
        this(pepper, new SecureRandom());
    }

    /** A new random code in display form. Show it once, then keep only {@link #hash(String)} of it. */
    public String generate() {
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(CODE_CHARS + 7);
        int buffer = 0;
        int bits = 0;
        int emitted = 0;
        for (byte b : bytes) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                if (emitted > 0 && emitted % 4 == 0) {
                    sb.append('-');
                }
                sb.append(ALPHABET.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
                emitted++;
            }
            buffer &= (1 << bits) - 1;
        }
        return sb.toString();
    }

    /**
     * Canonical form of a typed code: separators removed, upper-cased, and the Crockford look-alikes folded
     * ({@code O}→0, {@code I}/{@code L}→1). Throws if the result is not exactly 32 valid characters.
     */
    public static String normalize(String input) {
        if (input == null || input.length() > 64) {
            throw new IllegalArgumentException("malformed activation code");
        }
        StringBuilder sb = new StringBuilder(CODE_CHARS);
        for (int i = 0; i < input.length(); i++) {
            char c = Character.toUpperCase(input.charAt(i));
            if (c == '-' || c == ' ') {
                continue;
            }
            if (c == 'O') {
                c = '0';
            } else if (c == 'I' || c == 'L') {
                c = '1';
            }
            if (ALPHABET.indexOf(c) < 0) {
                throw new IllegalArgumentException("malformed activation code");
            }
            sb.append(c);
        }
        if (sb.length() != CODE_CHARS) {
            throw new IllegalArgumentException("malformed activation code");
        }
        return sb.toString();
    }

    /** Keyed hash (lowercase hex) of a code. Normalises first, so any accepted spelling hashes identically. */
    public String hash(String code) {
        return hmacHex(normalize(code));
    }

    /** Keyed, non-reversible reference to an arbitrary value (an email, a fingerprint) for audit and storage. */
    public String reference(String purpose, String value) {
        return hmacHex(purpose + "\u0000" + value);
    }

    private String hmacHex(String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(message.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC-SHA-256 unavailable", e);
        }
    }
}
