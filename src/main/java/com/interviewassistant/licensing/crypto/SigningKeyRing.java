package com.interviewassistant.licensing.crypto;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The server's entitlement keys: ONE active signing key (identified by {@code kid}) plus any number of retired public keys that
 * are still trusted for verification during a rotation.
 *
 * <h3>Rotation (see docs/KEY_ROTATION.md)</h3>
 * <ol>
 *   <li>Generate a new pair with a new kid ({@code KeyGenTool}).</li>
 *   <li>Ship a desktop release that trusts BOTH the old and new public keys.</li>
 *   <li>Switch the server's active key to the new kid; move the old public key into the verify-only directory.</li>
 *   <li>After every token signed by the old key has expired (max token lifetime) and old desktop builds are gone, remove it.</li>
 * </ol>
 * The private key exists only on the server and is never serialised by this class.
 */
public final class SigningKeyRing {

    private static final Pattern KID = Pattern.compile("[A-Za-z0-9._-]{1,64}");

    private final String activeKid;
    private final PrivateKey activePrivate;
    private final Map<String, PublicKey> publicKeys;

    public SigningKeyRing(String activeKid, PrivateKey activePrivate, PublicKey activePublic, Map<String, PublicKey> verifyOnly) {
        requireKid(activeKid);
        Map<String, PublicKey> all = new LinkedHashMap<>();
        all.put(activeKid, activePublic);
        for (Map.Entry<String, PublicKey> e : verifyOnly.entrySet()) {
            requireKid(e.getKey());
            if (all.putIfAbsent(e.getKey(), e.getValue()) != null) {
                throw new IllegalArgumentException("duplicate key id " + e.getKey());
            }
        }
        this.activeKid = activeKid;
        this.activePrivate = activePrivate;
        this.publicKeys = Collections.unmodifiableMap(all);
        selfTest();
    }

    /** Loads the active pair from files and every {@code <kid>.pub.pem} in the optional verify-only directory. */
    public static SigningKeyRing load(String kid, Path privateKeyFile, Path publicKeyFile, Path verifyOnlyDir) {
        PrivateKey priv = PemKeys.readPrivate(privateKeyFile);
        PublicKey pub = PemKeys.readPublic(publicKeyFile);
        Map<String, PublicKey> retired = new LinkedHashMap<>();
        if (verifyOnlyDir != null && Files.isDirectory(verifyOnlyDir)) {
            try (DirectoryStream<Path> ds = Files.newDirectoryStream(verifyOnlyDir, "*.pub.pem")) {
                for (Path p : ds) {
                    String name = p.getFileName().toString();
                    retired.put(name.substring(0, name.length() - ".pub.pem".length()), PemKeys.readPublic(p));
                }
            } catch (IOException e) {
                throw new IllegalStateException("cannot read verify-only key directory", e);
            }
        }
        return new SigningKeyRing(kid, priv, pub, retired);
    }

    /** A throw-away key for development and tests. Never use in production; the application refuses it outside dev. */
    public static SigningKeyRing ephemeral(String kid) {
        KeyPair pair = PemKeys.generateEd25519();
        return new SigningKeyRing(kid, pair.getPrivate(), pair.getPublic(), Map.of());
    }

    public String activeKid() {
        return activeKid;
    }

    /** All trusted PUBLIC keys by kid (active first). */
    public Map<String, PublicKey> publicKeys() {
        return publicKeys;
    }

    /** Signs with the active private key. The key itself is never exposed. */
    byte[] sign(byte[] message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(activePrivate);
            s.update(message);
            return s.sign();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /** Refuses to start with a private key that does not match its public key. */
    private void selfTest() {
        byte[] probe = "licensing-key-selftest".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        try {
            Signature v = Signature.getInstance("Ed25519");
            v.initVerify(publicKeys.get(activeKid));
            v.update(probe);
            if (!v.verify(sign(probe))) {
                throw new IllegalArgumentException("the active private key does not match the active public key");
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("the signing key pair is unusable", e);
        }
    }

    private static void requireKid(String kid) {
        if (kid == null || !KID.matcher(kid).matches()) {
            throw new IllegalArgumentException("key id must match " + KID.pattern());
        }
    }
}
