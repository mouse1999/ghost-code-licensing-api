package com.interviewassistant.licensing.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;

/**
 * Device-key helpers for the proof-of-possession scheme the Phase 129 desktop client will implement.
 *
 * <p>A device generates an Ed25519 key pair, keeps the private key protected locally, and registers the PUBLIC key
 * (X.509 SubjectPublicKeyInfo DER, base64url). Every client request carries a signature, made with the device private key, over
 * a message that names the operation, the subject and a fresh timestamp and nonce:
 *
 * <pre>
 *   "ia-license-v1" LF "activate" LF email LF thumbprint LF timestamp LF nonce
 *   "ia-license-v1" LF "validate" LF licenseId LF deviceId LF timestamp LF nonce
 *   "ia-license-v1" LF "entitlement" LF licenseId LF deviceId LF timestamp LF nonce
 * </pre>
 *
 * The operation name is part of the signed bytes, so a signature for one operation cannot be replayed as another.
 * A hardware/OS fingerprint is never sufficient: only possession of the private key authorises a request.
 */
public final class DeviceKeys {

    public static final String PREFIX = "ia-license-v1";

    private DeviceKeys() {
    }

    /** Parses a registered public key; throws {@link IllegalArgumentException} if it is not a valid Ed25519 SPKI. */
    public static PublicKey parsePublicKey(String base64urlSpki) {
        byte[] der = Base64Url.decode(base64urlSpki);
        if (der.length != 44) { // 12-byte SPKI prefix + 32-byte Ed25519 key
            throw new IllegalArgumentException("not an Ed25519 public key");
        }
        try {
            PublicKey key = PemKeys.publicFromDer(der);
            if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
                throw new IllegalArgumentException("not an Ed25519 public key");
            }
            return key;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("not an Ed25519 public key");
        }
    }

    /** SHA-256 of the DER bytes, lowercase hex: a stable identity for the key. */
    public static String thumbprint(String base64urlSpki) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Base64Url.decode(base64urlSpki)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String activateMessage(String email, String thumbprint, long timestamp, String nonce) {
        return PREFIX + "\nactivate\n" + email + "\n" + thumbprint + "\n" + timestamp + "\n" + nonce;
    }

    public static String operationMessage(String operation, String licenseId, String deviceId, long timestamp, String nonce) {
        return PREFIX + "\n" + operation + "\n" + licenseId + "\n" + deviceId + "\n" + timestamp + "\n" + nonce;
    }

    /** True only if {@code base64urlSignature} is a valid Ed25519 signature by {@code key} over {@code message}. */
    public static boolean verify(PublicKey key, String message, String base64urlSignature) {
        try {
            byte[] sig = Base64Url.decode(base64urlSignature);
            if (sig.length != 64) {
                return false;
            }
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(message.getBytes(StandardCharsets.UTF_8));
            return s.verify(sig);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }
}
