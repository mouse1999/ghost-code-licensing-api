package com.interviewassistant.licensing.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

/** Reading and writing Ed25519 keys as PEM (PKCS#8 for private keys, X.509 SubjectPublicKeyInfo for public keys). */
public final class PemKeys {

    private PemKeys() {
    }

    public static KeyPair generateEd25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is not available in this Java runtime", e);
        }
    }

    public static String toPem(PrivateKey key) {
        return pem("PRIVATE KEY", key.getEncoded());
    }

    public static String toPem(PublicKey key) {
        return pem("PUBLIC KEY", key.getEncoded());
    }

    public static PrivateKey readPrivate(Path file) {
        requireOwnerOnly(file);
        try {
            byte[] der = decodePem(Files.readString(file, StandardCharsets.US_ASCII), "PRIVATE KEY");
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            // Never include file content in the message.
            throw new IllegalStateException("cannot read Ed25519 private key from " + file.getFileName(), e);
        }
    }

    public static PublicKey readPublic(Path file) {
        try {
            byte[] der = decodePem(Files.readString(file, StandardCharsets.US_ASCII), "PUBLIC KEY");
            return publicFromDer(der);
        } catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("cannot read Ed25519 public key from " + file.getFileName(), e);
        }
    }

    public static PublicKey publicFromDer(byte[] der) throws GeneralSecurityException {
        return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
    }

    /** Writes a private key file readable only by its owner (POSIX systems; on others the OS ACL must be set by the operator). */
    public static void writePrivate(Path file, PrivateKey key) throws IOException {
        Files.writeString(file, toPem(key), StandardCharsets.US_ASCII);
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX file system: documented operator responsibility.
        }
    }

    public static void writePublic(Path file, PublicKey key) throws IOException {
        Files.writeString(file, toPem(key), StandardCharsets.US_ASCII);
    }

    private static void requireOwnerOnly(Path file) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
            boolean open = perms.contains(PosixFilePermission.GROUP_READ) || perms.contains(PosixFilePermission.GROUP_WRITE)
                    || perms.contains(PosixFilePermission.OTHERS_READ) || perms.contains(PosixFilePermission.OTHERS_WRITE);
            if (open) {
                throw new IllegalStateException("private key file " + file.getFileName()
                        + " is readable by group/others; run: chmod 600 " + file);
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX: cannot check.
        } catch (IOException e) {
            throw new IllegalStateException("cannot inspect private key file " + file.getFileName(), e);
        }
    }

    private static String pem(String label, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    private static byte[] decodePem(String text, String label) {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        int b = text.indexOf(begin);
        int e = text.indexOf(end);
        if (b < 0 || e < b) {
            throw new IllegalArgumentException("not a PEM " + label);
        }
        String body = text.substring(b + begin.length(), e).replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}
