package com.interviewassistant.licensing.tools;

import com.interviewassistant.licensing.crypto.PemKeys;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Generates an Ed25519 entitlement-signing key pair and the activation-code pepper.
 *
 * <pre>
 *   java -cp licensing-api.jar com.interviewassistant.licensing.tools.KeyGenTool &lt;kid&gt; &lt;output-directory&gt;
 * </pre>
 *
 * Writes {@code <kid>.key.pem} (PRIVATE, mode 600: server only) and {@code <kid>.pub.pem} (public: embed in the desktop build).
 * Refuses to overwrite existing files. Also prints a fresh 32-byte pepper for LICENSING_CODE_PEPPER_BASE64: generate it once and
 * never change it while activation codes issued under it are still outstanding.
 */
public final class KeyGenTool {

    private KeyGenTool() {
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 2 || !Pattern.matches("[A-Za-z0-9._-]{1,64}", args[0])) {
            System.err.println("usage: KeyGenTool <kid: [A-Za-z0-9._-]{1,64}> <output-directory>");
            System.exit(2);
        }
        Path dir = Path.of(args[1]);
        Files.createDirectories(dir);
        Path priv = dir.resolve(args[0] + ".key.pem");
        Path pub = dir.resolve(args[0] + ".pub.pem");
        if (Files.exists(priv) || Files.exists(pub)) {
            System.err.println("refusing to overwrite existing key files for kid " + args[0]);
            System.exit(1);
        }
        KeyPair pair = PemKeys.generateEd25519();
        PemKeys.writePrivate(priv, pair.getPrivate());
        PemKeys.writePublic(pub, pair.getPublic());
        byte[] pepper = new byte[32];
        new SecureRandom().nextBytes(pepper);
        System.out.println("wrote " + priv + " (private, server only) and " + pub + " (public)");
        System.out.println();
        System.out.println("LICENSING_SIGNING_KEY_ID=" + args[0]);
        System.out.println("LICENSING_SIGNING_PRIVATE_KEY_FILE=" + priv.toAbsolutePath());
        System.out.println("LICENSING_SIGNING_PUBLIC_KEY_FILE=" + pub.toAbsolutePath());
        System.out.println();
        System.out.println("Activation-code pepper (generate once; keep secret; do not rotate with outstanding codes):");
        System.out.println("LICENSING_CODE_PEPPER_BASE64=" + java.util.Base64.getEncoder().encodeToString(pepper));
    }
}
