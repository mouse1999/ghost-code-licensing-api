package com.interviewassistant.licensing.tools;

import com.interviewassistant.licensing.security.AdminAuthenticator;

import java.security.SecureRandom;

/**
 * Creates the first (or any further) administrator credential.
 *
 * <pre>
 *   java -cp licensing-api.jar com.interviewassistant.licensing.tools.AdminTokenTool
 * </pre>
 *
 * Prints the token ONCE to the terminal and the SHA-256 hash to put in configuration. Store the token in your password manager
 * and give the server only the hash. Nothing is written to disk or logged by this tool. Run it on a trusted machine, not in a
 * CI log.
 */
public final class AdminTokenTool {

    private AdminTokenTool() {
    }

    public static void main(String[] args) {
        String token = AdminAuthenticator.generateToken(new SecureRandom());
        System.out.println("ADMIN TOKEN (shown once; keep it in a password manager, never commit it):");
        System.out.println("  " + token);
        System.out.println();
        System.out.println("Configuration (hash only), e.g. as environment variables:");
        System.out.println("  LICENSING_ADMIN_CREDENTIALS_0_ID=developer");
        System.out.println("  LICENSING_ADMIN_CREDENTIALS_0_TOKEN_SHA256=" + AdminAuthenticator.hashHex(token));
        System.out.println("  LICENSING_ADMIN_CREDENTIALS_0_SCOPES=LICENSE_ISSUE,LICENSE_READ,LICENSE_LIFECYCLE,AUDIT_READ");
    }
}
