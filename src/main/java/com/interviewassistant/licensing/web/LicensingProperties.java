package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.security.AdminScope;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * All licensing settings ({@code licensing.*}). Secrets are read from environment variables (see application.yml and the
 * README); none has a usable default, so a mis-configured deployment fails at startup instead of running insecurely.
 *
 * @param codePepperBase64 base64 of >= 32 random bytes; keys the hash of activation codes. REQUIRED.
 */
@ConfigurationProperties("licensing")
public record LicensingProperties(
        String codePepperBase64,
        @DefaultValue Admin admin,
        @DefaultValue Signing signing,
        @DefaultValue Security security,
        @DefaultValue RateLimits rateLimits,
        @DefaultValue Entitlement entitlement,
        @DefaultValue Defaults defaults) {

    /** @param credentials one entry per administrator credential (id, SHA-256 of its token, scopes) */
    public record Admin(List<Credential> credentials) {
        public Admin {
            credentials = credentials == null ? List.of() : List.copyOf(credentials);
        }
    }

    public record Credential(String id, String tokenSha256, Set<AdminScope> scopes) {
    }

    /**
     * @param keyId            kid written into every token
     * @param privateKeyFile   PKCS#8 PEM, mode 600, server only
     * @param publicKeyFile    matching X.509 PEM
     * @param verifyOnlyDir    directory of retired {@code <kid>.pub.pem} files still trusted during rotation
     * @param allowEphemeral   dev only: generate a throw-away key when no file is configured (never in production)
     */
    public record Signing(String keyId, String privateKeyFile, String publicKeyFile, String verifyOnlyDir,
                          @DefaultValue("false") boolean allowEphemeral) {
    }

    /**
     * @param requireHttps  reject requests that did not arrive over HTTPS (as seen after the proxy's X-Forwarded-Proto handling)
     * @param maxBodyBytes  largest accepted request body
     */
    public record Security(@DefaultValue("true") boolean requireHttps, @DefaultValue("16384") int maxBodyBytes) {
    }

    public record RateLimits(
            @DefaultValue("10") int activationPerClientPerMinute,
            @DefaultValue("5") int activationFailuresPerClientAndEmailPer15Minutes,
            @DefaultValue("60") int validationPerClientPerMinute,
            @DefaultValue("10") int adminAuthFailuresPerClientPerMinute) {
    }

    public record Entitlement(@DefaultValue("https://licensing.invalid") String issuer,
                              @DefaultValue("7d") Duration ttl,
                              @DefaultValue("5m") Duration proofMaxSkew) {
    }

    /** Defaults applied when an issue request omits a policy field. */
    public record Defaults(@DefaultValue("30") int activationWindowDays) {
    }
}
