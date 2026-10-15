package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.crypto.ActivationCodes;
import com.interviewassistant.licensing.crypto.SigningKeyRing;
import com.interviewassistant.licensing.security.AdminAuthenticator;
import com.interviewassistant.licensing.security.DevSettingsGuard;
import com.interviewassistant.licensing.security.NonceCache;
import com.interviewassistant.licensing.security.RateLimiter;
import com.interviewassistant.licensing.service.AdminLicenseService;
import com.interviewassistant.licensing.service.ClientLicenseService;
import com.interviewassistant.licensing.service.IssuanceService;
import com.interviewassistant.licensing.service.ServiceSettings;
import com.interviewassistant.licensing.store.JdbcLicenseStore;
import com.interviewassistant.licensing.store.JdbcTransactionRunner;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.TransactionRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Set;

/** Wires the framework-free core into Spring. Every secret is validated here so a bad configuration stops the start-up. */
@Configuration
public class LicensingConfiguration {

    private static final System.Logger LOG = System.getLogger(LicensingConfiguration.class.getName());

    /** Phase 136: development settings (HTTP, throw-away key) are refused unless the server is bound to loopback. Fails the start-up. */
    @Bean
    DevSettingsGuard.Checked developmentSettingsGuard(LicensingProperties p, org.springframework.core.env.Environment env) {
        return DevSettingsGuard.check(p.security().requireHttps(), p.signing().allowEphemeral(), env.getProperty("server.address"));
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    ActivationCodes activationCodes(LicensingProperties p) {
        if (p.codePepperBase64() == null || p.codePepperBase64().isBlank()) {
            throw new IllegalStateException("licensing.code-pepper-base64 (LICENSING_CODE_PEPPER_BASE64) is required");
        }
        return new ActivationCodes(Base64.getDecoder().decode(p.codePepperBase64().trim()));
    }

    @Bean
    SigningKeyRing signingKeyRing(LicensingProperties p) {
        LicensingProperties.Signing s = p.signing();
        if (s.keyId() == null || s.keyId().isBlank()) {
            throw new IllegalStateException("licensing.signing.key-id (LICENSING_SIGNING_KEY_ID) is required");
        }
        if (s.privateKeyFile() != null && !s.privateKeyFile().isBlank()) {
            if (s.publicKeyFile() == null || s.publicKeyFile().isBlank()) {
                throw new IllegalStateException("licensing.signing.public-key-file is required with a private key file");
            }
            return SigningKeyRing.load(s.keyId(), Path.of(s.privateKeyFile()), Path.of(s.publicKeyFile()),
                    s.verifyOnlyDir() == null || s.verifyOnlyDir().isBlank() ? null : Path.of(s.verifyOnlyDir()));
        }
        if (s.allowEphemeral()) {
            LOG.log(System.Logger.Level.WARNING,
                    "USING A THROW-AWAY SIGNING KEY (licensing.signing.allow-ephemeral). Tokens stop verifying on restart. DEVELOPMENT ONLY.");
            return SigningKeyRing.ephemeral(s.keyId());
        }
        throw new IllegalStateException("no signing key configured (LICENSING_SIGNING_PRIVATE_KEY_FILE); refusing to start");
    }

    @Bean
    AdminAuthenticator adminAuthenticator(LicensingProperties p) {
        List<AdminAuthenticator.Credential> creds = p.admin().credentials().stream()
                .map(c -> AdminAuthenticator.Credential.ofHex(c.id(), c.tokenSha256(), c.scopes() == null ? Set.of() : c.scopes()))
                .toList();
        if (creds.isEmpty()) {
            throw new IllegalStateException("no administrator credential configured; create one with AdminTokenTool (see README)");
        }
        return new AdminAuthenticator(creds);
    }

    @Bean
    TransactionRunner transactionRunner(DataSource dataSource) {
        return new JdbcTransactionRunner(dataSource);
    }

    @Bean
    LicenseStore licenseStore() {
        return new JdbcLicenseStore();
    }

    @Bean
    ServiceSettings serviceSettings(LicensingProperties p) {
        return new ServiceSettings(p.entitlement().issuer(), p.entitlement().ttl(), p.entitlement().proofMaxSkew());
    }

    @Bean
    IssuanceService issuanceService(LicenseStore store, TransactionRunner tx, ActivationCodes codes, Clock clock) {
        return new IssuanceService(store, tx, codes, clock);
    }

    @Bean
    AdminLicenseService adminLicenseService(LicenseStore store, TransactionRunner tx, Clock clock) {
        return new AdminLicenseService(store, tx, clock);
    }

    @Bean
    ClientLicenseService clientLicenseService(LicenseStore store, TransactionRunner tx, ActivationCodes codes, SigningKeyRing ring,
                                              ServiceSettings settings, LicensingProperties p, Clock clock) {
        LicensingProperties.RateLimits r = p.rateLimits();
        return new ClientLicenseService(store, tx, codes, ring, settings,
                new RateLimiter(r.activationPerClientPerMinute(), Duration.ofMinutes(1), clock),
                new RateLimiter(r.activationFailuresPerClientAndEmailPer15Minutes(), Duration.ofMinutes(15), clock),
                new RateLimiter(r.validationPerClientPerMinute(), Duration.ofMinutes(1), clock),
                new NonceCache(settings.proofMaxSkew().multipliedBy(2), clock), clock);
    }

    /** Throttles repeated failed administrator authentication per client address. */
    @Bean
    RateLimiter adminAuthFailureLimiter(LicensingProperties p, Clock clock) {
        return new RateLimiter(p.rateLimits().adminAuthFailuresPerClientPerMinute(), Duration.ofMinutes(1), clock);
    }
}
