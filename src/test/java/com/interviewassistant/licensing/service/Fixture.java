package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.crypto.ActivationCodes;
import com.interviewassistant.licensing.crypto.Base64Url;
import com.interviewassistant.licensing.crypto.DeviceKeys;
import com.interviewassistant.licensing.crypto.SigningKeyRing;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.security.NonceCache;
import com.interviewassistant.licensing.security.RateLimiter;
import com.interviewassistant.licensing.service.ClientLicenseService.ActivateCommand;
import com.interviewassistant.licensing.service.ClientLicenseService.DeviceRequest;
import com.interviewassistant.licensing.service.IssuanceService.IssueCommand;
import com.interviewassistant.licensing.service.IssuanceService.IssueResult;

import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.TransactionRunner;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/** Wires the real services to the in-memory store and a controllable clock. */
final class Fixture {

    static final class MutableClock extends Clock {
        private final AtomicLong millis;

        MutableClock(Instant start) {
            millis = new AtomicLong(start.toEpochMilli());
        }

        void advance(Duration d) {
            millis.addAndGet(d.toMillis());
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }
    }

    record Device(KeyPair pair, String publicKey, String thumbprint) {
    }

    final MutableClock clock = new MutableClock(Instant.parse("2026-11-01T12:00:00Z"));
    final LicenseStore ls;
    final TransactionRunner tr;
    final Inspect store;
    final ActivationCodes codes = new ActivationCodes(new byte[32] /* test pepper */, new SecureRandom());
    final SigningKeyRing ring = SigningKeyRing.ephemeral("test-key-1");
    final ServiceSettings settings = new ServiceSettings("https://licensing.test", Duration.ofDays(7), Duration.ofMinutes(5));
    final RateLimiter activationPerClient;
    final RateLimiter activationFailures;
    final RateLimiter validationPerClient;
    final NonceCache nonces = new NonceCache(Duration.ofMinutes(10), clock);
    final IssuanceService issuance;
    final ClientLicenseService client;
    final AdminLicenseService admin;
    final AdminPrincipal fullAdmin = new AdminPrincipal("dev", EnumSet.allOf(AdminScope.class));
    private final SecureRandom random = new SecureRandom();

    Fixture() {
        this(100, 5, 100);
    }

    Fixture(int activationsPerWindow, int failuresPerWindow, int validationsPerWindow) {
        if (PgSupport.enabled()) {
            PgSupport.Db db = new PgSupport.Db();
            ls = db.licenses();
            tr = db.tx;
            store = db;
        } else {
            InMemoryLicenseStore mem = new InMemoryLicenseStore();
            ls = mem;
            tr = mem;
            store = mem;
        }
        activationPerClient = new RateLimiter(activationsPerWindow, Duration.ofMinutes(1), clock);
        activationFailures = new RateLimiter(failuresPerWindow, Duration.ofMinutes(15), clock);
        validationPerClient = new RateLimiter(validationsPerWindow, Duration.ofMinutes(1), clock);
        issuance = new IssuanceService(ls, tr, codes, clock);
        client = new ClientLicenseService(ls, tr, codes, ring, settings, activationPerClient, activationFailures,
                validationPerClient, nonces, clock);
        admin = new AdminLicenseService(ls, tr, clock);
    }

    IssueResult issue(String email, int deviceLimit, Integer validityDays) {
        LicensePolicy policy = new LicensePolicy(deviceLimit, validityDays, EnumSet.of(LicenseRight.LIVE, LicenseRight.DSA), 30);
        return issuance.issue(fullAdmin, new IssueCommand(email, true, "bank-ref-001", policy, UUID.randomUUID().toString()));
    }

    Device newDevice() {
        try {
            java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("Ed25519");
            KeyPair p = g.generateKeyPair();
            String pub = Base64Url.encode(p.getPublic().getEncoded());
            return new Device(p, pub, DeviceKeys.thumbprint(pub));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String sign(Device d, String message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(d.pair().getPrivate());
            s.update(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64Url.encode(s.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    String nonce() {
        byte[] b = new byte[16];
        random.nextBytes(b);
        return Base64Url.encode(b);
    }

    long now() {
        return clock.instant().getEpochSecond();
    }

    ActivateCommand activation(Device d, String email, String code, String clientKey) {
        String n = nonce();
        long ts = now();
        String sig = sign(d, DeviceKeys.activateMessage(email.trim().toLowerCase(), d.thumbprint(), ts, n));
        return new ActivateCommand(email, code, d.publicKey(), ts, n, sig, "Test laptop", null, clientKey);
    }

    DeviceRequest deviceRequest(Device d, String operation, UUID licenseId, UUID deviceId, String clientKey) {
        String n = nonce();
        long ts = now();
        String sig = sign(d, DeviceKeys.operationMessage(operation, licenseId.toString(), deviceId.toString(), ts, n));
        return new DeviceRequest(licenseId, deviceId, ts, n, sig, clientKey);
    }

    static Set<LicenseRight> rights(LicenseRight... r) {
        return EnumSet.copyOf(java.util.List.of(r));
    }
}
