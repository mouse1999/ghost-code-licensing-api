package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.crypto.EntitlementTokens;
import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.Entitlement;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.service.ClientLicenseService.ActivateCommand;
import com.interviewassistant.licensing.service.ClientLicenseService.ActivationResult;
import com.interviewassistant.licensing.service.ClientLicenseService.DeviceRequest;
import com.interviewassistant.licensing.service.Fixture.Device;
import com.interviewassistant.licensing.service.IssuanceService.IssueResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ClientLicenseServiceTest {

    private static final String CLIENT = "203.0.113.7";
    private final Fixture f = new Fixture();

    private static ErrorCode codeOf(Runnable r) {
        return assertThrows(LicensingException.class, r::run).code();
    }

    private ActivationResult activate(IssueResult issued, Device d) {
        return f.client.activate(f.activation(d, issued.license().customerEmail(), issued.activationCode(), CLIENT));
    }

    // ---------------------------------------------------------------- happy path

    @Test
    void activationBindsTheDeviceAndReturnsAVerifiableEntitlement() {
        IssueResult issued = f.issue("a@example.com", 1, 365);
        Device d = f.newDevice();
        ActivationResult r = activate(issued, d);
        assertEquals(LicenseStatus.ACTIVE, r.status());
        assertFalse(r.alreadyRegistered());
        assertEquals(LicenseStatus.ACTIVE, f.store.license(issued.license().id()).status());
        assertEquals(1, f.store.license(issued.license().id()).activeDeviceCount());

        Entitlement e = EntitlementTokens.verify(r.entitlement(), f.ring.publicKeys(), f.clock.instant());
        assertEquals(issued.license().id(), e.licenseId());
        assertEquals(r.deviceRegistrationId(), e.deviceRegistrationId());
        assertEquals(d.thumbprint(), e.deviceKeyThumbprint());
        assertEquals(Fixture.rights(LicenseRight.LIVE, LicenseRight.DSA), e.rights());
        assertEquals(f.clock.instant().plus(Duration.ofDays(7)), e.expiresAt());
        assertTrue(e.renewAfter().isAfter(e.issuedAt()) && e.renewAfter().isBefore(e.expiresAt()));
        assertEquals(f.clock.instant().plus(Duration.ofDays(365)), e.licenseExpiresAt());
    }

    @Test
    void entitlementNeverOutlivesTheLicense() {
        IssueResult issued = f.issue("a@example.com", 1, 1);
        Device d = f.newDevice();
        ActivationResult r = activate(issued, d);
        Entitlement e = EntitlementTokens.verify(r.entitlement(), f.ring.publicKeys(), f.clock.instant());
        assertEquals(f.clock.instant().plus(Duration.ofDays(1)), e.expiresAt());
    }

    @Test
    void repeatedActivationFromTheSameDeviceIsIdempotent() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        Device d = f.newDevice();
        ActivationResult first = activate(issued, d);
        ActivationResult again = activate(issued, d);
        assertTrue(again.alreadyRegistered());
        assertEquals(first.deviceRegistrationId(), again.deviceRegistrationId());
        assertEquals(1, f.store.deviceCount(issued.license().id()));
        assertEquals(1, f.store.license(issued.license().id()).activeDeviceCount());
    }

    @Test
    void validateAndRenewWorkWithTheDeviceKeyAndRenewalIssuesAFreshToken() {
        IssueResult issued = f.issue("a@example.com", 1, 365);
        Device d = f.newDevice();
        ActivationResult act = activate(issued, d);
        UUID lic = act.licenseId();
        UUID dev = act.deviceRegistrationId();

        var v = f.client.validate(f.deviceRequest(d, "validate", lic, dev, CLIENT));
        assertEquals(LicenseStatus.ACTIVE, v.status());
        assertEquals(Fixture.rights(LicenseRight.LIVE, LicenseRight.DSA), v.rights());

        f.clock.advance(Duration.ofDays(4));
        var renewed = f.client.entitlement(f.deviceRequest(d, "entitlement", lic, dev, CLIENT));
        Entitlement e1 = EntitlementTokens.verify(act.entitlement(), f.ring.publicKeys(), f.clock.instant());
        Entitlement e2 = EntitlementTokens.verify(renewed.entitlement(), f.ring.publicKeys(), f.clock.instant());
        assertNotEquals(e1.entitlementId(), e2.entitlementId());
        assertTrue(e2.expiresAt().isAfter(e1.expiresAt()));
    }

    // ---------------------------------------------------------------- invalid activation

    @Test
    void unknownEmailAndWrongCodeAreIndistinguishable() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        Device d = f.newDevice();
        String otherCode = f.codes.generate();
        LicensingException wrongCode = assertThrows(LicensingException.class,
                () -> f.client.activate(f.activation(d, "a@example.com", otherCode, CLIENT)));
        LicensingException unknownEmail = assertThrows(LicensingException.class,
                () -> f.client.activate(f.activation(f.newDevice(), "nobody@example.com", issued.activationCode(), CLIENT)));
        LicensingException wrongPair = assertThrows(LicensingException.class,
                () -> f.client.activate(f.activation(f.newDevice(), "nobody@example.com", otherCode, CLIENT)));
        for (LicensingException e : List.of(wrongCode, unknownEmail, wrongPair)) {
            assertEquals(ErrorCode.INVALID_CREDENTIALS, e.code());
            assertEquals(wrongCode.getMessage(), e.getMessage());
        }
        assertEquals(LicenseStatus.PENDING, f.store.license(issued.license().id()).status(), "a failed attempt changes nothing");
        assertEquals(0, f.store.deviceCount(issued.license().id()));
    }

    @Test
    void failedAttemptsAreAuditedWithoutTheCodeOrEmail() {
        f.issue("a@example.com", 1, 30);
        String guess = f.codes.generate();
        assertEquals(ErrorCode.INVALID_CREDENTIALS, codeOf(() -> f.client.activate(f.activation(f.newDevice(), "a@example.com", guess, CLIENT))));
        AuditEvent e = f.store.allAudit().get(f.store.allAudit().size() - 1);
        assertEquals(AuditAction.ACTIVATION, e.action());
        assertEquals(AuditOutcome.FAILURE, e.outcome());
        assertFalse(e.detail().contains(guess));
        assertFalse(e.detail().contains("a@example.com"));
        assertFalse(f.store.dumpEverythingStored().contains(guess));
    }

    @Test
    void malformedInputIsRejectedBeforeAnyLookup() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        Device d = f.newDevice();
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.client.activate(f.activation(d, "a@example.com", "not-a-code", CLIENT))));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.client.activate(f.activation(d, "bad-email", issued.activationCode(), CLIENT))));
        ActivateCommand good = f.activation(d, "a@example.com", issued.activationCode(), CLIENT);
        ActivateCommand badKey = new ActivateCommand(good.email(), good.activationCode(), "AAAA", good.proofTimestamp(),
                good.proofNonce(), good.proofSignature(), null, null, CLIENT);
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.client.activate(badKey)));
    }

    // ---------------------------------------------------------------- device proof

    @Test
    void activationRequiresPossessionOfTheDevicePrivateKey() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        Device victim = f.newDevice();
        Device attacker = f.newDevice();
        ActivateCommand valid = f.activation(attacker, "a@example.com", issued.activationCode(), CLIENT);
        // Register the victim's public key but sign with the attacker's key.
        ActivateCommand forged = new ActivateCommand(valid.email(), valid.activationCode(), victim.publicKey(), valid.proofTimestamp(),
                valid.proofNonce(), valid.proofSignature(), null, null, CLIENT);
        assertEquals(ErrorCode.INVALID_DEVICE_PROOF, codeOf(() -> f.client.activate(forged)));
        // A fingerprint with no key proof is not accepted either.
        ActivateCommand unsigned = new ActivateCommand(valid.email(), valid.activationCode(), attacker.publicKey(),
                valid.proofTimestamp(), valid.proofNonce(), "", null, "hw-fingerprint-123", CLIENT);
        assertEquals(ErrorCode.INVALID_DEVICE_PROOF, codeOf(() -> f.client.activate(unsigned)));
        assertEquals(0, f.store.deviceCount(issued.license().id()));
    }

    @Test
    void replayedAndStaleProofsAreRejected() {
        IssueResult issued = f.issue("a@example.com", 2, 30);
        Device d = f.newDevice();
        ActivateCommand cmd = f.activation(d, "a@example.com", issued.activationCode(), CLIENT);
        f.client.activate(cmd);
        assertEquals(ErrorCode.INVALID_DEVICE_PROOF, codeOf(() -> f.client.activate(cmd)), "exact replay");

        ActivateCommand stale = f.activation(f.newDevice(), "a@example.com", issued.activationCode(), CLIENT);
        f.clock.advance(Duration.ofMinutes(6));
        assertEquals(ErrorCode.INVALID_DEVICE_PROOF, codeOf(() -> f.client.activate(stale)), "older than the skew window");
    }

    @Test
    void validationWithAForeignKeyUnknownDeviceOrReplayIsRejected() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        Device d = f.newDevice();
        ActivationResult act = activate(issued, d);
        Device other = f.newDevice();
        assertEquals(ErrorCode.INVALID_CREDENTIALS,
                codeOf(() -> f.client.validate(f.deviceRequest(other, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
        assertEquals(ErrorCode.INVALID_CREDENTIALS,
                codeOf(() -> f.client.validate(f.deviceRequest(d, "validate", act.licenseId(), UUID.randomUUID(), CLIENT))));
        assertEquals(ErrorCode.INVALID_CREDENTIALS,
                codeOf(() -> f.client.validate(f.deviceRequest(d, "validate", UUID.randomUUID(), act.deviceRegistrationId(), CLIENT))));
        // a validate signature cannot be used for renewal
        DeviceRequest v = f.deviceRequest(d, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT);
        assertEquals(ErrorCode.INVALID_CREDENTIALS, codeOf(() -> f.client.entitlement(v)));
        // exact replay of an accepted validate
        DeviceRequest ok = f.deviceRequest(d, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT);
        f.client.validate(ok);
        assertEquals(ErrorCode.INVALID_DEVICE_PROOF, codeOf(() -> f.client.validate(ok)));
    }

    // ---------------------------------------------------------------- lifecycle states as seen by the client

    @Test
    void suspendedLicenseIsReportedClearlyAndCanBeReinstated() {
        IssueResult issued = f.issue("a@example.com", 1, 365);
        Device d = f.newDevice();
        ActivationResult act = activate(issued, d);
        f.admin.suspend(f.fullAdmin, act.licenseId(), "review");
        assertEquals(ErrorCode.LICENSE_SUSPENDED,
                codeOf(() -> f.client.validate(f.deviceRequest(d, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
        assertEquals(ErrorCode.LICENSE_SUSPENDED,
                codeOf(() -> f.client.entitlement(f.deviceRequest(d, "entitlement", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
        f.admin.reinstate(f.fullAdmin, act.licenseId(), "ok");
        assertEquals(LicenseStatus.ACTIVE, f.client.validate(f.deviceRequest(d, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT)).status());
    }

    @Test
    void aValidSignatureOnAnOldEntitlementDoesNotOverrideRevocation() {
        IssueResult issued = f.issue("a@example.com", 1, 365);
        Device d = f.newDevice();
        ActivationResult act = activate(issued, d);
        f.admin.revoke(f.fullAdmin, act.licenseId(), "refund");
        // The old token still verifies offline (that is what signatures do)...
        assertDoesNotThrow(() -> EntitlementTokens.verify(act.entitlement(), f.ring.publicKeys(), f.clock.instant()));
        // ...but the server refuses to validate or renew.
        assertEquals(ErrorCode.LICENSE_REVOKED,
                codeOf(() -> f.client.validate(f.deviceRequest(d, "validate", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
        assertEquals(ErrorCode.LICENSE_REVOKED,
                codeOf(() -> f.client.entitlement(f.deviceRequest(d, "entitlement", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
    }

    @Test
    void revokedAndSuspendedLicensesCannotBeActivated() {
        IssueResult revoked = f.issue("r@example.com", 1, 30);
        f.admin.revoke(f.fullAdmin, revoked.license().id(), "");
        assertEquals(ErrorCode.LICENSE_REVOKED, codeOf(() -> activate(revoked, f.newDevice())));
        IssueResult suspended = f.issue("s@example.com", 1, 30);
        f.admin.suspend(f.fullAdmin, suspended.license().id(), "");
        assertEquals(ErrorCode.LICENSE_SUSPENDED, codeOf(() -> activate(suspended, f.newDevice())));
        assertEquals(0, f.store.deviceCount(revoked.license().id()) + f.store.deviceCount(suspended.license().id()));
    }

    @Test
    void anUnusedCodeStopsWorkingAfterTheActivationWindowAndTheStatusIsBroughtUpToDate() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        f.clock.advance(Duration.ofDays(31));
        assertEquals(ErrorCode.LICENSE_EXPIRED, codeOf(() -> activate(issued, f.newDevice())));
        assertEquals(LicenseStatus.EXPIRED, f.store.license(issued.license().id()).status());
        assertTrue(f.store.allAudit().stream().anyMatch(e -> e.action() == AuditAction.LICENSE_EXPIRED));
    }

    @Test
    void anActiveLicenseExpiresWithTimeAndEntitlementRenewalStops() {
        IssueResult issued = f.issue("a@example.com", 1, 10);
        Device d = f.newDevice();
        ActivationResult act = activate(issued, d);
        f.clock.advance(Duration.ofDays(11));
        assertEquals(ErrorCode.LICENSE_EXPIRED,
                codeOf(() -> f.client.entitlement(f.deviceRequest(d, "entitlement", act.licenseId(), act.deviceRegistrationId(), CLIENT))));
        assertEquals(LicenseStatus.EXPIRED, f.store.license(act.licenseId()).status());
        assertEquals(ErrorCode.LICENSE_EXPIRED, codeOf(() -> activate(issued, f.newDevice())));
    }

    // ---------------------------------------------------------------- device limit and concurrency

    @Test
    void secondDeviceIsRefusedOnceTheLimitIsReached() {
        IssueResult issued = f.issue("a@example.com", 1, 30);
        activate(issued, f.newDevice());
        assertEquals(ErrorCode.DEVICE_LIMIT_REACHED, codeOf(() -> activate(issued, f.newDevice())));
        assertEquals(1, f.store.deviceCount(issued.license().id()));

        IssueResult two = f.issue("b@example.com", 2, 30);
        activate(two, f.newDevice());
        activate(two, f.newDevice());
        assertEquals(ErrorCode.DEVICE_LIMIT_REACHED, codeOf(() -> activate(two, f.newDevice())));
        assertEquals(2, f.store.license(two.license().id()).activeDeviceCount());
    }

    private List<Object> raceActivations(IssueResult issued, List<Device> devices) throws Exception {
        CountDownLatch go = new CountDownLatch(1);
        List<Object> results = Collections.synchronizedList(new ArrayList<>());
        List<Thread> threads = new ArrayList<>();
        for (Device d : devices) {
            ActivateCommand cmd = f.activation(d, issued.license().customerEmail(), issued.activationCode(), "client-" + threads.size());
            Thread t = new Thread(() -> {
                try {
                    go.await();
                    results.add(f.client.activate(cmd));
                } catch (LicensingException e) {
                    results.add(e.code());
                } catch (Throwable e) {
                    results.add(e);
                }
            });
            threads.add(t);
            t.start();
        }
        go.countDown();
        for (Thread t : threads) {
            t.join();
        }
        return results;
    }

    @Test
    void concurrentActivationsNeverExceedTheDeviceLimit() throws Exception {
        for (int round = 0; round < 25; round++) {
            Fixture local = new Fixture();
            IssueResult issued = local.issue("race" + round + "@example.com", 1, 30);
            List<Device> devices = new ArrayList<>();
            for (int i = 0; i < 12; i++) {
                devices.add(local.newDevice());
            }
            // run against this round's fixture
            CountDownLatch go = new CountDownLatch(1);
            List<Object> results = Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (Device d : devices) {
                ActivateCommand cmd = local.activation(d, issued.license().customerEmail(), issued.activationCode(), "c" + threads.size());
                Thread t = new Thread(() -> {
                    try {
                        go.await();
                        results.add(local.client.activate(cmd));
                    } catch (LicensingException e) {
                        results.add(e.code());
                    } catch (Throwable e) {
                        results.add(e);
                    }
                });
                threads.add(t);
                t.start();
            }
            go.countDown();
            for (Thread t : threads) {
                t.join();
            }
            long ok = results.stream().filter(r -> r instanceof ActivationResult).count();
            long limit = results.stream().filter(r -> r == ErrorCode.DEVICE_LIMIT_REACHED).count();
            long other = results.size() - ok - limit;
            assertEquals(1, ok, "round " + round + ": exactly one device wins, results=" + results);
            assertEquals(11, limit, "round " + round + " results=" + results);
            assertEquals(0, other);
            assertEquals(1, local.store.deviceCount(issued.license().id()));
            assertEquals(1, local.store.license(issued.license().id()).activeDeviceCount());
        }
    }

    @Test
    void concurrentActivationsWithALimitOfThreeBindExactlyThree() throws Exception {
        IssueResult issued = f.issue("a@example.com", 3, 30);
        List<Device> devices = new ArrayList<>();
        for (int i = 0; i < 20; i++) {
            devices.add(f.newDevice());
        }
        List<Object> results = raceActivations(issued, devices);
        assertEquals(3, results.stream().filter(r -> r instanceof ActivationResult).count(), results.toString());
        assertEquals(17, results.stream().filter(r -> r == ErrorCode.DEVICE_LIMIT_REACHED).count(), results.toString());
        assertEquals(3, f.store.deviceCount(issued.license().id()));
        assertEquals(3, f.store.license(issued.license().id()).activeDeviceCount());
    }

    @Test
    void theSameDeviceRetryingConcurrentlyIsBoundOnceAndNeverSeesALimitError() throws Exception {
        for (int round = 0; round < 20; round++) {
            Fixture local = new Fixture();
            IssueResult issued = local.issue("a@example.com", 1, 30);
            Device d = local.newDevice();
            CountDownLatch go = new CountDownLatch(1);
            AtomicInteger ok = new AtomicInteger();
            List<Object> failures = Collections.synchronizedList(new ArrayList<>());
            List<Thread> threads = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                ActivateCommand cmd = local.activation(d, "a@example.com", issued.activationCode(), "c" + i);
                Thread t = new Thread(() -> {
                    try {
                        go.await();
                        local.client.activate(cmd);
                        ok.incrementAndGet();
                    } catch (Throwable e) {
                        failures.add(e instanceof LicensingException le ? le.code() : e);
                    }
                });
                threads.add(t);
                t.start();
            }
            go.countDown();
            for (Thread t : threads) {
                t.join();
            }
            assertEquals(8, ok.get(), "round " + round + " failures=" + failures);
            assertEquals(1, local.store.deviceCount(issued.license().id()));
            assertEquals(1, local.store.license(issued.license().id()).activeDeviceCount());
        }
    }

    @Test
    void suspendRacingWithActivationLeavesAConsistentState() throws Exception {
        for (int round = 0; round < 25; round++) {
            Fixture local = new Fixture();
            IssueResult issued = local.issue("a@example.com", 1, 30);
            Device d = local.newDevice();
            ActivateCommand cmd = local.activation(d, "a@example.com", issued.activationCode(), "c");
            CountDownLatch go = new CountDownLatch(1);
            Thread a = new Thread(() -> {
                try {
                    go.await();
                    local.client.activate(cmd);
                } catch (Exception ignored) {
                    // either outcome is acceptable; the invariant is checked below
                }
            });
            Thread s = new Thread(() -> {
                try {
                    go.await();
                    local.admin.suspend(local.fullAdmin, issued.license().id(), "race");
                } catch (Exception ignored) {
                    // see above
                }
            });
            a.start();
            s.start();
            go.countDown();
            a.join();
            s.join();
            var l = local.store.license(issued.license().id());
            assertEquals(local.store.deviceCount(l.id()), l.activeDeviceCount(), "counter always matches bound devices");
            assertTrue(l.status() == LicenseStatus.SUSPENDED || l.status() == LicenseStatus.ACTIVE, l.status().toString());
            if (l.status() == LicenseStatus.ACTIVE) {
                assertEquals(1, l.activeDeviceCount());
            }
        }
    }

    // ---------------------------------------------------------------- abuse protection

    @Test
    void requestRateLimitIsEnforcedPerClient() {
        Fixture local = new Fixture(3, 50, 100);
        IssueResult issued = local.issue("a@example.com", 5, 30);
        for (int i = 0; i < 3; i++) {
            local.client.activate(local.activation(local.newDevice(), "a@example.com", issued.activationCode(), "1.1.1.1"));
        }
        LicensingException e = assertThrows(LicensingException.class,
                () -> local.client.activate(local.activation(local.newDevice(), "a@example.com", issued.activationCode(), "1.1.1.1")));
        assertEquals(ErrorCode.RATE_LIMITED, e.code());
        assertTrue(e.retryAfterSeconds() >= 1);
        // another client is unaffected
        assertDoesNotThrow(() -> local.client.activate(local.activation(local.newDevice(), "a@example.com", issued.activationCode(), "2.2.2.2")));
    }

    @Test
    void repeatedWrongCodesLockOutThatClientAndEmailButNotOthers() {
        Fixture local = new Fixture(100, 5, 100);
        IssueResult issued = local.issue("a@example.com", 1, 30);
        for (int i = 0; i < 5; i++) {
            assertEquals(ErrorCode.INVALID_CREDENTIALS, codeOf(() -> local.client.activate(
                    local.activation(local.newDevice(), "a@example.com", local.codes.generate(), "9.9.9.9"))));
        }
        // even the correct code is refused for this client+email now...
        assertEquals(ErrorCode.RATE_LIMITED, codeOf(() -> local.client.activate(
                local.activation(local.newDevice(), "a@example.com", issued.activationCode(), "9.9.9.9"))));
        // ...but the genuine customer on another address is not locked out (no remote lockout of a victim)
        assertDoesNotThrow(() -> local.client.activate(local.activation(local.newDevice(), "a@example.com", issued.activationCode(), "8.8.8.8")));
        // and the lockout ends with the window
        local.clock.advance(Duration.ofMinutes(16));
        assertFalse(local.activationFailures.isExhausted("9.9.9.9|" + local.codes.reference("email", "a@example.com")));
    }

    // ---------------------------------------------------------------- no secrets in logs

    @Test
    void noSecretsReachTheLogsAcrossTheWholeFlow() {
        try (LogCapture logs = new LogCapture()) {
            IssueResult issued = f.issue("secretive@example.com", 1, 30);
            Device d = f.newDevice();
            ActivationResult act = activate(issued, d);
            assertThrows(LicensingException.class, () -> f.client.activate(f.activation(f.newDevice(), "secretive@example.com", f.codes.generate(), CLIENT)));
            f.admin.revoke(f.fullAdmin, act.licenseId(), "x");
            String text = logs.text();
            assertFalse(text.contains(issued.activationCode()));
            assertFalse(text.contains(issued.activationCode().replace("-", "")));
            assertFalse(text.contains(act.entitlement()));
            assertFalse(text.contains("secretive@example.com"));
            assertFalse(text.contains("PRIVATE KEY"));
            assertFalse(text.contains(d.publicKey()));
            assertTrue(text.contains("license issued"), "sanity: the capture is working");
        }
        ActivateCommand cmd = f.activation(f.newDevice(), "a@example.com", "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", CLIENT);
        assertFalse(cmd.toString().contains("AAAA"));
    }
}
