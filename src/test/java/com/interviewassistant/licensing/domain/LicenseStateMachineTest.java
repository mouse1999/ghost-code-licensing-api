package com.interviewassistant.licensing.domain;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.EnumSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class LicenseStateMachineTest {

    private static final Instant T0 = Instant.parse("2026-11-01T12:00:00Z");

    private static LicensePolicy policy(Integer validityDays) {
        return new LicensePolicy(1, validityDays, EnumSet.of(LicenseRight.LIVE), 30);
    }

    private static License issued(Integer validityDays) {
        return License.issue(UUID.randomUUID(), "a@example.com", policy(validityDays), T0);
    }

    @Test
    void transitionTableMatchesTheDocumentedStateMachine() {
        for (LicenseStatus from : LicenseStatus.values()) {
            for (LicenseStatus to : LicenseStatus.values()) {
                boolean expected = switch (from) {
                    case PENDING -> to == LicenseStatus.ACTIVE || to == LicenseStatus.SUSPENDED || to == LicenseStatus.REVOKED
                            || to == LicenseStatus.EXPIRED;
                    case ACTIVE -> to == LicenseStatus.SUSPENDED || to == LicenseStatus.REVOKED || to == LicenseStatus.EXPIRED;
                    case SUSPENDED -> to != LicenseStatus.SUSPENDED;
                    case REVOKED, EXPIRED -> false;
                };
                assertEquals(expected, from.canTransitionTo(to), from + " -> " + to);
            }
        }
        assertTrue(LicenseStatus.REVOKED.isTerminal());
        assertTrue(LicenseStatus.EXPIRED.isTerminal());
    }

    @Test
    void newLicenseIsPendingWithDeadlineAndNoDevices() {
        License l = issued(365);
        assertEquals(LicenseStatus.PENDING, l.status());
        assertEquals(T0.plus(Duration.ofDays(30)), l.activationDeadline());
        assertNull(l.activatedAt());
        assertNull(l.expiresAt());
        assertEquals(0, l.activeDeviceCount());
    }

    @Test
    void activationStartsTheTermAndLeavesTheOriginalUntouched() {
        License pending = issued(365);
        Instant t = T0.plus(Duration.ofDays(2));
        License active = pending.activate(t);
        assertEquals(LicenseStatus.ACTIVE, active.status());
        assertEquals(t, active.activatedAt());
        assertEquals(t.plus(Duration.ofDays(365)), active.expiresAt());
        assertEquals(LicenseStatus.PENDING, pending.status(), "records are immutable");
    }

    @Test
    void perpetualLicenseHasNoExpiry() {
        License active = issued(null).activate(T0);
        assertNull(active.expiresAt());
        assertEquals(LicenseStatus.ACTIVE, active.effectiveStatus(T0.plus(Duration.ofDays(36500))));
    }

    @Test
    void expiryIsDerivedFromTimeEvenBeforeTheStoredStatusIsUpdated() {
        License active = issued(10).activate(T0);
        assertEquals(LicenseStatus.ACTIVE, active.effectiveStatus(T0.plus(Duration.ofDays(10)).minusSeconds(1)));
        assertEquals(LicenseStatus.EXPIRED, active.effectiveStatus(T0.plus(Duration.ofDays(10))));
        assertEquals(LicenseStatus.EXPIRED, issued(10).effectiveStatus(T0.plus(Duration.ofDays(30))), "activation window lapsed");
    }

    @Test
    void cannotActivateAnExpiredPendingLicense() {
        License pending = issued(10);
        assertThrows(IllegalLicenseTransitionException.class, () -> pending.activate(T0.plus(Duration.ofDays(31))));
    }

    @Test
    void suspendAndReinstateRestoreTheRightState() {
        License active = issued(100).activate(T0);
        License suspended = active.suspend(T0.plusSeconds(60));
        assertEquals(LicenseStatus.SUSPENDED, suspended.status());
        assertEquals(LicenseStatus.ACTIVE, suspended.reinstate(T0.plusSeconds(120)).status());

        License neverActivated = issued(100).suspend(T0.plusSeconds(60));
        assertEquals(LicenseStatus.PENDING, neverActivated.reinstate(T0.plusSeconds(120)).status());
    }

    @Test
    void reinstateFailsOnceTheLicenseHasLapsed() {
        License suspended = issued(5).activate(T0).suspend(T0.plusSeconds(1));
        assertThrows(IllegalLicenseTransitionException.class, () -> suspended.reinstate(T0.plus(Duration.ofDays(6))));
    }

    @Test
    void revokedAndExpiredAreTerminal() {
        License revoked = issued(5).activate(T0).revoke(T0.plusSeconds(1));
        assertThrows(IllegalLicenseTransitionException.class, () -> revoked.suspend(T0.plusSeconds(2)));
        assertThrows(IllegalLicenseTransitionException.class, () -> revoked.reinstate(T0.plusSeconds(2)));
        assertThrows(IllegalLicenseTransitionException.class, () -> revoked.revoke(T0.plusSeconds(2)));
        assertThrows(IllegalLicenseTransitionException.class, () -> revoked.activate(T0.plusSeconds(2)));

        License active = issued(1).activate(T0);
        License expired = active.expire(T0.plus(Duration.ofDays(1)));
        assertEquals(LicenseStatus.EXPIRED, expired.status());
        assertThrows(IllegalLicenseTransitionException.class, () -> expired.revoke(T0.plus(Duration.ofDays(2))));
    }

    @Test
    void cannotExpireBeforeTheEndOrSuspendAnExpiredLicense() {
        License active = issued(10).activate(T0);
        assertThrows(IllegalLicenseTransitionException.class, () -> active.expire(T0.plusSeconds(5)));
        assertThrows(IllegalLicenseTransitionException.class, () -> active.suspend(T0.plus(Duration.ofDays(11))));
    }

    @Test
    void pendingCanBeRevokedButOnlySuspendedCanBeReinstated() {
        assertEquals(LicenseStatus.REVOKED, issued(5).revoke(T0.plusSeconds(1)).status());
        assertThrows(IllegalLicenseTransitionException.class, () -> issued(5).reinstate(T0));
        assertThrows(IllegalLicenseTransitionException.class, () -> issued(5).activate(T0).reinstate(T0));
    }

    @Test
    void policyIsValidatedDeterministically() {
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(0, 10, EnumSet.of(LicenseRight.LIVE), 30));
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(11, 10, EnumSet.of(LicenseRight.LIVE), 30));
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(1, 0, EnumSet.of(LicenseRight.LIVE), 30));
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(1, 10, EnumSet.noneOf(LicenseRight.class), 30));
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(1, 10, EnumSet.of(LicenseRight.LIVE), 0));
        assertThrows(IllegalArgumentException.class, () -> new LicensePolicy(1, 10, EnumSet.of(LicenseRight.LIVE), 366));
    }

    @Test
    void deviceCountCannotExceedTheLimitEvenInTheModel() {
        License l = issued(5);
        assertThrows(IllegalArgumentException.class, () -> new License(l.id(), l.customerEmail(), l.status(), l.policy(),
                l.createdAt(), l.activationDeadline(), null, null, null, null, l.updatedAt(), 2, 0));
    }
}
