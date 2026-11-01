package com.interviewassistant.licenseclient;

import com.interviewassistant.licenseclient.api.HttpLicensingApi;
import com.interviewassistant.licenseclient.crypto.EntitlementVerifier;
import com.interviewassistant.licenseclient.crypto.TrustedKeys;
import com.interviewassistant.licenseclient.model.LicenseState;
import com.interviewassistant.licenseclient.model.LicenseState.Kind;
import com.interviewassistant.licenseclient.service.ActivationResult;
import com.interviewassistant.licenseclient.service.ActivationResult.Failure;
import com.interviewassistant.licenseclient.service.ActivationResult.Reason;
import com.interviewassistant.licenseclient.service.ActivationService;
import com.interviewassistant.licenseclient.service.LicenseStateService;
import com.interviewassistant.licenseclient.service.ServerValidation;
import com.interviewassistant.licenseclient.storage.ActivationStateStore;
import com.interviewassistant.licenseclient.storage.DeviceKeyStore;
import com.interviewassistant.licenseclient.support.MemoryCredentialStore;
import com.interviewassistant.licensing.service.RealServerHarness;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 134: the subscription lifecycle (fixed expiry, renewal, suspension, reinstatement, revocation) end to end: the real desktop
 * licenseclient -> HTTP -> real controllers/DTOs/services -> real JdbcLicenseStore on PostgreSQL, with the server clock under test
 * control. Admin actions go through the real admin API. (HttpHarness replaces Spring MVC/Jackson; see its Javadoc.)
 */
class Phase134LifecycleDesktopTest {

    RealServerHarness server;

    @BeforeEach void up() throws Exception { server = new RealServerHarness(); }
    @AfterEach void down() { server.close(); }

    final class Install {
        final MemoryCredentialStore cs = new MemoryCredentialStore();
        final DeviceKeyStore keys = new DeviceKeyStore(cs);
        final ActivationStateStore state;
        Install() throws Exception { state = new ActivationStateStore(Files.createTempDirectory("p134-it")); }
        EntitlementVerifier verifier() { return new EntitlementVerifier(new TrustedKeys(Map.of(server.kid(), server.publicKey())), server.issuer(), Duration.ofMinutes(5)); }
        ActivationService activation() {
            return new ActivationService(new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5)), keys, state, verifier(), server.clock(), ms -> { }, 3, "it-pc", true);
        }
        LicenseStateService states() {
            return new LicenseStateService(new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5)), keys, state, verifier(), true, server.clock());
        }
        ActivationResult activate(String email, String code) { return activation().activate(email, code.toCharArray()); }
    }

    private Instant now() { return server.clock().instant(); }

    private static void near(Instant expected, Instant actual, String msg) {
        assertTrue(Math.abs(Duration.between(expected, actual).toSeconds()) <= 2, msg + ": expected " + expected + " but was " + actual);
    }

    @Test
    void aPresetLicenseTermStartsAtActivationAndTheDesktopHoldsAnEntitlementWithinIt() throws Exception {
        var issued = server.issuePreset("preset@example.com", 3);
        server.advance(Duration.ofDays(2));                                      // issued 2 days before the customer activates
        Install a = new Install();
        LicenseState s = ((ActivationResult.Success) a.activate("preset@example.com", issued.activationCode())).state();
        near(now().plus(Duration.ofDays(3)), s.entitlementExpiresAt(), "3-day term counted from activation, not from issuance (capped by the 7-day entitlement ttl)");
        assertTrue(server.get(issued.license().id()).body().contains("\"effectiveStatus\":\"ACTIVE\""));
    }

    @Test
    void aFixedExpiryIsKeptAtActivationAndCarriedToTheDesktop() throws Exception {
        Instant end = now().plus(Duration.ofDays(5)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var issued = server.issueFixed("fixed@example.com", end);
        server.advance(Duration.ofDays(2));
        Install a = new Install();
        LicenseState s = ((ActivationResult.Success) a.activate("fixed@example.com", issued.activationCode())).state();
        assertEquals(end, s.entitlementExpiresAt(), "the original fixed end survives activation and bounds the signed entitlement exactly");
        assertTrue(server.get(issued.license().id()).body().contains("\"expiresAt\":\"" + end + "\""));
        server.advance(Duration.ofDays(4));                                      // past the fixed end
        assertEquals(Kind.LICENSE_EXPIRED, a.states().refresh().kind(), "after the end date the desktop is told the subscription expired");
        assertEquals(Kind.LICENSE_EXPIRED, a.states().current().kind());
    }

    @Test
    void aFixedExpiryPendingLicenseCannotBeActivatedAfterItsExpiry() throws Exception {
        Instant end = now().plus(Duration.ofDays(2)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        var issued = server.issueFixed("late@example.com", end);
        server.advance(Duration.ofDays(3));
        Install a = new Install();
        Failure f = (Failure) a.activate("late@example.com", issued.activationCode());
        assertEquals(Reason.LICENSE_STATUS, f.reason(), String.valueOf(f));
        assertEquals(0, server.activeDevices(issued.license().id()), "no device was registered");
        assertEquals(Kind.NOT_ACTIVATED, a.states().current().kind());
    }

    @Test
    void renewingAnExpiredLicenseRestoresTheSameDeviceWithoutReactivation() throws Exception {
        var issued = server.issuePreset("renew@example.com", 2);
        Install a = new Install();
        a.activate("renew@example.com", issued.activationCode());
        server.advance(Duration.ofDays(3));
        assertEquals(Kind.LICENSE_EXPIRED, a.states().refresh().kind());
        assertEquals(1, server.activeDevices(issued.license().id()), "the device stays bound while expired");
        var r = server.renewDays(issued.license().id(), 30);
        assertEquals(200, r.status(), r.body());
        LicenseState s = a.states().refresh();                                   // same install, same key, no activation code
        assertEquals(Kind.ACTIVE, s.kind(), "expired -> active after renewal, with no reactivation");
        assertEquals(1, server.activeDevices(issued.license().id()));
        near(now().plus(Duration.ofDays(7)), s.entitlementExpiresAt(), "renewed term is longer than the entitlement ttl, so the ttl applies");
    }

    @Test
    void renewalToAnExactDateIsTheDateTheDesktopSees() throws Exception {
        var issued = server.issuePreset("exact@example.com", 30);
        Install a = new Install();
        a.activate("exact@example.com", issued.activationCode());
        Instant newEnd = now().plus(Duration.ofDays(2)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertEquals(200, server.renewTo(issued.license().id(), newEnd).status());
        LicenseState s = a.states().refresh();
        assertEquals(newEnd, s.entitlementExpiresAt(), "shortened exact end is honoured by the signed entitlement");
    }

    @Test
    void aSuspendedLicenseStaysSuspendedAfterRenewalUntilReinstated() throws Exception {
        var issued = server.issuePreset("susp@example.com", 10);
        UUID id = issued.license().id();
        Install a = new Install();
        a.activate("susp@example.com", issued.activationCode());
        assertEquals(200, server.suspend(id).status());
        assertEquals(Kind.SUSPENDED, a.states().refresh().kind());
        assertEquals(200, server.renewDays(id, 60).status());
        assertTrue(server.get(id).body().contains("\"effectiveStatus\":\"SUSPENDED\""), "renewal did not reinstate");
        assertEquals(Kind.SUSPENDED, a.states().refresh().kind(), "the desktop still sees it suspended");
        assertEquals(200, server.reinstate(id).status());
        assertEquals(Kind.ACTIVE, a.states().refresh().kind(), "reinstatement restores access to the same device");
    }

    @Test
    void revokedAndNeverActivatedLicensesCannotBeRenewedAndRevocationReachesTheDesktop() throws Exception {
        var never = server.issuePreset("never@example.com", 10);
        var r1 = server.renewDays(never.license().id(), 30);
        assertEquals(409, r1.status(), r1.body());
        assertTrue(r1.body().contains("ILLEGAL_TRANSITION"));
        var issued = server.issuePreset("rev@example.com", 10);
        Install a = new Install();
        a.activate("rev@example.com", issued.activationCode());
        assertEquals(200, server.revoke(issued.license().id()).status());
        assertEquals(409, server.renewDays(issued.license().id(), 30).status());
        assertEquals(Kind.REVOKED, a.states().refresh().kind());
        assertEquals(409, server.reinstate(issued.license().id()).status(), "revocation is permanent");
    }

    @Test
    void authoritativeValidationFollowsTheAdminActionsAndNoOfflineGraceExists() throws Exception {
        var issued = server.issuePreset("auth@example.com", 10);
        UUID id = issued.license().id();
        Install a = new Install();
        a.activate("auth@example.com", issued.activationCode());
        assertEquals(ServerValidation.Kind.VALIDATED, a.states().validateOnline().kind());
        server.suspend(id);
        assertEquals(ServerValidation.Kind.DENIED, a.states().validateOnline().kind());
        server.reinstate(id);
        assertEquals(ServerValidation.Kind.VALIDATED, a.states().validateOnline().kind(), "reinstated licenses recover");
        server.close();                                                          // the server goes away
        ServerValidation v = a.states().validateOnline();
        assertNotEquals(ServerValidation.Kind.VALIDATED, v.kind(), "an unreachable server never validates (no offline grace)");
        server = new RealServerHarness();                                        // so the @AfterEach has something to close
    }

    @Test
    void aSecondDeviceBeyondTheLimitIsRefusedAndTheFirstKeepsWorking() throws Exception {
        var issued = server.issuePreset("proof@example.com", 10);
        Install a = new Install();
        a.activate("proof@example.com", issued.activationCode());
        Install b = new Install();                                               // other device, same license, limit 1
        assertEquals(Reason.DEVICE_LIMIT, ((Failure) b.activate("proof@example.com", issued.activationCode())).reason());
        // (a validate/entitlement call signed with the WRONG device key is refused: covered by RealServerIntegrationTest.anEntitlementFromAnotherDevice... and ClientLicenseServiceTest)
        LicenseState sa = a.states().current();
        assertEquals(Kind.ACTIVE, sa.kind());
        assertEquals(1, server.activeDevices(issued.license().id()));
    }
}
