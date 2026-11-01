package com.interviewassistant.licenseclient;

import com.interviewassistant.licenseclient.api.HttpLicensingApi;
import com.interviewassistant.licenseclient.crypto.EntitlementVerifier;
import com.interviewassistant.licenseclient.crypto.TrustedKeys;
import com.interviewassistant.licenseclient.enforcement.EnforcementSettings;
import com.interviewassistant.licenseclient.enforcement.LicenseDecision.Outcome;
import com.interviewassistant.licenseclient.enforcement.LicenseDeniedException;
import com.interviewassistant.licenseclient.enforcement.LicenseEnforcementService;
import com.interviewassistant.licenseclient.service.ActivationService;
import com.interviewassistant.licenseclient.service.LicenseStateService;
import com.interviewassistant.licenseclient.storage.ActivationStateStore;
import com.interviewassistant.licenseclient.storage.DeviceKeyStore;
import com.interviewassistant.licenseclient.support.MemoryCredentialStore;
import com.interviewassistant.licensing.service.RealServerHarness;
import com.interviewassistant.session.InterviewMode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Phase 130 enforcement over REAL HTTP against the REAL Phase 128 ClientLicenseService (signed /client/entitlement). */
class EnforcementRealServerIntegrationTest {

    RealServerHarness server;
    MemoryCredentialStore cs;
    DeviceKeyStore keys;
    ActivationStateStore state;

    @BeforeEach
    void up() throws Exception {
        server = new RealServerHarness();
        cs = new MemoryCredentialStore();
        keys = new DeviceKeyStore(cs);
        state = new ActivationStateStore(Files.createTempDirectory("p130-it"));
    }

    @AfterEach
    void down() {
        server.close();
    }

    EntitlementVerifier verifier() {
        return new EntitlementVerifier(new TrustedKeys(Map.of(server.kid(), server.publicKey())), server.issuer(), Duration.ofMinutes(5));
    }

    HttpLicensingApi api() {
        return new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5));
    }

    LicenseEnforcementService enforcement() {
        LicenseStateService states = new LicenseStateService(api(), keys, state, verifier(), true, server.clock());
        return new LicenseEnforcementService(states, server.clock(),
                new EnforcementSettings(Duration.ofSeconds(60), Duration.ofSeconds(30), Duration.ofSeconds(5)));
    }

    void activate(String email, String code) {
        new ActivationService(api(), keys, state, verifier(), server.clock(), ms -> { }, 3, "it-pc", true)
                .activate(email, code.toCharArray());
    }

    @Test
    void notActivatedIsRefusedWithoutAnyServerSession() {
        try (LicenseEnforcementService e = enforcement()) {
            LicenseDeniedException x = assertThrows(LicenseDeniedException.class, () -> e.authorize(InterviewMode.DSA));
            assertEquals(Outcome.ACTIVATION_REQUIRED, x.decision().outcome());
        }
    }

    @Test
    void activatedDeviceIsAuthorizedOnlyAfterARealSignedServerConfirmation() {
        var issued = server.issue("c@example.com", 1);
        activate("c@example.com", issued.activationCode());
        try (LicenseEnforcementService e = enforcement()) {
            assertNotEquals(Outcome.ALLOWED, e.currentStatus().outcome(), "a stored record alone is not a confirmation");
            try (var scope = e.authorize(InterviewMode.LIVE)) {
                assertEquals(InterviewMode.LIVE, scope.mode());
            }
            assertEquals(Outcome.ALLOWED, e.currentStatus().outcome());
        }
    }

    @Test
    void everyAppStartMustRevalidateEvenWithAFreshLocalRecord() {
        var issued = server.issue("c@example.com", 1);
        activate("c@example.com", issued.activationCode());
        try (LicenseEnforcementService first = enforcement()) {
            first.authorize(InterviewMode.DSA).close();
        }
        try (LicenseEnforcementService restarted = enforcement()) {
            assertNotEquals(Outcome.ALLOWED, restarted.currentStatus().outcome(), "the confirmation is in memory only");
        }
    }

    @Test
    void suspensionAndRevocationOnTheServerDenyTheNextStartAndTheRunningSessionIsNotifiedOnRecheck() {
        var issued = server.issue("c@example.com", 1);
        activate("c@example.com", issued.activationCode());
        try (LicenseEnforcementService e = enforcement()) {
            AtomicReference<Outcome> invalidated = new AtomicReference<>();
            e.setInvalidationHandler(d -> invalidated.set(d.outcome()));
            e.authorize(InterviewMode.DSA).close();
            e.sessionStarted(InterviewMode.DSA);
            server.advance(Duration.ofSeconds(61));
            server.suspend(issued.license().id());
            e.recheckNow();
            assertEquals(Outcome.LICENSE_SUSPENDED, invalidated.get());
            LicenseDeniedException x = assertThrows(LicenseDeniedException.class, () -> e.authorize(InterviewMode.DSA));
            assertEquals(Outcome.LICENSE_SUSPENDED, x.decision().outcome());
        }
    }

    @Test
    void revokedLicenseIsDeniedAndNoGraceIsGivenAfterTheEntitlementWindow() {
        var issued = server.issue("c@example.com", 1);
        activate("c@example.com", issued.activationCode());
        server.revoke(issued.license().id());
        try (LicenseEnforcementService e = enforcement()) {
            LicenseDeniedException x = assertThrows(LicenseDeniedException.class, () -> e.authorize(InterviewMode.DSA));
            assertEquals(Outcome.LICENSE_REVOKED, x.decision().outcome());
        }
    }

    @Test
    void serverGoingAwayIsUnavailableNotAllowed() {
        var issued = server.issue("c@example.com", 1);
        activate("c@example.com", issued.activationCode());
        LicenseEnforcementService e = enforcement();
        server.close();
        try (e) {
            LicenseDeniedException x = assertThrows(LicenseDeniedException.class, () -> e.authorize(InterviewMode.DSA));
            assertEquals(Outcome.LICENSING_UNAVAILABLE, x.decision().outcome());
        }
    }

    @Test
    void theRightsTheServerGrantsDecideWhichModesAreAllowed() {
        var issued = server.issue("c@example.com", 1);   // the real server's test policy grants LIVE and DSA only
        activate("c@example.com", issued.activationCode());
        try (LicenseEnforcementService e = enforcement()) {
            e.authorize(InterviewMode.LIVE).close();
            e.authorize(InterviewMode.DSA).close();
            for (InterviewMode m : new InterviewMode[]{InterviewMode.AI_LIVE, InterviewMode.SCREEN_QUESTION}) {
                LicenseDeniedException x = assertThrows(LicenseDeniedException.class, () -> e.authorize(m), m.name());
                assertEquals(Outcome.NOT_ENTITLED, x.decision().outcome());
            }
        }
    }
}
