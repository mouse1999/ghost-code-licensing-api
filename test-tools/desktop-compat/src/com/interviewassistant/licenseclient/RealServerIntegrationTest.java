package com.interviewassistant.licenseclient;

import com.interviewassistant.licenseclient.api.HttpLicensingApi;
import com.interviewassistant.licenseclient.crypto.EntitlementVerifier;
import com.interviewassistant.licenseclient.crypto.TrustedKeys;
import com.interviewassistant.licenseclient.model.LicenseState.Kind;
import com.interviewassistant.licenseclient.service.ActivationResult;
import com.interviewassistant.licenseclient.service.ActivationResult.Failure;
import com.interviewassistant.licenseclient.service.ActivationResult.Reason;
import com.interviewassistant.licenseclient.service.ActivationService;
import com.interviewassistant.licenseclient.service.LicenseStateService;
import com.interviewassistant.licenseclient.storage.ActivationStateStore;
import com.interviewassistant.licenseclient.storage.DeviceKeyStore;
import com.interviewassistant.licenseclient.support.MemoryCredentialStore;
import com.interviewassistant.licensing.service.RealServerHarness;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The desktop client over REAL HTTP against the REAL Phase 128 ClientLicenseService (proof verification, device limit,
 * entitlement signing, status handling). Only the Spring controller layer is replaced by RealServerHarness; the in-memory store
 * stands in for PostgreSQL.
 */
class RealServerIntegrationTest {

    RealServerHarness server;

    /** One simulated installation: its own credential store, data directory and clock. */
    final class Install {
        final MemoryCredentialStore cs = new MemoryCredentialStore();
        final DeviceKeyStore keys = new DeviceKeyStore(cs);
        ActivationStateStore state;
        Clock clock = server.clock();

        Install() throws Exception {
            state = new ActivationStateStore(Files.createTempDirectory("p129-it"));
        }

        ActivationService activation() {
            return new ActivationService(new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5)), keys, state,
                    verifier(), clock, ms -> { }, 3, "it-pc", true);
        }

        LicenseStateService states() {
            return new LicenseStateService(new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5)), keys,
                    state, verifier(), true, clock);
        }

        ActivationResult activate(String email, String code) {
            return activation().activate(email, code.toCharArray());
        }
    }

    EntitlementVerifier verifier() {
        return new EntitlementVerifier(new TrustedKeys(Map.of(server.kid(), server.publicKey())), server.issuer(), Duration.ofMinutes(5));
    }

    @BeforeEach
    void up() throws Exception {
        server = new RealServerHarness();
    }

    @AfterEach
    void down() {
        server.close();
    }

    @Test
    void activationAgainstTheRealServerWorksAndIsIdempotent() throws Exception {
        var issued = server.issue("Customer@Example.com", 1);
        UUID id = issued.license().id();
        Install a = new Install();
        ActivationResult r = a.activate("customer@example.com", issued.activationCode());
        assertTrue(r instanceof ActivationResult.Success s && !s.alreadyRegistered(), String.valueOf(r));
        assertEquals(Kind.ACTIVE, a.states().current().kind());
        assertEquals(1, server.activeDevices(id));
        // local record lost, key kept: the retry is recognised as the same device, no second registration
        a.state = new ActivationStateStore(Files.createTempDirectory("p129-it2"));
        ActivationResult again = a.activate("customer@example.com", issued.activationCode());
        assertTrue(again instanceof ActivationResult.Success s2 && s2.alreadyRegistered(), String.valueOf(again));
        assertEquals(1, server.activeDevices(id));
    }

    @Test
    void wrongCodeGetsTheGenericMessageAndNoKeyIsRegisteredOnTheServer() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install a = new Install();
        String wellFormedWrong = "0".repeat(32); // right format, not issued
        Failure f = (Failure) a.activate("c@example.com", wellFormedWrong);
        assertEquals(Reason.INVALID_CREDENTIALS, f.reason());
        assertFalse(f.retryable());
        assertEquals(0, server.activeDevices(issued.license().id()));
        Failure unknownAccount = (Failure) a.activate("nobody@example.com", wellFormedWrong);
        assertEquals(f.message(), unknownAccount.message(), "no account/code oracle");
    }

    /** Compatibility finding: the real server answers a code of the wrong FORMAT with 400 VALIDATION_FAILED, not INVALID_CREDENTIALS. */
    @Test
    void aMalformedCodeIsReportedAsAFormatProblemNotAServerFault() throws Exception {
        Install a = new Install();
        Failure f = (Failure) a.activate("c@example.com", "WRONG-CODE-1234");
        assertEquals(Reason.INVALID_INPUT, f.reason());
        assertFalse(f.retryable());
        assertTrue(f.message().contains("expected format"));
    }

    @Test
    void deviceLimitIsEnforcedAndNoKeyRegenerationBypassesIt() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install first = new Install();
        assertTrue(first.activate("c@example.com", issued.activationCode()) instanceof ActivationResult.Success);
        Install second = new Install();
        Failure f = (Failure) second.activate("c@example.com", issued.activationCode());
        assertEquals(Reason.DEVICE_LIMIT, f.reason());
        String keyBefore = second.keys.load().key().thumbprint();
        assertEquals(Reason.DEVICE_LIMIT, ((Failure) second.activate("c@example.com", issued.activationCode())).reason());
        assertEquals(keyBefore, second.keys.load().key().thumbprint(), "same key kept; no regeneration to dodge the limit");
        assertEquals(1, server.activeDevices(issued.license().id()));
        assertEquals(Kind.ACTIVE, first.states().current().kind());
    }

    @Test
    void entitlementExpiresWithoutGraceAndRefreshRenewsIt() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install a = new Install();
        a.activate("c@example.com", issued.activationCode());
        assertFalse(a.states().refreshAdvisable());
        server.advance(Duration.ofDays(4)); // past renewAfter (ttl 7d)
        assertTrue(a.states().refreshAdvisable());
        assertEquals(Kind.ACTIVE, a.states().refresh().kind());
        server.advance(Duration.ofDays(8)); // never refreshed: expired, not honoured
        assertEquals(Kind.ENTITLEMENT_EXPIRED, a.states().current().kind());
        assertEquals(Kind.ACTIVE, a.states().refresh().kind(), "renewed from the server");
    }

    @Test
    void suspensionAndRevocationAreLearnedOnRefreshAndDropTheCachedEntitlement() throws Exception {
        var issued = server.issue("c@example.com", 2);
        UUID id = issued.license().id();
        Install a = new Install();
        a.activate("c@example.com", issued.activationCode());
        server.suspend(id);
        assertEquals(Kind.SUSPENDED, a.states().refresh().kind());
        assertEquals(Kind.SUSPENDED, a.states().current().kind());
        assertFalse(Files.readString(a.state.file()).contains("eyJ"));
        // a suspended license cannot be activated again either
        assertEquals(Reason.LICENSE_STATUS, ((Failure) new Install().activate("c@example.com", issued.activationCode())).reason());
    }

    @Test
    void revokedLicenseIsReportedRevoked() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install a = new Install();
        a.activate("c@example.com", issued.activationCode());
        server.revoke(issued.license().id());
        assertEquals(Kind.REVOKED, a.states().refresh().kind());
    }

    @Test
    void aBadlyWrongComputerClockIsReportedAsAClockProblem() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install a = new Install();
        a.clock = Clock.offset(server.clock(), Duration.ofMinutes(20));
        Failure f = (Failure) a.activate("c@example.com", issued.activationCode());
        assertEquals(Reason.CLOCK, f.reason());
        assertTrue(f.message().contains("date and time"));
    }

    @Test
    void anEntitlementFromAnotherDeviceCannotBeReplayedOntoThisOne() throws Exception {
        var issued = server.issue("c@example.com", 2);
        Install a = new Install();
        Install b = new Install();
        a.activate("c@example.com", issued.activationCode());
        b.activate("c@example.com", issued.activationCode());
        // copy A's record into B: its token names A's key thumbprint, B holds a different key
        b.state.save(((ActivationStateStore.Loaded.Present) a.state.load()).record());
        assertEquals(Kind.RECORD_INVALID, b.states().current().kind());
    }

    @Test
    void trustedKeyOfAnotherServerRejectsTheRealServersAnswer() throws Exception {
        var issued = server.issue("c@example.com", 1);
        Install a = new Install();
        var other = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair().getPublic();
        var strict = new EntitlementVerifier(new TrustedKeys(Map.of(server.kid(), other)), server.issuer(), Duration.ofMinutes(5));
        var svc = new ActivationService(new HttpLicensingApi(server.baseUrl(), Duration.ofSeconds(2), Duration.ofSeconds(5)), a.keys,
                a.state, strict, server.clock(), ms -> { }, 1, "pc", true);
        assertEquals(Reason.VERIFICATION, ((Failure) svc.activate("c@example.com", issued.activationCode().toCharArray())).reason());
        assertFalse(Files.exists(a.state.file()));
    }
}
