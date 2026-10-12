package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.crypto.EntitlementTokens;
import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.Entitlement;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.service.AdminLicenseService.RenewCommand;
import com.interviewassistant.licensing.service.AdminLicenseService.RenewMode;
import com.interviewassistant.licensing.service.AdminLicenseService.SearchResult;
import com.interviewassistant.licensing.service.AdminLicenseService.Stats;
import com.interviewassistant.licensing.service.ClientLicenseService.ActivationResult;
import com.interviewassistant.licensing.service.Fixture.Device;
import com.interviewassistant.licensing.service.IssuanceService.IssueCommand;
import com.interviewassistant.licensing.service.IssuanceService.IssueResult;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 133: what the admin portal relies on, through the real services and the in-memory store. (The portal's HTTP layer and the
 * SQL are checked elsewhere; this class proves the rules.)
 */
class AdminPortalServiceTest {

    private static final String CLIENT = "203.0.113.7";
    private final Fixture f = new Fixture();

    private static final LicensePolicy FIXED_TERM_POLICY = new LicensePolicy(1, null, Fixture.rights(LicenseRight.LIVE, LicenseRight.DSA), 30);

    private IssueResult issueFixed(String email, Instant end) {
        return f.issuance.issue(f.fullAdmin, new IssueCommand(email, true, "ref-1", FIXED_TERM_POLICY, UUID.randomUUID().toString(), end));
    }

    private ActivationResult activate(IssueResult i, Device d) {
        return f.client.activate(f.activation(d, i.license().customerEmail(), i.activationCode(), CLIENT));
    }

    private static ErrorCode codeOf(Runnable r) {
        return assertThrows(LicensingException.class, r::run).code();
    }

    private AdminPrincipal only(AdminScope... scopes) {
        return new AdminPrincipal("limited", EnumSet.copyOf(List.of(scopes)));
    }

    private License stored(UUID id) {
        return f.store.license(id);
    }

    // ------------------------------------------------------------------ issuance

    @Test
    void nothingIsStoredUnlessTheAdministratorConfirmsPaymentAndEveryRefusalLeavesNothingBehind() {
        LicensePolicy p = new LicensePolicy(1, 30, Fixture.rights(LicenseRight.DSA), 30);
        assertEquals(ErrorCode.PAYMENT_NOT_CONFIRMED, codeOf(() ->
                f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", false, "ref", p, UUID.randomUUID().toString()))));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() ->
                f.issuance.issue(f.fullAdmin, new IssueCommand("not-an-email", true, "ref", p, UUID.randomUUID().toString()))));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() ->
                f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref", p, "short"))));
        assertEquals(0, f.store.licenseCount(), "a refused issuance must create no customer or license record");
        assertTrue(f.store.allAudit().isEmpty());
        f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref", p, UUID.randomUUID().toString()));
        assertEquals(1, f.store.licenseCount());
    }

    @Test
    void aCustomDurationCountsFromActivationAndIsPersisted() {
        IssueResult issued = f.issue("a@example.com", 1, 45);
        assertNull(stored(issued.license().id()).expiresAt(), "the term has not started before activation");
        ActivationResult r = activate(issued, f.newDevice());
        assertEquals(f.clock.instant().plus(Duration.ofDays(45)), r.licenseExpiresAt());
        assertEquals(f.clock.instant().plus(Duration.ofDays(45)), stored(issued.license().id()).expiresAt());
    }

    @Test
    void anExplicitEndDateIsStoredAtIssuanceKeptAtActivationAndCarriedInTheSignedEntitlement() {
        Instant end = f.clock.instant().plus(Duration.ofDays(100)).plusMillis(789);   // sub-second part is dropped
        IssueResult issued = issueFixed("a@example.com", end);
        Instant whole = end.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        assertEquals(whole, stored(issued.license().id()).expiresAt());
        assertEquals(LicenseStatus.PENDING, stored(issued.license().id()).status());

        f.clock.advance(Duration.ofDays(10));   // activating later does not move the end date
        ActivationResult r = activate(issued, f.newDevice());
        assertEquals(whole, r.licenseExpiresAt());
        Entitlement e = EntitlementTokens.verify(r.entitlement(), f.ring.publicKeys(), f.clock.instant());
        assertEquals(whole, e.licenseExpiresAt(), "the desktop's signed entitlement carries the fixed end date");
    }

    @Test
    void aDurationAndAnEndDateTogetherAreRefusedAndSoAreDatesInThePastOrTooFarAway() {
        LicensePolicy withTerm = new LicensePolicy(1, 30, Fixture.rights(LicenseRight.DSA), 30);
        Instant later = f.clock.instant().plus(Duration.ofDays(60));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.issuance.issue(f.fullAdmin,
                new IssueCommand("a@example.com", true, "ref", withTerm, UUID.randomUUID().toString(), later))));
        for (Instant bad : List.of(f.clock.instant().minusSeconds(1), f.clock.instant(), f.clock.instant().plus(Duration.ofDays(3651)))) {
            assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> issueFixed("a@example.com", bad)), String.valueOf(bad));
        }
        assertEquals(0, f.store.licenseCount());
    }

    @Test
    void aFixedEndDateThatPassesBeforeActivationMakesTheCodeUnusable() {
        IssueResult issued = issueFixed("a@example.com", f.clock.instant().plus(Duration.ofDays(5)));
        f.clock.advance(Duration.ofDays(6));
        assertEquals(LicenseStatus.EXPIRED, f.admin.get(f.fullAdmin, issued.license().id()).effectiveStatus());
        assertEquals(ErrorCode.LICENSE_EXPIRED, codeOf(() -> activate(issued, f.newDevice())));
        assertEquals(0, stored(issued.license().id()).activeDeviceCount());
    }

    @Test
    void repeatedSubmissionsOfTheSameFormCreateOneLicenseAndNeverShowTheCodeAgain() {
        LicensePolicy p = new LicensePolicy(1, 30, Fixture.rights(LicenseRight.DSA), 30);
        String key = "form-submission-0001";
        IssueResult first = f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref", p, key));
        IssueResult again = f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref", p, key));
        assertNotNull(first.activationCode());
        assertTrue(again.replayed());
        assertNull(again.activationCode(), "the raw code is shown once only");
        assertEquals(first.license().id(), again.license().id());
        assertEquals(1, f.store.licenseCount());
        // the same key with a different request (here: a different end date) is a conflict, not a second license
        Instant end = f.clock.instant().plus(Duration.ofDays(20));
        LicensePolicy noTerm = new LicensePolicy(1, null, Fixture.rights(LicenseRight.DSA), 30);
        assertEquals(ErrorCode.IDEMPOTENCY_KEY_REUSED, codeOf(() -> f.issuance.issue(f.fullAdmin,
                new IssueCommand("a@example.com", true, "ref", noTerm, key, end))));
        assertEquals(1, f.store.licenseCount());
    }

    @Test
    void manySimultaneousSubmissionsOfOneFormCreateExactlyOneLicense() throws Exception {
        LicensePolicy p = new LicensePolicy(1, 30, Fixture.rights(LicenseRight.DSA), 30);
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<IssueResult>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            results.add(pool.submit(() -> {
                go.await();
                return f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref", p, "double-click-key-0001"));
            }));
        }
        go.countDown();
        int withCode = 0;
        for (Future<IssueResult> r : results) {
            if (r.get(10, TimeUnit.SECONDS).activationCode() != null) {
                withCode++;
            }
        }
        pool.shutdownNow();
        assertEquals(1, f.store.licenseCount());
        assertEquals(1, withCode, "exactly one submission receives the code");
    }

    @Test
    void theIssuedCodeActivatesThroughTheDesktopFlowAndOnlyTheHashIsStored() {
        IssueResult issued = f.issue("a@example.com", 1, 365);
        assertFalse(f.store.dumpEverythingStored().contains(issued.activationCode()), "the raw code is never persisted");
        ActivationResult r = activate(issued, f.newDevice());
        assertEquals(LicenseStatus.ACTIVE, r.status());
        Entitlement e = EntitlementTokens.verify(r.entitlement(), f.ring.publicKeys(), f.clock.instant());
        assertEquals(issued.license().id(), e.licenseId());
    }

    // ------------------------------------------------------------------ renewal

    private record Activated(UUID id, Device device, ActivationResult activation) {
    }

    private Activated activatedLicense(int days) {
        IssueResult issued = f.issue("renew@example.com", 1, days);
        Device d = f.newDevice();
        return new Activated(issued.license().id(), d, activate(issued, d));
    }

    private void validate(Activated a) {
        f.client.validate(f.deviceRequest(a.device(), "validate", a.id(), a.activation().deviceRegistrationId(), CLIENT));
    }

    @Test
    void extendingAnActiveLicenseAddsDaysToTheCurrentEndAndTouchesNothingElse() {
        Activated a = activatedLicense(30);
        License before = stored(a.id());
        Instant end = before.expiresAt();
        f.clock.advance(Duration.ofDays(5));
        License after = f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 90, null, "paid again")).license();
        assertEquals(end.plus(Duration.ofDays(90)), after.expiresAt());
        assertEquals(LicenseStatus.ACTIVE, after.status());
        assertEquals(before.activatedAt(), after.activatedAt());
        assertEquals(before.policy(), after.policy());
        assertEquals(1, after.activeDeviceCount(), "the device binding is not reset");
        assertEquals(before.suspendedAt(), after.suspendedAt());
    }

    @Test
    void renewingAnExpiredLicenseKeepsTheExistingDeviceWorkingWithoutReactivation() {
        Activated a = activatedLicense(30);
        f.clock.advance(Duration.ofDays(40));
        assertEquals(ErrorCode.LICENSE_EXPIRED, codeOf(() -> validate(a)));
        assertEquals(LicenseStatus.EXPIRED, stored(a.id()).status(), "validation brought the stored status up to date");

        Instant now = f.clock.instant();
        License renewed = f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, "late payment")).license();
        assertEquals(now.plus(Duration.ofDays(30)), renewed.expiresAt(), "extending a lapsed license counts from now, not from the past");
        assertEquals(LicenseStatus.ACTIVE, renewed.status());
        assertEquals(1, renewed.activeDeviceCount());
        assertDoesNotThrow(() -> validate(a), "the SAME registered device validates again; no new activation, no second slot");
        assertEquals(1, f.store.deviceCount(a.id()));
    }

    @Test
    void anExactEndDateCanBeSetIncludingOnALicenseThatNeverExpired() {
        IssueResult issued = f.issue("a@example.com", 1, null);   // no term
        activate(issued, f.newDevice());
        UUID id = issued.license().id();
        assertEquals(ErrorCode.VALIDATION_FAILED,
                codeOf(() -> f.admin.renew(f.fullAdmin, id, new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, ""))),
                "extending would silently impose an end date");
        assertNull(stored(id).expiresAt());
        Instant end = f.clock.instant().plus(Duration.ofDays(200));
        assertEquals(end, f.admin.renew(f.fullAdmin, id, new RenewCommand(RenewMode.SET_END, null, end, "annual plan")).license().expiresAt());
    }

    @Test
    void renewalRulesRevokedAndNeverActivatedAreRefusedAndASuspendedLicenseStaysSuspended() {
        Activated a = activatedLicense(30);
        f.admin.suspend(f.fullAdmin, a.id(), "review");
        License r = f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, "")).license();
        assertEquals(LicenseStatus.SUSPENDED, r.status(), "renewal does not silently reinstate");
        assertEquals(LicenseStatus.ACTIVE, f.admin.reinstate(f.fullAdmin, a.id(), "ok").license().status());

        f.admin.revoke(f.fullAdmin, a.id(), "refund");
        assertEquals(ErrorCode.ILLEGAL_TRANSITION,
                codeOf(() -> f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, ""))));
        assertEquals(LicenseStatus.REVOKED, stored(a.id()).status());

        UUID pending = f.issue("p@example.com", 1, 30).license().id();
        assertEquals(ErrorCode.ILLEGAL_TRANSITION,
                codeOf(() -> f.admin.renew(f.fullAdmin, pending, new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, ""))));
        assertEquals(ErrorCode.LICENSE_NOT_FOUND,
                codeOf(() -> f.admin.renew(f.fullAdmin, UUID.randomUUID(), new RenewCommand(RenewMode.EXTEND_DAYS, 30, null, ""))));
    }

    @Test
    void renewalInputsAreValidatedAndMustBeExplicit() {
        Activated a = activatedLicense(30);
        Instant past = f.clock.instant().minusSeconds(60);
        Instant far = f.clock.instant().plus(Duration.ofDays(4000));
        List<RenewCommand> bad = List.of(
                new RenewCommand(null, 30, null, ""),
                new RenewCommand(RenewMode.EXTEND_DAYS, null, null, ""),
                new RenewCommand(RenewMode.EXTEND_DAYS, 0, null, ""),
                new RenewCommand(RenewMode.EXTEND_DAYS, 3651, null, ""),
                new RenewCommand(RenewMode.EXTEND_DAYS, 30, f.clock.instant().plus(Duration.ofDays(1)), ""),
                new RenewCommand(RenewMode.SET_END, null, null, ""),
                new RenewCommand(RenewMode.SET_END, 30, f.clock.instant().plus(Duration.ofDays(1)), ""),
                new RenewCommand(RenewMode.SET_END, null, past, ""),
                new RenewCommand(RenewMode.SET_END, null, far, ""),
                new RenewCommand(RenewMode.SET_END, null, f.clock.instant().plus(Duration.ofDays(1)), "x".repeat(201)));
        Instant end = stored(a.id()).expiresAt();
        for (RenewCommand c : bad) {
            assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.admin.renew(f.fullAdmin, a.id(), c)), String.valueOf(c));
        }
        assertEquals(end, stored(a.id()).expiresAt(), "no refused renewal changed anything");
    }

    @Test
    void everySuccessfulAndRefusedMutationIsAudited() {
        Activated a = activatedLicense(30);
        Instant oldEnd = stored(a.id()).expiresAt();
        f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 15, null, "invoice 42"));
        AuditEvent ok = f.admin.audit(f.fullAdmin, a.id(), null, 1).get(0);
        assertEquals(AuditAction.LICENSE_RENEWED, ok.action());
        assertEquals(AuditOutcome.SUCCESS, ok.outcome());
        assertEquals("admin:dev", ok.actor());
        assertTrue(ok.detail().contains("expiresFrom=" + oldEnd), ok.detail());
        assertTrue(ok.detail().contains("expiresTo=" + oldEnd.plus(Duration.ofDays(15))), ok.detail());
        assertTrue(ok.detail().contains("note=invoice 42") && ok.detail().contains("mode=EXTEND_DAYS"), ok.detail());

        f.admin.revoke(f.fullAdmin, a.id(), "");
        codeOf(() -> f.admin.renew(f.fullAdmin, a.id(), new RenewCommand(RenewMode.EXTEND_DAYS, 15, null, "")));
        AuditEvent refused = f.admin.audit(f.fullAdmin, a.id(), null, 1).get(0);
        assertEquals(AuditAction.LICENSE_RENEWED, refused.action());
        assertEquals(AuditOutcome.FAILURE, refused.outcome());
    }

    // ------------------------------------------------------------------ authorization

    @Test
    void everyNewOperationChecksItsOwnScope() {
        Activated a = activatedLicense(30);
        AdminPrincipal issueOnly = only(AdminScope.LICENSE_ISSUE);
        AdminPrincipal readOnly = only(AdminScope.LICENSE_READ);
        RenewCommand c = new RenewCommand(RenewMode.EXTEND_DAYS, 10, null, "");
        assertEquals(ErrorCode.FORBIDDEN, codeOf(() -> f.admin.renew(issueOnly, a.id(), c)));
        assertEquals(ErrorCode.FORBIDDEN, codeOf(() -> f.admin.renew(readOnly, a.id(), c)));
        assertEquals(ErrorCode.FORBIDDEN, codeOf(() -> f.admin.search(issueOnly, "a", null, 10, 0)));
        assertEquals(ErrorCode.FORBIDDEN, codeOf(() -> f.admin.stats(issueOnly)));
        assertDoesNotThrow(() -> f.admin.search(readOnly, "a", null, 10, 0));
        assertDoesNotThrow(() -> f.admin.stats(readOnly));
    }

    // ------------------------------------------------------------------ search

    @Test
    void searchMatchesALiteralCaseInsensitiveFragmentNotAPattern() {
        f.issue("Alice.Smith@Example.com", 1, 30);
        f.issue("bob_x@example.com", 1, 30);
        f.issue("bobyx@example.com", 1, 30);
        assertEquals(1, f.admin.search(f.fullAdmin, "ALICE", null, 10, 0).items().size());
        assertEquals(3, f.admin.search(f.fullAdmin, "@example.com", null, 10, 0).items().size());
        assertEquals(1, f.admin.search(f.fullAdmin, "bob_x", null, 10, 0).items().size(), "'_' is not a wildcard");
        assertEquals(0, f.admin.search(f.fullAdmin, "%", null, 10, 0).items().size(), "'%' is not a wildcard");
        assertEquals(3, f.admin.search(f.fullAdmin, "  ", null, 10, 0).items().size(), "blank means no filter");
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.admin.search(f.fullAdmin, "a".repeat(101), null, 10, 0)));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.admin.search(f.fullAdmin, "a\nb", null, 10, 0)));
        assertEquals(ErrorCode.VALIDATION_FAILED, codeOf(() -> f.admin.search(f.fullAdmin, "a", null, 10, -1)));
    }

    @Test
    void searchFiltersByEffectiveStatusAndPagesWithoutOverReporting() {
        Activated a = activatedLicense(30);              // will expire
        f.issue("pending1@example.com", 1, 30);
        f.issue("pending2@example.com", 1, 30);
        f.clock.advance(Duration.ofDays(31));            // a's term ended; the pending ones' 30-day window ended too
        f.issue("fresh@example.com", 1, 30);
        assertEquals(1, f.admin.search(f.fullAdmin, null, LicenseStatus.PENDING, 10, 0).items().size());
        assertEquals(3, f.admin.search(f.fullAdmin, null, LicenseStatus.EXPIRED, 10, 0).items().size());
        SearchResult page1 = f.admin.search(f.fullAdmin, null, null, 2, 0);
        assertEquals(2, page1.items().size());
        assertTrue(page1.hasMore());
        SearchResult page2 = f.admin.search(f.fullAdmin, null, null, 2, 2);
        assertEquals(2, page2.items().size());
        assertFalse(page2.hasMore());
        assertEquals(LicenseStatus.EXPIRED, f.admin.get(f.fullAdmin, a.id()).effectiveStatus());
    }

    // ------------------------------------------------------------------ analytics

    @Test
    void statisticsMatchThePersistedRecordsAndSeparateUnavailableFromZero() {
        Stats empty = f.admin.stats(f.fullAdmin);
        assertEquals(0, empty.licenses().total());
        assertNull(empty.activity().recordedSince(), "no events yet: the figures are real zeros and say so");
        assertEquals(0, empty.activity().allRecorded().activationSuccesses());

        Activated active = activatedLicense(365);                                             // ACTIVE, 1 activation success
        Activated willExpire = activatedLicense(10);                                          // becomes expired-after-activation
        UUID suspended = f.issue("s@example.com", 1, 365).license().id();
        f.admin.suspend(f.fullAdmin, suspended, "");
        UUID revoked = f.issue("r@example.com", 1, 365).license().id();
        f.admin.revoke(f.fullAdmin, revoked, "");
        UUID pending = f.issue("p@example.com", 1, 365).license().id();
        IssueResult lapsing = f.issue("l@example.com", 1, 365);                              // window will pass unactivated
        // an activation attempt with a wrong code is recorded as a failure
        Device d = f.newDevice();
        assertEquals(ErrorCode.INVALID_CREDENTIALS, codeOf(() ->
                f.client.activate(f.activation(d, "l@example.com", "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH", CLIENT))));
        f.clock.advance(Duration.ofDays(11));
        f.admin.get(f.fullAdmin, willExpire.id());

        Stats s = f.admin.stats(f.fullAdmin);
        assertEquals(6, s.licenses().total(), "6 licenses were issued in this test");
        assertEquals(1, s.licenses().suspended());
        assertEquals(1, s.licenses().revoked());
        assertEquals(1 + 1 + 1, s.licenses().active() + s.licenses().pending(), "the long active one + the two 365-day pending");
        assertEquals(1, s.licenses().expiredAfterActivation());
        assertEquals(0, s.licenses().lapsedUnactivated());
        assertEquals(s.licenses().total(), s.licenses().pending() + s.licenses().active() + s.licenses().expiredAfterActivation()
                + s.licenses().lapsedUnactivated() + s.licenses().suspended() + s.licenses().revoked(), "the groups add up");
        assertEquals(2, s.activity().allRecorded().activationSuccesses());
        assertEquals(1, s.activity().allRecorded().activationFailures());
        assertEquals(6, s.activity().allRecorded().licensesIssued());
        assertFalse(s.recent().isEmpty());
        assertTrue(s.recent().size() <= 15);
        assertNotNull(active);
        assertNotNull(pending);
        assertNotNull(lapsing);
    }

    @Test
    void withoutTheAuditScopeActivityFiguresAreUnavailableNotZero() {
        activatedLicense(30);
        Stats s = f.admin.stats(only(AdminScope.LICENSE_READ));
        assertEquals(1, s.licenses().total());
        assertNull(s.activity(), "unavailable, so null rather than a fabricated zero");
        assertNull(s.recent());
    }

    @Test
    void anUnactivatedLicenseWhoseWindowPassedIsCountedSeparatelyFromAnExpiredSubscription() {
        f.issue("a@example.com", 1, 30);
        f.clock.advance(Duration.ofDays(31));
        Stats s = f.admin.stats(f.fullAdmin);
        assertEquals(1, s.licenses().lapsedUnactivated());
        assertEquals(0, s.licenses().expiredAfterActivation());
    }
}
