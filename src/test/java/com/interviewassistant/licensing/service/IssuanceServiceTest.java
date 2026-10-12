package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.service.IssuanceService.IssueCommand;
import com.interviewassistant.licensing.service.IssuanceService.IssueResult;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class IssuanceServiceTest {

    private final Fixture f = new Fixture();

    private LicensePolicy policy() {
        return new LicensePolicy(2, 365, EnumSet.of(LicenseRight.LIVE, LicenseRight.AI_LIVE), 14);
    }

    @Test
    void validManualIssuanceCreatesAPendingLicenseAndReturnsTheCodeOnce() {
        IssueResult r = f.issuance.issue(f.fullAdmin, new IssueCommand("  Customer@Example.COM ", true, "bank-2026-11-01", policy(), "key-0123456789abcdef"));
        assertFalse(r.replayed());
        assertNotNull(r.activationCode());
        assertTrue(r.activationCode().matches("([0-9A-Z]{4}-){7}[0-9A-Z]{4}"));
        assertEquals("customer@example.com", r.license().customerEmail());
        assertEquals(LicenseStatus.PENDING, r.license().status());
        assertEquals(2, r.license().policy().deviceLimit());
        assertFalse(r.toString().contains(r.activationCode()), "toString must not print the code");
    }

    @Test
    void paymentMustBeExplicitlyConfirmed() {
        LicensingException e = assertThrows(LicensingException.class,
                () -> f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", false, null, policy(), "key-0123456789abcdef")));
        assertEquals(ErrorCode.PAYMENT_NOT_CONFIRMED, e.code());
        assertTrue(f.store.allAudit().isEmpty());
    }

    @Test
    void credentialWithoutTheIssueScopeIsForbidden() {
        AdminPrincipal readOnly = new AdminPrincipal("viewer", EnumSet.of(AdminScope.LICENSE_READ, AdminScope.AUDIT_READ));
        LicensingException e = assertThrows(LicensingException.class,
                () -> f.issuance.issue(readOnly, new IssueCommand("a@example.com", true, null, policy(), "key-0123456789abcdef")));
        assertEquals(ErrorCode.FORBIDDEN, e.code());
    }

    @Test
    void onlyAKeyedHashOfTheCodeIsStoredAndTheRawCodeAppearsNowhere() {
        IssueResult r = f.issue("a@example.com", 1, 30);
        String dump = f.store.dumpEverythingStored();
        assertFalse(dump.contains(r.activationCode()));
        assertFalse(dump.contains(r.activationCode().replace("-", "")));
        assertTrue(dump.contains(f.codes.hash(r.activationCode())), "the keyed hash is what is stored");
    }

    @Test
    void issuanceIsAuditedWithoutTheCodeOrTheEmailAddress() {
        IssueResult r = f.issue("someone@example.com", 1, 30);
        List<AuditEvent> events = f.store.allAudit();
        assertEquals(1, events.size());
        AuditEvent e = events.get(0);
        assertEquals(AuditAction.LICENSE_ISSUED, e.action());
        assertEquals("admin:dev", e.actor());
        assertEquals(r.license().id(), e.licenseId());
        assertTrue(e.detail().contains("paymentConfirmedByAdmin=true"));
        assertFalse(e.detail().contains("someone@example.com"));
        assertFalse(e.detail().contains(r.activationCode()));
    }

    @Test
    void retryWithTheSameKeyReplaysTheSameLicenseWithoutAnyCode() {
        IssueCommand cmd = new IssueCommand("a@example.com", true, "ref1", policy(), "retry-key-0123456789");
        IssueResult first = f.issuance.issue(f.fullAdmin, cmd);
        IssueResult second = f.issuance.issue(f.fullAdmin, cmd);
        assertTrue(second.replayed());
        assertNull(second.activationCode());
        assertEquals(first.license().id(), second.license().id());
        assertEquals(1, f.store.countByEmail("a@example.com"));
    }

    @Test
    void sameKeyWithADifferentRequestIsRefused() {
        f.issuance.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref1", policy(), "retry-key-0123456789"));
        LicensingException e = assertThrows(LicensingException.class, () -> f.issuance.issue(f.fullAdmin,
                new IssueCommand("a@example.com", true, "ref1", new LicensePolicy(5, 365, EnumSet.of(LicenseRight.LIVE), 14), "retry-key-0123456789")));
        assertEquals(ErrorCode.IDEMPOTENCY_KEY_REUSED, e.code());
    }

    @Test
    void concurrentRetriesCreateExactlyOneLicense() throws Exception {
        IssueCommand cmd = new IssueCommand("race@example.com", true, "r", policy(), "race-key-0123456789ab");
        Thread[] ts = new Thread[12];
        java.util.concurrent.atomic.AtomicInteger withCode = new java.util.concurrent.atomic.AtomicInteger();
        for (int i = 0; i < ts.length; i++) {
            ts[i] = new Thread(() -> {
                IssueResult r = f.issuance.issue(f.fullAdmin, cmd);
                if (r.activationCode() != null) {
                    withCode.incrementAndGet();
                }
            });
            ts[i].start();
        }
        for (Thread t : ts) {
            t.join();
        }
        assertEquals(1, f.store.countByEmail("race@example.com"));
        assertEquals(1, withCode.get(), "the code is handed out exactly once");
    }

    @Test
    void inputIsValidated() {
        for (String key : new String[] {null, "short", "has space in it 0123456789", "x".repeat(200)}) {
            assertEquals(ErrorCode.VALIDATION_FAILED, assertThrows(LicensingException.class, () -> f.issuance.issue(f.fullAdmin,
                    new IssueCommand("a@example.com", true, null, policy(), key))).code());
        }
        for (String email : new String[] {null, "", "no-at-sign", "a@b", "a b@example.com", "x@@example.com"}) {
            assertEquals(ErrorCode.VALIDATION_FAILED, assertThrows(LicensingException.class, () -> f.issuance.issue(f.fullAdmin,
                    new IssueCommand(email, true, null, policy(), "key-0123456789abcdef"))).code());
        }
        assertEquals(ErrorCode.VALIDATION_FAILED, assertThrows(LicensingException.class, () -> f.issuance.issue(f.fullAdmin,
                new IssueCommand("a@example.com", true, "card 4111 <script>", policy(), "key-0123456789abcdef"))).code());
    }
}
