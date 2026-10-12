package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.service.AdminLicenseService.LicenseView;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AdminLicenseServiceTest {

    private final Fixture f = new Fixture();

    @Test
    void suspendReinstateRevokeFollowTheStateMachineAndAreAudited() {
        UUID id = f.issue("a@example.com", 1, 30).license().id();
        assertEquals(LicenseStatus.SUSPENDED, f.admin.suspend(f.fullAdmin, id, "chargeback under review").license().status());
        assertEquals(LicenseStatus.PENDING, f.admin.reinstate(f.fullAdmin, id, "resolved").license().status());
        assertEquals(LicenseStatus.REVOKED, f.admin.revoke(f.fullAdmin, id, "refund").license().status());
        List<AuditEvent> audit = f.admin.audit(f.fullAdmin, id, null, 50);
        assertEquals(List.of(AuditAction.LICENSE_REVOKED, AuditAction.LICENSE_REINSTATED, AuditAction.LICENSE_SUSPENDED, AuditAction.LICENSE_ISSUED),
                audit.stream().map(AuditEvent::action).toList());
        assertTrue(audit.get(0).detail().contains("from=PENDING; to=REVOKED"));
        assertEquals("admin:dev", audit.get(0).actor());
    }

    @Test
    void illegalTransitionIsRefusedAndTheAttemptIsAudited() {
        UUID id = f.issue("a@example.com", 1, 30).license().id();
        f.admin.revoke(f.fullAdmin, id, "");
        LicensingException e = assertThrows(LicensingException.class, () -> f.admin.suspend(f.fullAdmin, id, ""));
        assertEquals(ErrorCode.ILLEGAL_TRANSITION, e.code());
        assertEquals(LicenseStatus.REVOKED, f.store.license(id).status());
        AuditEvent last = f.store.allAudit().get(f.store.allAudit().size() - 1);
        assertEquals(AuditOutcome.FAILURE, last.outcome());
        assertEquals(AuditAction.LICENSE_SUSPENDED, last.action());
    }

    @Test
    void unknownLicenseIs404() {
        assertEquals(ErrorCode.LICENSE_NOT_FOUND,
                assertThrows(LicensingException.class, () -> f.admin.revoke(f.fullAdmin, UUID.randomUUID(), "")).code());
        assertEquals(ErrorCode.LICENSE_NOT_FOUND,
                assertThrows(LicensingException.class, () -> f.admin.get(f.fullAdmin, UUID.randomUUID())).code());
    }

    @Test
    void everyOperationChecksItsOwnScope() {
        UUID id = f.issue("a@example.com", 1, 30).license().id();
        AdminPrincipal none = new AdminPrincipal("x", EnumSet.of(AdminScope.LICENSE_ISSUE));
        for (Runnable r : List.<Runnable>of(() -> f.admin.get(none, id), () -> f.admin.findByEmail(none, "a@example.com"),
                () -> f.admin.suspend(none, id, ""), () -> f.admin.revoke(none, id, ""), () -> f.admin.reinstate(none, id, ""),
                () -> f.admin.audit(none, null, null, 10))) {
            assertEquals(ErrorCode.FORBIDDEN, assertThrows(LicensingException.class, r::run).code());
        }
    }

    @Test
    void metadataViewShowsEffectiveStatusAndNeverACredential() {
        var issued = f.issue("a@example.com", 1, 30);
        f.clock.advance(Duration.ofDays(40));
        LicenseView v = f.admin.get(f.fullAdmin, issued.license().id());
        assertEquals(LicenseStatus.PENDING, v.license().status());
        assertEquals(LicenseStatus.EXPIRED, v.effectiveStatus(), "activation window lapsed");
        assertFalse(v.toString().contains(issued.activationCode()));
        assertEquals(1, f.admin.findByEmail(f.fullAdmin, " A@Example.com ").size());
    }

    @Test
    void auditPagingIsCappedAndCursorBased() {
        UUID id = f.issue("a@example.com", 1, 30).license().id();
        f.admin.suspend(f.fullAdmin, id, "");
        f.admin.reinstate(f.fullAdmin, id, "");
        List<AuditEvent> page1 = f.admin.audit(f.fullAdmin, null, null, 2);
        assertEquals(2, page1.size());
        List<AuditEvent> page2 = f.admin.audit(f.fullAdmin, null, page1.get(1).id(), 2);
        assertEquals(1, page2.size());
        assertTrue(page2.get(0).id() < page1.get(1).id());
        assertEquals(3, f.admin.audit(f.fullAdmin, null, null, 100000).size());
    }

    @Test
    void overlongReasonIsRejected() {
        UUID id = f.issue("a@example.com", 1, 30).license().id();
        assertEquals(ErrorCode.VALIDATION_FAILED,
                assertThrows(LicensingException.class, () -> f.admin.suspend(f.fullAdmin, id, "x".repeat(201))).code());
    }
}
