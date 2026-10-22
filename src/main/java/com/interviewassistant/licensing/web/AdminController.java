package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.service.AdminLicenseService;
import com.interviewassistant.licensing.service.IssuanceService;
import com.interviewassistant.licensing.service.IssuanceService.IssueResult;
import com.interviewassistant.licensing.service.ErrorCode;
import com.interviewassistant.licensing.service.LicensingException;
import com.interviewassistant.licensing.web.Dtos.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Administrative API. Authentication is enforced for the whole path prefix by {@link AdminAuthFilter}; this class only reads
 * the already-authenticated principal, and each service call checks the scope it needs.
 */
@RestController
@RequestMapping("/api/v1/admin")
class AdminController {

    private final IssuanceService issuance;
    private final AdminLicenseService admin;
    private final LicensingProperties props;

    AdminController(IssuanceService issuance, AdminLicenseService admin, LicensingProperties props) {
        this.issuance = issuance;
        this.admin = admin;
        this.props = props;
    }

    /**
     * The principal {@link AdminAuthFilter} authenticated. Missing means the filter did not run for this request (for example a
     * request path the prefix check did not recognise): refuse explicitly with 401 instead of relying on a later null failure.
     */
    private static AdminPrincipal principal(HttpServletRequest request) {
        Object p = request.getAttribute(AdminAuthFilter.PRINCIPAL_ATTRIBUTE);
        if (!(p instanceof AdminPrincipal principal)) {
            throw new LicensingException(ErrorCode.UNAUTHENTICATED);
        }
        return principal;
    }

    @PostMapping("/licenses")
    ResponseEntity<IssueLicenseResponse> issue(HttpServletRequest request,
                                               @RequestHeader(value = "Idempotency-Key", required = false) String idempotencyKey,
                                               @Valid @RequestBody IssueLicenseRequest body) {
        PolicyRequest p = body.policy();
        LicensePolicy policy = new LicensePolicy(p.deviceLimit(), p.validityDays(), p.rights(),
                p.activationWindowDays() == null ? props.defaults().activationWindowDays() : p.activationWindowDays());
        IssueResult r = issuance.issue(principal(request), new IssuanceService.IssueCommand(body.customerEmail(),
                Boolean.TRUE.equals(body.paymentVerified()), body.paymentReference(), policy, idempotencyKey, body.expiresAt()));
        var view = new AdminLicenseService.LicenseView(r.license(), r.license().effectiveStatus(java.time.Instant.now()));
        return ResponseEntity.status(r.replayed() ? HttpStatus.OK : HttpStatus.CREATED)
                .body(new IssueLicenseResponse(LicenseResponse.of(view), r.activationCode(), r.replayed()));
    }

    @GetMapping("/licenses/search")
    SearchResponse search(HttpServletRequest request, @RequestParam(required = false) String q,
                          @RequestParam(required = false) String status, @RequestParam(defaultValue = "25") int limit,
                          @RequestParam(defaultValue = "0") int offset) {
        LicenseStatus wanted = null;
        if (status != null && !status.isBlank()) {
            try {
                wanted = LicenseStatus.valueOf(status.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException e) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, "unknown status filter");
            }
        }
        var r = admin.search(principal(request), q, wanted, limit, offset);
        return new SearchResponse(r.items().stream().map(LicenseResponse::of).toList(), r.hasMore(), r.offset());
    }

    @GetMapping("/stats")
    StatsResponse stats(HttpServletRequest request) {
        var s = admin.stats(principal(request));
        var c = s.licenses();
        CountsResponse counts = new CountsResponse(c.total(), c.pending(), c.active(), c.expiredAfterActivation(),
                c.lapsedUnactivated(), c.suspended(), c.revoked());
        if (s.activity() == null) {
            return new StatsResponse(s.generatedAt(), counts, false, null, null, null, null);
        }
        return new StatsResponse(s.generatedAt(), counts, true, s.activity().recordedSince(), window(s.activity().last30Days()),
                window(s.activity().allRecorded()), s.recent().stream().map(AuditEventResponse::of).toList());
    }

    private static ActivityWindowResponse window(AdminLicenseService.ActivityWindow w) {
        return new ActivityWindowResponse(w.activationSuccesses(), w.activationFailures(), w.entitlementsIssued(),
                w.validationRejections(), w.licensesIssued());
    }

    @PostMapping("/licenses/{id}/renew")
    LicenseResponse renew(HttpServletRequest request, @PathVariable UUID id, @Valid @RequestBody RenewRequest body) {
        AdminLicenseService.RenewMode mode;
        try {
            mode = AdminLicenseService.RenewMode.valueOf(body.mode());
        } catch (IllegalArgumentException e) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "mode must be EXTEND_DAYS or SET_END");
        }
        return LicenseResponse.of(admin.renew(principal(request), id,
                new AdminLicenseService.RenewCommand(mode, body.days(), body.endsAt(), body.reason())));
    }

    @GetMapping("/licenses/{id}")
    LicenseResponse get(HttpServletRequest request, @PathVariable UUID id) {
        return LicenseResponse.of(admin.get(principal(request), id));
    }

    @GetMapping("/licenses")
    List<LicenseResponse> byEmail(HttpServletRequest request, @RequestParam String customerEmail) {
        return admin.findByEmail(principal(request), customerEmail).stream().map(LicenseResponse::of).toList();
    }

    @PostMapping("/licenses/{id}/suspend")
    LicenseResponse suspend(HttpServletRequest request, @PathVariable UUID id, @Valid @RequestBody(required = false) ReasonRequest body) {
        return LicenseResponse.of(admin.suspend(principal(request), id, body == null ? null : body.reason()));
    }

    @PostMapping("/licenses/{id}/reinstate")
    LicenseResponse reinstate(HttpServletRequest request, @PathVariable UUID id, @Valid @RequestBody(required = false) ReasonRequest body) {
        return LicenseResponse.of(admin.reinstate(principal(request), id, body == null ? null : body.reason()));
    }

    @PostMapping("/licenses/{id}/revoke")
    LicenseResponse revoke(HttpServletRequest request, @PathVariable UUID id, @Valid @RequestBody(required = false) ReasonRequest body) {
        return LicenseResponse.of(admin.revoke(principal(request), id, body == null ? null : body.reason()));
    }

    @GetMapping("/licenses/{id}/audit")
    AuditPage licenseAudit(HttpServletRequest request, @PathVariable UUID id,
                           @RequestParam(required = false) Long beforeId, @RequestParam(defaultValue = "50") int limit) {
        return page(admin.audit(principal(request), id, beforeId, limit), limit);
    }

    @GetMapping("/audit")
    AuditPage audit(HttpServletRequest request, @RequestParam(required = false) Long beforeId,
                    @RequestParam(defaultValue = "50") int limit) {
        return page(admin.audit(principal(request), null, beforeId, limit), limit);
    }

    private static AuditPage page(List<com.interviewassistant.licensing.domain.AuditEvent> events, int limit) {
        List<AuditEventResponse> out = events.stream().map(AuditEventResponse::of).toList();
        Long next = out.isEmpty() || out.size() < Math.min(Math.max(limit, 1), 200) ? null : out.get(out.size() - 1).id();
        return new AuditPage(out, next);
    }
}
