package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.service.AdminLicenseService.LicenseView;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Request and response bodies of API v1. Field-by-field documentation is in docs/API.md. */
final class Dtos {

    private Dtos() {
    }

    // ------------------------------------------------------------------ admin

    record PolicyRequest(
            @NotNull @Min(1) @Max(10) Integer deviceLimit,
            @Min(1) @Max(3650) Integer validityDays,
            @NotEmpty Set<LicenseRight> rights,
            @Min(1) @Max(365) Integer activationWindowDays) {
    }

    record IssueLicenseRequest(
            @NotBlank @Size(max = 254) String customerEmail,
            @NotNull Boolean paymentVerified,
            @Size(max = 64) String paymentReference,
            @NotNull @Valid PolicyRequest policy,
            /** Optional exact end date; mutually exclusive with {@code policy.validityDays} (the service refuses both). */
            Instant expiresAt) {
    }

    /** Renewal: exactly one of {@code days} (extend) or {@code endsAt} (set the end); the mode is stated, never guessed. */
    record RenewRequest(@NotNull String mode, @Min(1) @Max(3650) Integer days, Instant endsAt, @Size(max = 200) String reason) {
    }

    record SearchResponse(List<LicenseResponse> items, boolean hasMore, int offset) {
    }

    record CountsResponse(long total, long pending, long active, long expiredAfterActivation, long lapsedUnactivated,
                          long suspended, long revoked) {
    }

    record ActivityWindowResponse(long activationSuccesses, long activationFailures, long entitlementsIssued,
                                  long validationRejections, long licensesIssued) {
    }

    /** {@code activityAvailable=false} means the figures could not be shown to this credential (not that they are zero). */
    record StatsResponse(Instant generatedAt, CountsResponse licenses, boolean activityAvailable, Instant activityRecordedSince,
                         ActivityWindowResponse last30Days, ActivityWindowResponse allRecorded, List<AuditEventResponse> recent) {
    }

    record ReasonRequest(@Size(max = 200) String reason) {
    }

    record LicenseResponse(UUID id, String customerEmail, LicenseStatus status, LicenseStatus effectiveStatus, int deviceLimit,
                           int activeDeviceCount, Integer validityDays, Set<LicenseRight> rights, Instant createdAt,
                           Instant activationDeadline, Instant activatedAt, Instant expiresAt, Instant suspendedAt,
                           Instant revokedAt) {
        static LicenseResponse of(LicenseView v) {
            License l = v.license();
            return new LicenseResponse(l.id(), l.customerEmail(), l.status(), v.effectiveStatus(), l.policy().deviceLimit(),
                    l.activeDeviceCount(), l.policy().validityDays(), l.policy().rights(), l.createdAt(), l.activationDeadline(),
                    l.activatedAt(), l.expiresAt(), l.suspendedAt(), l.revokedAt());
        }
    }

    /** {@code activationCode} is present only in the response that creates the license; it is null on a replay. */
    record IssueLicenseResponse(LicenseResponse license, String activationCode, boolean replayed) {
    }

    record AuditEventResponse(long id, Instant occurredAt, String actor, String action, UUID licenseId, String outcome, String detail) {
        static AuditEventResponse of(AuditEvent e) {
            return new AuditEventResponse(e.id(), e.occurredAt(), e.actor(), e.action().name(), e.licenseId(), e.outcome().name(),
                    e.detail());
        }
    }

    record AuditPage(List<AuditEventResponse> events, Long nextBeforeId) {
    }

    // ------------------------------------------------------------------ client

    record ActivateRequest(
            @NotBlank @Size(max = 254) String email,
            @NotBlank @Size(max = 64) String activationCode,
            @NotBlank @Size(max = 100) String devicePublicKey,
            @NotNull Long proofTimestamp,
            @NotBlank @Size(max = 64) String proofNonce,
            @NotBlank @Size(max = 100) String proofSignature,
            @Size(max = 64) String deviceLabel,
            @Size(max = 256) String supplementaryFingerprint) {
    }

    record DeviceProofRequest(
            @NotNull UUID licenseId,
            @NotNull UUID deviceRegistrationId,
            @NotNull Long proofTimestamp,
            @NotBlank @Size(max = 64) String proofNonce,
            @NotBlank @Size(max = 100) String proofSignature) {
    }

    record ActivationResponse(UUID licenseId, UUID deviceRegistrationId, LicenseStatus status, Set<LicenseRight> rights,
                              Instant licenseExpiresAt, String entitlement, Instant entitlementExpiresAt, Instant renewAfter,
                              boolean alreadyRegistered) {
    }

    record ValidationResponse(boolean valid, UUID licenseId, UUID deviceRegistrationId, LicenseStatus status,
                              Set<LicenseRight> rights, Instant licenseExpiresAt, Instant serverTime) {
    }

    record EntitlementResponse(UUID licenseId, UUID deviceRegistrationId, Set<LicenseRight> rights, Instant licenseExpiresAt,
                               String entitlement, Instant entitlementExpiresAt, Instant renewAfter) {
    }

    record Jwk(String kty, String crv, String kid, String x, String use, String alg) {
    }

    record Jwks(List<Jwk> keys) {
    }
}
