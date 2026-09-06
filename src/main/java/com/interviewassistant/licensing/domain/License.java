package com.interviewassistant.licensing.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * An immutable license. Every lifecycle change returns a NEW instance, validated against {@link LicenseStatus#allowedNext()}.
 * Time is always passed in, so the rules are deterministic and testable.
 *
 * <p>{@code version} is the optimistic-locking counter owned by the database; the domain never changes it.
 * {@code activeDeviceCount} is likewise owned by the store (it is changed by one atomic conditional update).
 */
public record License(
        UUID id,
        String customerEmail,
        LicenseStatus status,
        LicensePolicy policy,
        Instant createdAt,
        Instant activationDeadline,
        Instant activatedAt,
        Instant expiresAt,
        Instant suspendedAt,
        Instant revokedAt,
        Instant updatedAt,
        int activeDeviceCount,
        long version) {

    public License {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(customerEmail, "customerEmail");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(createdAt, "createdAt");
        Objects.requireNonNull(activationDeadline, "activationDeadline");
        Objects.requireNonNull(updatedAt, "updatedAt");
        if (activeDeviceCount < 0 || activeDeviceCount > policy.deviceLimit()) {
            throw new IllegalArgumentException("activeDeviceCount outside 0.." + policy.deviceLimit());
        }
    }

    /** A freshly issued license: PENDING, with an activation deadline derived from the policy. */
    public static License issue(UUID id, String normalizedEmail, LicensePolicy policy, Instant now) {
        return issue(id, normalizedEmail, policy, now, null);
    }

    /**
     * As above, optionally with a fixed end date chosen by the administrator. The end date is carried in {@code expiresAt}
     * while the license is still PENDING and is kept (not recomputed) when it is activated; {@code fixedEnd} and the policy's
     * {@code validityDays} are mutually exclusive, which the issuing service enforces.
     */
    public static License issue(UUID id, String normalizedEmail, LicensePolicy policy, Instant now, Instant fixedEnd) {
        return new License(id, normalizedEmail, LicenseStatus.PENDING, policy, now,
                now.plus(Duration.ofDays(policy.activationWindowDays())), null, fixedEnd, null, null, now, 0, 0L);
    }

    /**
     * The status that applies at {@code now}. Time-based expiry is derived, so a license is never usable past its end
     * even before the stored status has been brought up to date.
     */
    public LicenseStatus effectiveStatus(Instant now) {
        return switch (status) {
            case PENDING -> pendingLapsed(now) ? LicenseStatus.EXPIRED : LicenseStatus.PENDING;
            case ACTIVE -> expiresAt != null && !now.isBefore(expiresAt) ? LicenseStatus.EXPIRED : LicenseStatus.ACTIVE;
            default -> status;
        };
    }

    /** PENDING to ACTIVE. Sets the activation time and, if the policy has a term, the expiry. */
    public License activate(Instant now) {
        requireEffective(now, LicenseStatus.PENDING, LicenseStatus.ACTIVE);
        // A fixed end date chosen at issuance wins; otherwise the term counts from activation.
        Instant end = expiresAt != null ? expiresAt
                : policy.validityDays() == null ? null : now.plus(Duration.ofDays(policy.validityDays()));
        return copy(LicenseStatus.ACTIVE, now, activatedAt == null ? now : activatedAt, end, suspendedAt, revokedAt);
    }

    public License suspend(Instant now) {
        LicenseStatus effective = effectiveStatus(now);
        if (effective == LicenseStatus.EXPIRED) {
            throw new IllegalLicenseTransitionException(status, LicenseStatus.SUSPENDED, "the license has expired");
        }
        requireAllowed(LicenseStatus.SUSPENDED);
        return copy(LicenseStatus.SUSPENDED, now, activatedAt, expiresAt, now, revokedAt);
    }

    /** SUSPENDED back to ACTIVE (if it was ever activated) or PENDING (if not). Fails if it expired in the meantime. */
    public License reinstate(Instant now) {
        if (status != LicenseStatus.SUSPENDED) {
            throw new IllegalLicenseTransitionException(status, LicenseStatus.ACTIVE, "only a suspended license can be reinstated");
        }
        LicenseStatus target = activatedAt == null ? LicenseStatus.PENDING : LicenseStatus.ACTIVE;
        boolean lapsed = target == LicenseStatus.PENDING
                ? pendingLapsed(now)
                : expiresAt != null && !now.isBefore(expiresAt);
        if (lapsed) {
            throw new IllegalLicenseTransitionException(status, target, "the license has expired");
        }
        return copy(target, now, activatedAt, expiresAt, null, revokedAt);
    }

    public License revoke(Instant now) {
        requireAllowed(LicenseStatus.REVOKED);
        return copy(LicenseStatus.REVOKED, now, activatedAt, expiresAt, suspendedAt, now);
    }

    /** Brings the stored status up to date once the effective status has become EXPIRED. */
    public License expire(Instant now) {
        if (!hasLapsed(now)) {
            throw new IllegalLicenseTransitionException(status, LicenseStatus.EXPIRED, "the license has not reached its end");
        }
        requireAllowed(LicenseStatus.EXPIRED);
        return copy(LicenseStatus.EXPIRED, now, activatedAt, expiresAt, suspendedAt, revokedAt);
    }

    /** True once the time limit that applies to the license's lifecycle stage has passed, whatever the stored status says. */
    public boolean hasLapsed(Instant now) {
        return activatedAt == null
                ? pendingLapsed(now)
                : expiresAt != null && !now.isBefore(expiresAt);
    }

    /** A never-activated license lapses at its activation deadline, or earlier at a fixed end date set when it was issued. */
    private boolean pendingLapsed(Instant now) {
        return !now.isBefore(activationDeadline) || (expiresAt != null && !now.isBefore(expiresAt));
    }

    /**
     * Sets a new end date on a license that has been activated. This is the ONLY way an EXPIRED license returns to ACTIVE, and it
     * changes nothing else: policy, device count, activation time, and any suspension stay exactly as they were (a SUSPENDED license
     * stays suspended; reinstating it is a separate, explicit act). A revoked license, and one that was never activated, cannot be
     * renewed. The caller chooses the end date; validating it against the clock is the service's job.
     */
    public License renew(Instant now, Instant newEnd) {
        Objects.requireNonNull(newEnd, "newEnd");
        if (status == LicenseStatus.REVOKED) {
            throw new IllegalLicenseTransitionException(status, LicenseStatus.ACTIVE, "a revoked license cannot be renewed");
        }
        if (activatedAt == null) {
            throw new IllegalLicenseTransitionException(status, LicenseStatus.ACTIVE,
                    "the license was never activated; its term starts at activation");
        }
        if (!newEnd.isAfter(now)) {
            throw new IllegalArgumentException("the new end date must be in the future");
        }
        LicenseStatus target = status == LicenseStatus.SUSPENDED ? LicenseStatus.SUSPENDED : LicenseStatus.ACTIVE;
        return copy(target, now, activatedAt, newEnd, suspendedAt, revokedAt);
    }

    private void requireEffective(Instant now, LicenseStatus expected, LicenseStatus target) {
        LicenseStatus effective = effectiveStatus(now);
        if (effective != expected) {
            throw new IllegalLicenseTransitionException(status, target, "license is effectively " + effective);
        }
        requireAllowed(target);
    }

    private void requireAllowed(LicenseStatus target) {
        if (!status.canTransitionTo(target)) {
            throw new IllegalLicenseTransitionException(status, target, "transition not permitted");
        }
    }

    private License copy(LicenseStatus s, Instant now, Instant activated, Instant end, Instant suspended, Instant revoked) {
        return new License(id, customerEmail, s, policy, createdAt, activationDeadline, activated, end, suspended, revoked,
                now, activeDeviceCount, version);
    }

    /** Same license with store-owned counters replaced (used by the store when reading rows). */
    public License withVersion(long newVersion) {
        return new License(id, customerEmail, status, policy, createdAt, activationDeadline, activatedAt, expiresAt,
                suspendedAt, revokedAt, updatedAt, activeDeviceCount, newVersion);
    }
}
