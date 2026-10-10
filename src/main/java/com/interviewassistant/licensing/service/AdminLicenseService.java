package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.IllegalLicenseTransitionException;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.store.LicenseCounts;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.StoreExceptions.ConcurrentUpdateException;
import com.interviewassistant.licensing.store.TransactionRunner;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiFunction;

/**
 * Administrative reads and lifecycle changes (suspend, reinstate, revoke) and audit review. Every method checks the caller's
 * scope first. Lifecycle changes go through the domain state machine and an optimistic version check, and write their audit
 * record in the same transaction.
 *
 * <p>Renewal (Phase 133) is the only way an existing license's end date changes. Still deliberately absent: changing the device
 * limit or rights of an existing license, and device reset; those need their own security rules.
 */
public final class AdminLicenseService {

    private static final int MAX_ATTEMPTS = 3;
    private static final int MAX_AUDIT_PAGE = 200;

    /** A license plus the status that applies right now (stored status may lag behind a time-based expiry). */
    public record LicenseView(License license, LicenseStatus effectiveStatus) {
    }

    /** How a renewal chooses the new end date. */
    public enum RenewMode {
        /** New end = the later of (current end, now) plus {@code days}. Refused for a license that has no end date. */
        EXTEND_DAYS,
        /** New end = exactly {@code endsAt}. */
        SET_END
    }

    /** An explicit administrator choice; exactly one of {@code days} (EXTEND_DAYS) or {@code endsAt} (SET_END) is used. */
    public record RenewCommand(RenewMode mode, Integer days, Instant endsAt, String reason) {
    }

    /** One page of search results; {@code hasMore} says whether another page exists. */
    public record SearchResult(List<LicenseView> items, boolean hasMore, int offset) {
    }

    /** Audit-derived counts for one time window. Only events that were actually recorded are counted. */
    public record ActivityWindow(long activationSuccesses, long activationFailures, long entitlementsIssued, long validationRejections,
                                 long licensesIssued) {
        static ActivityWindow of(Map<String, Long> counts) {
            return new ActivityWindow(counts.getOrDefault("ACTIVATION/SUCCESS", 0L), counts.getOrDefault("ACTIVATION/FAILURE", 0L),
                    counts.getOrDefault("ENTITLEMENT_ISSUED/SUCCESS", 0L), counts.getOrDefault("VALIDATION_REJECTED/FAILURE", 0L),
                    counts.getOrDefault("LICENSE_ISSUED/SUCCESS", 0L));
        }
    }

    /** {@code recordedSince} is null when the audit trail is empty (the figures are then genuinely zero, not unknown). */
    public record Activity(Instant recordedSince, ActivityWindow last30Days, ActivityWindow allRecorded) {
    }

    /**
     * Dashboard figures. {@code activity} and {@code recent} are {@code null} (UNAVAILABLE, not zero) when the caller lacks the
     * audit-read scope, because they come from the audit trail.
     */
    public record Stats(Instant generatedAt, LicenseCounts licenses, Activity activity, List<AuditEvent> recent) {
    }

    private static final int MAX_SEARCH_PAGE = 100;
    private static final int MAX_SEARCH_OFFSET = 10_000;
    private static final int RECENT_EVENTS = 15;
    private static final Duration ACTIVITY_WINDOW = Duration.ofDays(30);

    private final LicenseStore store;
    private final TransactionRunner tx;
    private final Clock clock;

    public AdminLicenseService(LicenseStore store, TransactionRunner tx, Clock clock) {
        this.store = store;
        this.tx = tx;
        this.clock = clock;
    }

    public LicenseView get(AdminPrincipal admin, UUID id) {
        admin.require(AdminScope.LICENSE_READ);
        Instant now = clock.instant();
        License l = tx.inTransaction(t -> store.findLicense(t, id)).orElseThrow(() -> new LicensingException(ErrorCode.LICENSE_NOT_FOUND));
        return new LicenseView(l, l.effectiveStatus(now));
    }

    public List<LicenseView> findByEmail(AdminPrincipal admin, String email) {
        admin.require(AdminScope.LICENSE_READ);
        String normalized = Emails.normalize(email);
        Instant now = clock.instant();
        return tx.inTransaction(t -> store.findLicensesByEmail(t, normalized)).stream()
                .map(l -> new LicenseView(l, l.effectiveStatus(now))).toList();
    }

    public LicenseView suspend(AdminPrincipal admin, UUID id, String reason) {
        return change(admin, id, reason, AuditAction.LICENSE_SUSPENDED, License::suspend);
    }

    public LicenseView reinstate(AdminPrincipal admin, UUID id, String reason) {
        return change(admin, id, reason, AuditAction.LICENSE_REINSTATED, License::reinstate);
    }

    public LicenseView revoke(AdminPrincipal admin, UUID id, String reason) {
        return change(admin, id, reason, AuditAction.LICENSE_REVOKED, License::revoke);
    }

    /**
     * Sets a new end date on an activated license (see {@link License#renew}). The administrator chooses explicitly between
     * extending by a number of days and setting an exact end date; nothing else about the license changes, device bindings
     * included. The old and new end dates are written to the audit trail.
     */
    public LicenseView renew(AdminPrincipal admin, UUID id, RenewCommand cmd) {
        admin.require(AdminScope.LICENSE_LIFECYCLE);
        if (cmd == null || cmd.mode() == null) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "choose how to renew: extend by days or set an end date");
        }
        if (cmd.mode() == RenewMode.EXTEND_DAYS) {
            if (cmd.days() == null || cmd.days() < 1 || cmd.days() > LicensePolicy.MAX_VALIDITY_DAYS || cmd.endsAt() != null) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED,
                        "extending needs a number of days between 1 and " + LicensePolicy.MAX_VALIDITY_DAYS + " and no end date");
            }
        } else if (cmd.endsAt() == null || cmd.days() != null) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "setting an end date needs the date and no number of days");
        }
        return change(admin, id, cmd.reason(), AuditAction.LICENSE_RENEWED,
                (license, now) -> {
                    license.renew(now, now.plusSeconds(1));   // eligibility first: a refused state outranks a bad end date
                    return license.renew(now, newEnd(license, now, cmd));
                },
                (before, after) -> "; expiresFrom=" + (before.expiresAt() == null ? "-" : before.expiresAt())
                        + "; expiresTo=" + after.expiresAt() + "; mode=" + cmd.mode());
    }

    private static Instant newEnd(License license, Instant now, RenewCommand cmd) {
        Instant end;
        if (cmd.mode() == RenewMode.EXTEND_DAYS) {
            if (license.expiresAt() == null) {
                // Extending a license that never expires would silently IMPOSE an end date; make the administrator say so.
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, "this license has no end date; set an exact end date instead");
            }
            Instant base = license.expiresAt().isAfter(now) ? license.expiresAt() : now;
            end = base.plus(Duration.ofDays(cmd.days()));
        } else {
            end = cmd.endsAt().truncatedTo(java.time.temporal.ChronoUnit.SECONDS); // what the entitlement can carry
        }
        if (!end.isAfter(now)) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "the new end date must be in the future");
        }
        if (end.isAfter(now.plus(Duration.ofDays(LicensePolicy.MAX_VALIDITY_DAYS)))) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED,
                    "the new end date is more than " + LicensePolicy.MAX_VALIDITY_DAYS + " days away");
        }
        return end;
    }

    /**
     * Searches by a literal, case-insensitive e-mail fragment and/or an effective status. Newest first, one page at a time.
     * Looking a license up by its id is {@link #get}.
     */
    public SearchResult search(AdminPrincipal admin, String emailContains, LicenseStatus effectiveStatus, int limit, int offset) {
        admin.require(AdminScope.LICENSE_READ);
        String fragment = emailContains == null ? "" : emailContains.trim().toLowerCase(Locale.ROOT);
        if (fragment.length() > 100) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "the search text is too long (max 100)");
        }
        for (int i = 0; i < fragment.length(); i++) {
            if (Character.isISOControl(fragment.charAt(i))) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, "the search text contains control characters");
            }
        }
        if (offset < 0 || offset > MAX_SEARCH_OFFSET) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "offset must be between 0 and " + MAX_SEARCH_OFFSET);
        }
        int page = Math.max(1, Math.min(limit, MAX_SEARCH_PAGE));
        Instant now = clock.instant();
        List<License> rows = tx.inTransaction(t ->
                store.searchLicenses(t, now, fragment.isEmpty() ? null : fragment, effectiveStatus, page + 1, offset));
        boolean more = rows.size() > page;
        List<LicenseView> items = rows.stream().limit(page).map(l -> new LicenseView(l, l.effectiveStatus(now))).toList();
        return new SearchResult(items, more, offset);
    }

    /** Figures straight from the database at this moment. */
    public Stats stats(AdminPrincipal admin) {
        admin.require(AdminScope.LICENSE_READ);
        boolean audit = admin.has(AdminScope.AUDIT_READ);
        Instant now = clock.instant();
        return tx.inTransaction(t -> {
            LicenseCounts counts = store.countLicenses(t, now);
            if (!audit) {
                return new Stats(now, counts, null, null);
            }
            Activity activity = new Activity(store.earliestAudit(t).orElse(null),
                    ActivityWindow.of(store.countAuditSince(t, now.minus(ACTIVITY_WINDOW))),
                    ActivityWindow.of(store.countAuditSince(t, Instant.EPOCH)));
            return new Stats(now, counts, activity, store.findAudit(t, null, null, RECENT_EVENTS));
        });
    }

    /** Audit events, newest first. {@code licenseId} and {@code beforeId} (a cursor) are optional. */
    public List<AuditEvent> audit(AdminPrincipal admin, UUID licenseId, Long beforeId, int limit) {
        admin.require(AdminScope.AUDIT_READ);
        int capped = Math.max(1, Math.min(limit, MAX_AUDIT_PAGE));
        return tx.inTransaction(t -> store.findAudit(t, licenseId, beforeId, capped));
    }

    private LicenseView change(AdminPrincipal admin, UUID id, String reason, AuditAction action,
                               BiFunction<License, Instant, License> transition) {
        return change(admin, id, reason, action, transition, (before, after) -> "");
    }

    /** {@code extraDetail} may add text to the success audit line (it receives the license before and after). */
    private LicenseView change(AdminPrincipal admin, UUID id, String reason, AuditAction action,
                               BiFunction<License, Instant, License> transition, BiFunction<License, License, String> extraDetail) {
        admin.require(AdminScope.LICENSE_LIFECYCLE);
        String cleanReason = reason == null ? "" : reason.trim();
        if (cleanReason.length() > 200) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "reason is too long (max 200)");
        }
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                Result result = tx.inTransaction(t -> {
                    Instant now = clock.instant();
                    License current = store.findLicense(t, id).orElse(null);
                    if (current == null) {
                        return new Result(null, ErrorCode.LICENSE_NOT_FOUND);
                    }
                    License updated;
                    try {
                        updated = transition.apply(current, now);
                    } catch (IllegalLicenseTransitionException e) {
                        store.appendAudit(t, AuditEvent.of(now, admin.actor(), action, id, AuditOutcome.FAILURE,
                                "reason=transition_not_permitted; from=" + current.status()));
                        return new Result(null, ErrorCode.ILLEGAL_TRANSITION);
                    }
                    if (!store.updateLicense(t, updated, current.version())) {
                        throw new ConcurrentUpdateException("license changed concurrently");
                    }
                    store.appendAudit(t, AuditEvent.of(now, admin.actor(), action, id, AuditOutcome.SUCCESS,
                            AuditEvent.detail("from", current.status().name(), "to", updated.status().name(),
                                    "note", cleanReason.isEmpty() ? "-" : cleanReason) + extraDetail.apply(current, updated)));
                    return new Result(new LicenseView(updated.withVersion(current.version() + 1), updated.effectiveStatus(now)), null);
                });
                if (result.failure() != null) {
                    throw new LicensingException(result.failure());
                }
                return result.view();
            } catch (ConcurrentUpdateException race) {
                // Someone else changed the license first: re-read and re-evaluate against the new state.
            }
        }
        throw new LicensingException(ErrorCode.CONFLICT);
    }

    private record Result(LicenseView view, ErrorCode failure) {
    }
}
