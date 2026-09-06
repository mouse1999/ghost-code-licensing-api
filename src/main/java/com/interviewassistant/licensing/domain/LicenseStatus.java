package com.interviewassistant.licensing.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * Lifecycle state of a license, with the complete set of permitted transitions.
 *
 * <pre>
 *   PENDING   -> ACTIVE | SUSPENDED | REVOKED | EXPIRED
 *   ACTIVE    -> SUSPENDED | REVOKED | EXPIRED
 *   SUSPENDED -> PENDING | ACTIVE | REVOKED | EXPIRED     (PENDING/ACTIVE: chosen by whether it was ever activated)
 *   REVOKED   -> (terminal)
 *   EXPIRED   -> (terminal, except that {@link License#renew} can bring an activated license back to ACTIVE)
 * </pre>
 *
 * The status is only ever changed by the server through {@link License}; no client-supplied status is accepted anywhere.
 */
public enum LicenseStatus {
    PENDING,
    ACTIVE,
    SUSPENDED,
    REVOKED,
    EXPIRED;

    public Set<LicenseStatus> allowedNext() {
        return switch (this) {
            case PENDING -> EnumSet.of(ACTIVE, SUSPENDED, REVOKED, EXPIRED);
            case ACTIVE -> EnumSet.of(SUSPENDED, REVOKED, EXPIRED);
            case SUSPENDED -> EnumSet.of(PENDING, ACTIVE, REVOKED, EXPIRED);
            case REVOKED, EXPIRED -> EnumSet.noneOf(LicenseStatus.class);
        };
    }

    public boolean canTransitionTo(LicenseStatus next) {
        return allowedNext().contains(next);
    }

    public boolean isTerminal() {
        return allowedNext().isEmpty();
    }
}
