package com.interviewassistant.licensing.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * What an administrator grants when issuing a license. Explicit and validated: nothing here is ever taken from a customer.
 *
 * @param deviceLimit         how many devices may be registered at once (1..{@value #MAX_DEVICE_LIMIT})
 * @param validityDays        license length counted from first activation, or {@code null} for a license that does not expire
 * @param rights              the rights granted (non-empty)
 * @param activationWindowDays how long the activation code may be redeemed after issuance (1..{@value #MAX_WINDOW_DAYS})
 */
public record LicensePolicy(int deviceLimit, Integer validityDays, Set<LicenseRight> rights, int activationWindowDays) {

    public static final int MAX_DEVICE_LIMIT = 10;
    public static final int MAX_VALIDITY_DAYS = 3650;
    public static final int MAX_WINDOW_DAYS = 365;

    public LicensePolicy {
        if (deviceLimit < 1 || deviceLimit > MAX_DEVICE_LIMIT) {
            throw new IllegalArgumentException("deviceLimit must be between 1 and " + MAX_DEVICE_LIMIT);
        }
        if (validityDays != null && (validityDays < 1 || validityDays > MAX_VALIDITY_DAYS)) {
            throw new IllegalArgumentException("validityDays must be between 1 and " + MAX_VALIDITY_DAYS + " or absent");
        }
        if (rights == null || rights.isEmpty()) {
            throw new IllegalArgumentException("at least one right is required");
        }
        if (activationWindowDays < 1 || activationWindowDays > MAX_WINDOW_DAYS) {
            throw new IllegalArgumentException("activationWindowDays must be between 1 and " + MAX_WINDOW_DAYS);
        }
        rights = Set.copyOf(EnumSet.copyOf(rights));
    }
}
