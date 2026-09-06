package com.interviewassistant.licensing.domain;

/** A requested lifecycle change is not permitted from the license's current state. */
public final class IllegalLicenseTransitionException extends RuntimeException {

    private final LicenseStatus from;
    private final LicenseStatus to;

    public IllegalLicenseTransitionException(LicenseStatus from, LicenseStatus to, String reason) {
        super("license cannot move from " + from + " to " + to + ": " + reason);
        this.from = from;
        this.to = to;
    }

    public LicenseStatus from() {
        return from;
    }

    public LicenseStatus to() {
        return to;
    }
}
