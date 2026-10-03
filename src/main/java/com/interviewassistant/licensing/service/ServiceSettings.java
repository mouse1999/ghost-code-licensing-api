package com.interviewassistant.licensing.service;

import java.time.Duration;

/**
 * @param issuer         {@code iss} claim of entitlements
 * @param entitlementTtl how long an issued entitlement stays valid (capped by the license end). Also the longest a desktop
 *                       client can run offline on one token, so it is the main offline-grace knob for Phase 129.
 * @param proofMaxSkew   how far a client proof timestamp may differ from server time
 */
public record ServiceSettings(String issuer, Duration entitlementTtl, Duration proofMaxSkew) {

    public ServiceSettings {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer is required");
        }
        if (entitlementTtl.compareTo(Duration.ofMinutes(5)) < 0 || entitlementTtl.compareTo(Duration.ofDays(90)) > 0) {
            throw new IllegalArgumentException("entitlementTtl must be between 5 minutes and 90 days");
        }
        if (proofMaxSkew.compareTo(Duration.ofSeconds(30)) < 0 || proofMaxSkew.compareTo(Duration.ofMinutes(30)) > 0) {
            throw new IllegalArgumentException("proofMaxSkew must be between 30 seconds and 30 minutes");
        }
    }
}
