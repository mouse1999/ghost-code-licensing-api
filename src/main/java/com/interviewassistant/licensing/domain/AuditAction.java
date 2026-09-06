package com.interviewassistant.licensing.domain;

/** Security-relevant actions that are written to the append-only audit trail. */
public enum AuditAction {
    LICENSE_ISSUED,
    LICENSE_ISSUE_REPLAYED,
    LICENSE_SUSPENDED,
    LICENSE_REINSTATED,
    LICENSE_RENEWED,
    LICENSE_REVOKED,
    LICENSE_EXPIRED,
    ACTIVATION,
    DEVICE_BOUND,
    ENTITLEMENT_ISSUED,
    VALIDATION_REJECTED
}
