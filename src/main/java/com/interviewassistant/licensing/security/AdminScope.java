package com.interviewassistant.licensing.security;

/** Least-privilege permissions for administrative credentials. Each credential carries only the scopes it needs. */
public enum AdminScope {
    LICENSE_ISSUE,
    LICENSE_READ,
    LICENSE_LIFECYCLE,
    AUDIT_READ
}
