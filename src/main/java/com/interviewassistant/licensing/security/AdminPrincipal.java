package com.interviewassistant.licensing.security;

import com.interviewassistant.licensing.service.ErrorCode;
import com.interviewassistant.licensing.service.LicensingException;

import java.util.EnumSet;
import java.util.Set;

/** An authenticated administrator: the credential id (never the token) and its scopes. */
public record AdminPrincipal(String id, Set<AdminScope> scopes) {

    public AdminPrincipal {
        scopes = Set.copyOf(scopes.isEmpty() ? EnumSet.noneOf(AdminScope.class) : EnumSet.copyOf(scopes));
    }

    /** The audit actor string for this administrator. */
    public String actor() {
        return "admin:" + id;
    }

    public boolean has(AdminScope scope) {
        return scopes.contains(scope);
    }

    /** Authorisation check: authenticated but lacking the scope is 403, not 401. */
    public void require(AdminScope scope) {
        if (!has(scope)) {
            throw new LicensingException(ErrorCode.FORBIDDEN, "this credential is not permitted to do that");
        }
    }
}
