package com.interviewassistant.licensing.security;

import com.interviewassistant.licensing.security.AdminAuthenticator.Credential;
import com.interviewassistant.licensing.service.ErrorCode;
import com.interviewassistant.licensing.service.LicensingException;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class AdminAuthenticatorTest {

    private static final SecureRandom RNG = new SecureRandom();

    private record Setup(AdminAuthenticator auth, String tokenA, String tokenB) {
    }

    private static Setup setup() {
        String a = AdminAuthenticator.generateToken(RNG);
        String b = AdminAuthenticator.generateToken(RNG);
        return new Setup(new AdminAuthenticator(List.of(
                Credential.ofHex("issuer", AdminAuthenticator.hashHex(a), EnumSet.of(AdminScope.LICENSE_ISSUE, AdminScope.LICENSE_READ)),
                Credential.ofHex("auditor", AdminAuthenticator.hashHex(b), EnumSet.of(AdminScope.AUDIT_READ)))), a, b);
    }

    @Test
    void generatedTokensHave256BitsAndAreUnique() {
        String t = AdminAuthenticator.generateToken(RNG);
        assertTrue(t.matches("ia_adm_[A-Za-z0-9_-]{43}"), t);
        assertNotEquals(t, AdminAuthenticator.generateToken(RNG));
    }

    @Test
    void validTokenResolvesToItsOwnCredentialAndScopes() {
        Setup s = setup();
        Optional<AdminPrincipal> p = s.auth().authenticate("Bearer " + s.tokenA());
        assertTrue(p.isPresent());
        assertEquals("issuer", p.get().id());
        assertEquals("admin:issuer", p.get().actor());
        assertTrue(p.get().has(AdminScope.LICENSE_ISSUE));
        assertFalse(p.get().has(AdminScope.LICENSE_LIFECYCLE));
        assertEquals("auditor", s.auth().authenticate("bearer " + s.tokenB()).orElseThrow().id());
    }

    @Test
    void everythingElseIsUnauthenticated() {
        Setup s = setup();
        String[] bad = {null, "", "Bearer", "Bearer ", "Basic " + s.tokenA(), s.tokenA(), "Bearer " + s.tokenA() + "x",
                "Bearer " + s.tokenA().substring(1), "Bearer ia_adm_" + "A".repeat(43), "Bearer x".repeat(100)};
        for (String h : bad) {
            assertTrue(s.auth().authenticate(h).isEmpty(), String.valueOf(h));
        }
        assertTrue(new AdminAuthenticator(List.of()).authenticate("Bearer " + s.tokenA()).isEmpty());
    }

    @Test
    void authenticatedButUnderPrivilegedIsForbiddenNotUnauthenticated() {
        Setup s = setup();
        AdminPrincipal auditor = s.auth().authenticate("Bearer " + s.tokenB()).orElseThrow();
        LicensingException ex = assertThrows(LicensingException.class, () -> auditor.require(AdminScope.LICENSE_ISSUE));
        assertEquals(ErrorCode.FORBIDDEN, ex.code());
        assertDoesNotThrow(() -> auditor.require(AdminScope.AUDIT_READ));
    }

    @Test
    void configurationErrorsFailFast() {
        assertThrows(IllegalArgumentException.class, () -> Credential.ofHex("x", "nothex", Set.of(AdminScope.AUDIT_READ)));
        assertThrows(IllegalArgumentException.class, () -> Credential.ofHex("x", "ab".repeat(31), Set.of(AdminScope.AUDIT_READ)));
        assertThrows(IllegalArgumentException.class, () -> Credential.ofHex("x", "ab".repeat(32), Set.of()));
        assertThrows(IllegalArgumentException.class, () -> Credential.ofHex("bad id", "ab".repeat(32), Set.of(AdminScope.AUDIT_READ)));
    }
}
