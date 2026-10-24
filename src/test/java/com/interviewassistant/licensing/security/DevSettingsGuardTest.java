package com.interviewassistant.licensing.security;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class DevSettingsGuardTest {
    @Test
    void productionSettingsNeedNoLoopback() {
        assertFalse(DevSettingsGuard.check(true, false, null).developmentSettings());
        assertFalse(DevSettingsGuard.check(true, false, "0.0.0.0").developmentSettings());
    }

    @Test
    void developmentSettingsAreAllowedOnlyOnLoopback() {
        for (String ok : new String[] {"127.0.0.1", "localhost", "::1", "[::1]", " 127.0.0.1 "}) {
            assertTrue(DevSettingsGuard.check(false, false, ok).developmentSettings());
            assertTrue(DevSettingsGuard.check(true, true, ok).developmentSettings());
        }
    }

    @Test
    void developmentSettingsOnAnythingElseRefuseToStartWithoutEchoingValues() {
        for (String bad : new String[] {null, "", " ", "0.0.0.0", "::", "10.0.0.5", "licensing.example.com", "127.0.0.1.evil.com", "1270.0.0.1"}) {
            IllegalStateException e1 = assertThrows(IllegalStateException.class, () -> DevSettingsGuard.check(false, false, bad));
            assertThrows(IllegalStateException.class, () -> DevSettingsGuard.check(true, true, bad));
            if (bad != null && !bad.isBlank()) {
                assertFalse(e1.getMessage().contains(bad.trim()), "message must not echo the configured value");
            }
        }
    }
}
