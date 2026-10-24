package com.interviewassistant.licensing.security;

import java.util.Locale;

/**
 * Phase 136: the development settings (plain HTTP accepted, throw-away signing key) must never be reachable from a network.
 * Whenever either is on, the server has to be bound to a loopback address explicitly; an unset address means "all interfaces"
 * and is refused. The messages name the setting, never a value.
 */
public final class DevSettingsGuard {
    /** Marker returned so Spring can hold the check as a bean (it runs at start-up). */
    public record Checked(boolean developmentSettings) {
    }

    private DevSettingsGuard() {
    }

    public static Checked check(boolean requireHttps, boolean allowEphemeralKey, String serverAddress) {
        boolean dev = !requireHttps || allowEphemeralKey;
        if (dev && !isLoopback(serverAddress)) {
            throw new IllegalStateException("licensing.security.require-https=false or licensing.signing.allow-ephemeral=true "
                    + "is only allowed when server.address is a loopback address; refusing to start");
        }
        return new Checked(dev);
    }

    static boolean isLoopback(String address) {
        if (address == null || address.isBlank()) {
            return false;
        }
        String a = address.trim().toLowerCase(Locale.ROOT);
        return a.equals("localhost") || a.equals("::1") || a.equals("[::1]") || a.matches("127(\\.\\d{1,3}){3}");
    }
}
