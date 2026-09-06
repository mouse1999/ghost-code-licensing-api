package com.interviewassistant.licensing.domain;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * The server-approved claims the desktop application can verify offline (version 1).
 *
 * <p>Carried as a signed JWS (see {@code EntitlementSigner}); claim names in the token are the standard
 * {@code iat}/{@code exp}/{@code jti}/{@code iss} plus the licensing-specific ones listed on the fields. A valid signature
 * proves only that the server issued these claims; it does NOT override a later suspension or revocation, which the client
 * learns by validating with the server (offline behaviour is defined in a later phase).
 *
 * @param entitlementId       {@code jti}: unique per issued token
 * @param licenseId           {@code lic}
 * @param deviceRegistrationId {@code dev}: the registration this token was issued to
 * @param deviceKeyThumbprint {@code dkt}: thumbprint of the registered device key (token is bound to that key)
 * @param rights              {@code rights}
 * @param issuedAt            {@code iat}
 * @param expiresAt           {@code exp}: the token must not be honoured after this instant
 * @param renewAfter          {@code ren}: the client should renew with the server from this instant
 * @param licenseExpiresAt    {@code lexp}: end of the license itself, or null if it does not expire
 * @param issuer              {@code iss}
 */
public record Entitlement(
        int version,
        UUID entitlementId,
        UUID licenseId,
        UUID deviceRegistrationId,
        String deviceKeyThumbprint,
        Set<LicenseRight> rights,
        Instant issuedAt,
        Instant expiresAt,
        Instant renewAfter,
        Instant licenseExpiresAt,
        String issuer) {

    public static final int CURRENT_VERSION = 1;

    public Entitlement {
        if (version != CURRENT_VERSION) {
            throw new IllegalArgumentException("unsupported entitlement version " + version);
        }
        Objects.requireNonNull(entitlementId, "entitlementId");
        Objects.requireNonNull(licenseId, "licenseId");
        Objects.requireNonNull(deviceRegistrationId, "deviceRegistrationId");
        Objects.requireNonNull(deviceKeyThumbprint, "deviceKeyThumbprint");
        Objects.requireNonNull(issuedAt, "issuedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(renewAfter, "renewAfter");
        Objects.requireNonNull(issuer, "issuer");
        if (rights == null || rights.isEmpty()) {
            throw new IllegalArgumentException("rights must not be empty");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
        rights = Set.copyOf(EnumSet.copyOf(rights));
    }
}
