package com.interviewassistant.licensing.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A device bound to a license by its PUBLIC key. The private key never leaves the device; possession of it is proven by a
 * signature on every client request. The optional supplementary fingerprint is stored only as an HMAC and is never trusted as
 * proof of ownership.
 *
 * @param publicKey        Ed25519 public key, X.509 SubjectPublicKeyInfo DER, base64url
 * @param keyThumbprint    SHA-256 of the DER bytes, lowercase hex (64 chars)
 * @param supplementaryFingerprintHash HMAC of a client hardware/OS fingerprint, or null; evidence only
 */
public record DeviceRegistration(
        UUID id,
        UUID licenseId,
        String publicKey,
        String keyThumbprint,
        String supplementaryFingerprintHash,
        String label,
        Instant boundAt,
        DeviceStatus status,
        Instant resetAt) {

    public DeviceRegistration {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(licenseId, "licenseId");
        Objects.requireNonNull(publicKey, "publicKey");
        Objects.requireNonNull(keyThumbprint, "keyThumbprint");
        Objects.requireNonNull(boundAt, "boundAt");
        Objects.requireNonNull(status, "status");
    }

    public boolean isActive() {
        return status == DeviceStatus.ACTIVE;
    }
}
