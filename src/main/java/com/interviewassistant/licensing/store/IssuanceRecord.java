package com.interviewassistant.licensing.store;

import java.time.Instant;
import java.util.UUID;

/**
 * Remembers an administrative issuance so a retry with the same Idempotency-Key cannot create a second license.
 *
 * @param keyHash     SHA-256 hex of (admin credential id + key)
 * @param fingerprint SHA-256 hex of the canonical request, to detect a key reused for a different request
 */
public record IssuanceRecord(String keyHash, String fingerprint, UUID licenseId, Instant createdAt) {
}
