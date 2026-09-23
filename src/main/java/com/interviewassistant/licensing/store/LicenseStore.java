package com.interviewassistant.licensing.store;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.DeviceRegistration;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicenseStatus;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence port. Every method takes the open {@link Tx} so that a service can combine several in one transaction.
 * The two concurrency-critical operations are single atomic statements in the JDBC implementation:
 * {@link #reserveDeviceSlot} and {@link #updateLicense}.
 */
public interface LicenseStore {

    Optional<License> findLicense(Tx tx, UUID id);

    List<License> findLicensesByEmail(Tx tx, String normalizedEmail);

    /** The license whose email AND activation-code hash both match, or empty. */
    Optional<License> findByEmailAndCodeHash(Tx tx, String normalizedEmail, String codeHash);

    /** Inserts a new license and its (hashed) activation credential together. */
    void insertLicense(Tx tx, License license, String codeHash);

    /**
     * Writes the mutable lifecycle fields if and only if the stored version equals {@code expectedVersion}, then increments the
     * version. Returns false if another request changed the license first.
     */
    boolean updateLicense(Tx tx, License updated, long expectedVersion);

    /**
     * Atomically takes one device slot: increments the active-device counter ONLY IF the license is PENDING or ACTIVE and the
     * counter is below the limit. Returns false if no slot was available. The database also enforces the limit with a CHECK
     * constraint, so even a coding mistake cannot exceed it.
     */
    boolean reserveDeviceSlot(Tx tx, UUID licenseId, Instant now);

    Optional<DeviceRegistration> findDevice(Tx tx, UUID deviceId);

    Optional<DeviceRegistration> findDeviceByThumbprint(Tx tx, UUID licenseId, String thumbprint);

    /** @throws StoreExceptions.DuplicateRecordException if (license, key thumbprint) is already registered */
    void insertDevice(Tx tx, DeviceRegistration device);

    Optional<IssuanceRecord> findIssuance(Tx tx, String keyHash);

    /** @throws StoreExceptions.DuplicateRecordException if the key hash already exists */
    void insertIssuance(Tx tx, IssuanceRecord record);

    /** Appends an audit event; there is deliberately no update or delete. Returns the new event id. */
    long appendAudit(Tx tx, AuditEvent event);

    /** Newest first. {@code licenseId} and {@code beforeId} are optional filters; {@code limit} is capped by the caller. */
    List<AuditEvent> findAudit(Tx tx, UUID licenseId, Long beforeId, int limit);

    /**
     * Licenses matching an optional case-insensitive e-mail fragment and an optional EFFECTIVE status (as of {@code now}), newest
     * first. {@code emailContains} is a literal fragment, not a pattern. The caller asks for {@code limit + 1} rows to learn
     * whether there is another page.
     */
    List<License> searchLicenses(Tx tx, Instant now, String emailContains, LicenseStatus effective, int limit, int offset);

    /** Counts of licenses by effective status at {@code now}. */
    LicenseCounts countLicenses(Tx tx, Instant now);

    /**
     * Number of audit events since {@code since} (inclusive), keyed {@code "ACTION/OUTCOME"} (for example
     * {@code "ACTIVATION/SUCCESS"}). Only events that were actually recorded are counted.
     */
    Map<String, Long> countAuditSince(Tx tx, Instant since);

    /** When the oldest audit event was recorded, if any: the earliest point the activity figures can speak for. */
    java.util.Optional<Instant> earliestAudit(Tx tx);
}
