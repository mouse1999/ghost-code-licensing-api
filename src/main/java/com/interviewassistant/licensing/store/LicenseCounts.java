package com.interviewassistant.licensing.store;

/**
 * Counts of licenses by the status that applies at one instant, computed by the database from the persisted rows (no cache, no
 * second source of truth). The groups are mutually exclusive and add up to {@code total}.
 *
 * @param total                 every license ever issued and stored
 * @param pending               issued, not yet activated, activation window still open
 * @param active                activated and within its term (or without a term)
 * @param expiredAfterActivation activated, and its term has ended
 * @param lapsedUnactivated     never activated; the activation window (or a fixed end date) passed
 * @param suspended             administratively suspended (stored status)
 * @param revoked               administratively revoked (stored status)
 */
public record LicenseCounts(long total, long pending, long active, long expiredAfterActivation, long lapsedUnactivated,
                            long suspended, long revoked) {
}
