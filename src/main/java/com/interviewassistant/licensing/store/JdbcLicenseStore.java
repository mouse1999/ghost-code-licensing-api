package com.interviewassistant.licensing.store;

import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.DeviceRegistration;
import com.interviewassistant.licensing.domain.DeviceStatus;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.store.JdbcTransactionRunner.JdbcTx;
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import com.interviewassistant.licensing.store.StoreExceptions.StoreFailureException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JDBC implementation using only portable SQL (PostgreSQL in production, H2 in PostgreSQL mode in tests). All values are bound
 * as parameters; no SQL is built from request data. The two concurrency-critical statements are {@code updateLicense}
 * (optimistic version check) and {@code reserveDeviceSlot} (conditional increment).
 */
public final class JdbcLicenseStore implements LicenseStore {

    private static final String UNIQUE_VIOLATION = "23505";

    private static final String LICENSE_COLUMNS = "id, customer_email, status, device_limit, validity_days, rights, "
            + "activation_window_days, created_at, activation_deadline, activated_at, expires_at, suspended_at, revoked_at, "
            + "updated_at, active_device_count, version";

    // ------------------------------------------------------------------ licenses

    @Override
    public Optional<License> findLicense(Tx tx, UUID id) {
        return queryOne(tx, "SELECT " + LICENSE_COLUMNS + " FROM license WHERE id = ?", ps -> ps.setObject(1, id),
                JdbcLicenseStore::license);
    }

    @Override
    public List<License> findLicensesByEmail(Tx tx, String normalizedEmail) {
        return queryList(tx, "SELECT " + LICENSE_COLUMNS + " FROM license WHERE customer_email = ? ORDER BY created_at DESC, id",
                ps -> ps.setString(1, normalizedEmail), JdbcLicenseStore::license);
    }

    @Override
    public Optional<License> findByEmailAndCodeHash(Tx tx, String normalizedEmail, String codeHash) {
        return queryOne(tx, "SELECT " + prefixed("l") + " FROM license l JOIN activation_credential c ON c.license_id = l.id "
                        + "WHERE c.code_hash = ? AND l.customer_email = ?",
                ps -> {
                    ps.setString(1, codeHash);
                    ps.setString(2, normalizedEmail);
                }, JdbcLicenseStore::license);
    }

    @Override
    public void insertLicense(Tx tx, License l, String codeHash) {
        LicensePolicy p = l.policy();
        execute(tx, "INSERT INTO license (" + LICENSE_COLUMNS + ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ps -> {
            ps.setObject(1, l.id());
            ps.setString(2, l.customerEmail());
            ps.setString(3, l.status().name());
            ps.setInt(4, p.deviceLimit());
            ps.setObject(5, p.validityDays(), java.sql.Types.INTEGER);
            ps.setString(6, rightsCsv(p.rights()));
            ps.setInt(7, p.activationWindowDays());
            ps.setObject(8, ts(l.createdAt()));
            ps.setObject(9, ts(l.activationDeadline()));
            ps.setObject(10, ts(l.activatedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(11, ts(l.expiresAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(12, ts(l.suspendedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(13, ts(l.revokedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(14, ts(l.updatedAt()));
            ps.setInt(15, l.activeDeviceCount());
            ps.setLong(16, l.version());
        });
        execute(tx, "INSERT INTO activation_credential (license_id, code_hash, created_at) VALUES (?,?,?)", ps -> {
            ps.setObject(1, l.id());
            ps.setString(2, codeHash);
            ps.setObject(3, ts(l.createdAt()));
        });
    }

    @Override
    public boolean updateLicense(Tx tx, License u, long expectedVersion) {
        return execute(tx, "UPDATE license SET status = ?, activated_at = ?, expires_at = ?, suspended_at = ?, revoked_at = ?, "
                + "updated_at = ?, version = version + 1 WHERE id = ? AND version = ?", ps -> {
            ps.setString(1, u.status().name());
            ps.setObject(2, ts(u.activatedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(3, ts(u.expiresAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(4, ts(u.suspendedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(5, ts(u.revokedAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
            ps.setObject(6, ts(u.updatedAt()));
            ps.setObject(7, u.id());
            ps.setLong(8, expectedVersion);
        }) == 1;
    }

    @Override
    public boolean reserveDeviceSlot(Tx tx, UUID licenseId, Instant now) {
        return execute(tx, "UPDATE license SET active_device_count = active_device_count + 1, updated_at = ?, version = version + 1 "
                + "WHERE id = ? AND status IN ('PENDING', 'ACTIVE') AND active_device_count < device_limit", ps -> {
            ps.setObject(1, ts(now));
            ps.setObject(2, licenseId);
        }) == 1;
    }

    // ------------------------------------------------------------------ devices

    private static final String DEVICE_COLUMNS = "id, license_id, public_key, key_thumbprint, supplementary_fingerprint_hash, "
            + "label, bound_at, status, reset_at";

    @Override
    public Optional<DeviceRegistration> findDevice(Tx tx, UUID deviceId) {
        return queryOne(tx, "SELECT " + DEVICE_COLUMNS + " FROM device_registration WHERE id = ?", ps -> ps.setObject(1, deviceId),
                JdbcLicenseStore::device);
    }

    @Override
    public Optional<DeviceRegistration> findDeviceByThumbprint(Tx tx, UUID licenseId, String thumbprint) {
        return queryOne(tx, "SELECT " + DEVICE_COLUMNS + " FROM device_registration WHERE license_id = ? AND key_thumbprint = ?",
                ps -> {
                    ps.setObject(1, licenseId);
                    ps.setString(2, thumbprint);
                }, JdbcLicenseStore::device);
    }

    @Override
    public void insertDevice(Tx tx, DeviceRegistration d) {
        execute(tx, "INSERT INTO device_registration (" + DEVICE_COLUMNS + ") VALUES (?,?,?,?,?,?,?,?,?)", ps -> {
            ps.setObject(1, d.id());
            ps.setObject(2, d.licenseId());
            ps.setString(3, d.publicKey());
            ps.setString(4, d.keyThumbprint());
            ps.setString(5, d.supplementaryFingerprintHash());
            ps.setString(6, d.label());
            ps.setObject(7, ts(d.boundAt()));
            ps.setString(8, d.status().name());
            ps.setObject(9, ts(d.resetAt()), java.sql.Types.TIMESTAMP_WITH_TIMEZONE);
        });
    }

    // ------------------------------------------------------------------ idempotency

    @Override
    public Optional<IssuanceRecord> findIssuance(Tx tx, String keyHash) {
        return queryOne(tx, "SELECT key_hash, fingerprint, license_id, created_at FROM issuance_request WHERE key_hash = ?",
                ps -> ps.setString(1, keyHash),
                rs -> new IssuanceRecord(rs.getString(1).trim(), rs.getString(2).trim(), rs.getObject(3, UUID.class), instant(rs, 4)));
    }

    @Override
    public void insertIssuance(Tx tx, IssuanceRecord r) {
        execute(tx, "INSERT INTO issuance_request (key_hash, fingerprint, license_id, created_at) VALUES (?,?,?,?)", ps -> {
            ps.setString(1, r.keyHash());
            ps.setString(2, r.fingerprint());
            ps.setObject(3, r.licenseId());
            ps.setObject(4, ts(r.createdAt()));
        });
    }

    // ------------------------------------------------------------------ audit

    @Override
    public long appendAudit(Tx tx, AuditEvent e) {
        try (PreparedStatement ps = conn(tx).prepareStatement(
                "INSERT INTO audit_event (occurred_at, actor, action, license_id, outcome, detail) VALUES (?,?,?,?,?,?)",
                new String[] {"id"})) {
            ps.setObject(1, ts(e.occurredAt()));
            ps.setString(2, e.actor());
            ps.setString(3, e.action().name());
            if (e.licenseId() == null) {
                ps.setNull(4, java.sql.Types.OTHER);
            } else {
                ps.setObject(4, e.licenseId());
            }
            ps.setString(5, e.outcome().name());
            ps.setString(6, e.detail());
            ps.executeUpdate();
            try (ResultSet keys = ps.getGeneratedKeys()) {
                return keys.next() ? keys.getLong(1) : -1L;
            }
        } catch (SQLException ex) {
            throw failure(ex);
        }
    }

    @Override
    public List<AuditEvent> findAudit(Tx tx, UUID licenseId, Long beforeId, int limit) {
        StringBuilder sql = new StringBuilder("SELECT id, occurred_at, actor, action, license_id, outcome, detail FROM audit_event WHERE 1 = 1");
        if (licenseId != null) {
            sql.append(" AND license_id = ?");
        }
        if (beforeId != null) {
            sql.append(" AND id < ?");
        }
        sql.append(" ORDER BY id DESC LIMIT ?");
        return queryList(tx, sql.toString(), ps -> {
            int i = 1;
            if (licenseId != null) {
                ps.setObject(i++, licenseId);
            }
            if (beforeId != null) {
                ps.setLong(i++, beforeId);
            }
            ps.setInt(i, limit);
        }, rs -> new AuditEvent(rs.getLong(1), instant(rs, 2), rs.getString(3), AuditAction.valueOf(rs.getString(4)),
                rs.getObject(5, UUID.class), AuditOutcome.valueOf(rs.getString(6)), rs.getString(7)));
    }

    // ------------------------------------------------------------------ mapping

    private static License license(ResultSet rs) throws SQLException {
        Integer validity = rs.getObject(5) == null ? null : rs.getInt(5);
        LicensePolicy policy = new LicensePolicy(rs.getInt(4), validity, parseRights(rs.getString(6)), rs.getInt(7));
        return new License(rs.getObject(1, UUID.class), rs.getString(2), LicenseStatus.valueOf(rs.getString(3)), policy,
                instant(rs, 8), instant(rs, 9), instant(rs, 10), instant(rs, 11), instant(rs, 12), instant(rs, 13),
                instant(rs, 14), rs.getInt(15), rs.getLong(16));
    }

    private static DeviceRegistration device(ResultSet rs) throws SQLException {
        String fp = rs.getString(5);
        return new DeviceRegistration(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3),
                rs.getString(4).trim(), fp == null ? null : fp.trim(), rs.getString(6), instant(rs, 7),
                DeviceStatus.valueOf(rs.getString(8)), instant(rs, 9));
    }

    private static String rightsCsv(Set<LicenseRight> rights) {
        return rights.stream().map(Enum::name).sorted().collect(Collectors.joining(","));
    }

    private static Set<LicenseRight> parseRights(String csv) {
        Set<LicenseRight> out = EnumSet.noneOf(LicenseRight.class);
        Arrays.stream(csv.split(",")).map(String::trim).filter(s -> !s.isEmpty()).forEach(s -> out.add(LicenseRight.valueOf(s)));
        return out;
    }

    private static OffsetDateTime ts(Instant i) {
        return i == null ? null : OffsetDateTime.ofInstant(i, ZoneOffset.UTC);
    }

    private static Instant instant(ResultSet rs, int col) throws SQLException {
        OffsetDateTime t = rs.getObject(col, OffsetDateTime.class);
        return t == null ? null : t.toInstant();
    }

    private static String prefixed(String alias) {
        return Arrays.stream(LICENSE_COLUMNS.split(",\\s*")).map(c -> alias + "." + c).collect(Collectors.joining(", "));
    }

    // ------------------------------------------------------------------ search and statistics (Phase 133)

    /**
     * The status that applies at one instant, computed in SQL exactly as {@code License.effectiveStatus} does in Java (a PENDING
     * license lapses at its activation deadline or its fixed end date; an ACTIVE one at its end date). Takes THREE timestamp
     * parameters, all "now".
     */
    private static final String EFFECTIVE_STATUS_SQL = "CASE status "
            + "WHEN 'PENDING' THEN CASE WHEN ? >= activation_deadline OR (expires_at IS NOT NULL AND ? >= expires_at) "
            + "THEN 'EXPIRED' ELSE 'PENDING' END "
            + "WHEN 'ACTIVE' THEN CASE WHEN expires_at IS NOT NULL AND ? >= expires_at THEN 'EXPIRED' ELSE 'ACTIVE' END "
            + "ELSE status END";

    private static int bindNow(PreparedStatement ps, int index, Instant now) throws SQLException {
        for (int i = 0; i < 3; i++) {
            ps.setObject(index++, ts(now));
        }
        return index;
    }

    @Override
    public List<License> searchLicenses(Tx tx, Instant now, String emailContains, LicenseStatus effective, int limit, int offset) {
        StringBuilder sql = new StringBuilder("SELECT " + LICENSE_COLUMNS + " FROM license WHERE 1 = 1");
        if (emailContains != null) {
            sql.append(" AND customer_email LIKE ? ESCAPE '\\'");
        }
        if (effective != null) {
            sql.append(" AND (").append(EFFECTIVE_STATUS_SQL).append(") = ?");
        }
        sql.append(" ORDER BY created_at DESC, id LIMIT ? OFFSET ?");
        return queryList(tx, sql.toString(), ps -> {
            int i = 1;
            if (emailContains != null) {
                ps.setString(i++, "%" + escapeLike(emailContains) + "%");
            }
            if (effective != null) {
                i = bindNow(ps, i, now);
                ps.setString(i++, effective.name());
            }
            ps.setInt(i++, limit);
            ps.setInt(i, offset);
        }, JdbcLicenseStore::license);
    }

    /** Makes a user-supplied fragment literal inside LIKE: the escape character, '%' and '_' lose their special meaning. */
    static String escapeLike(String fragment) {
        return fragment.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
    }

    @Override
    public LicenseCounts countLicenses(Tx tx, Instant now) {
        String sql = "SELECT COUNT(*), "
                + "SUM(CASE WHEN eff = 'PENDING' THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN eff = 'ACTIVE' THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN eff = 'EXPIRED' AND activated_at IS NOT NULL THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN eff = 'EXPIRED' AND activated_at IS NULL THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN eff = 'SUSPENDED' THEN 1 ELSE 0 END), "
                + "SUM(CASE WHEN eff = 'REVOKED' THEN 1 ELSE 0 END) "
                + "FROM (SELECT activated_at, " + EFFECTIVE_STATUS_SQL + " AS eff FROM license) x";
        return queryOne(tx, sql, ps -> bindNow(ps, 1, now),
                rs -> new LicenseCounts(rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4), rs.getLong(5), rs.getLong(6),
                        rs.getLong(7))).orElse(new LicenseCounts(0, 0, 0, 0, 0, 0, 0));
    }

    @Override
    public Map<String, Long> countAuditSince(Tx tx, Instant since) {
        Map<String, Long> out = new LinkedHashMap<>();
        queryList(tx, "SELECT action, outcome, COUNT(*) FROM audit_event WHERE occurred_at >= ? GROUP BY action, outcome",
                ps -> ps.setObject(1, ts(since)), rs -> {
                    out.put(rs.getString(1) + "/" + rs.getString(2), rs.getLong(3));
                    return Boolean.TRUE;
                });
        return out;
    }

    @Override
    public Optional<Instant> earliestAudit(Tx tx) {
        // MIN over an empty table is one row holding NULL: Optional.of(null) in queryOne would throw, so read the list directly.
        List<Instant> rows = queryList(tx, "SELECT MIN(occurred_at) FROM audit_event", ps -> { }, rs -> instant(rs, 1));
        return rows.isEmpty() || rows.get(0) == null ? Optional.empty() : Optional.of(rows.get(0));
    }

    // ------------------------------------------------------------------ plumbing

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    @FunctionalInterface
    private interface RowMapper<T> {
        T map(ResultSet rs) throws SQLException;
    }

    private static Connection conn(Tx tx) {
        return ((JdbcTx) tx).connection();
    }

    private static int execute(Tx tx, String sql, Binder binder) {
        try (PreparedStatement ps = conn(tx).prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw failure(e);
        }
    }

    private static <T> Optional<T> queryOne(Tx tx, String sql, Binder binder, RowMapper<T> mapper) {
        List<T> rows = queryList(tx, sql, binder, mapper);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private static <T> List<T> queryList(Tx tx, String sql, Binder binder, RowMapper<T> mapper) {
        try (PreparedStatement ps = conn(tx).prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                List<T> out = new ArrayList<>();
                while (rs.next()) {
                    out.add(mapper.map(rs));
                }
                return out;
            }
        } catch (SQLException e) {
            throw failure(e);
        }
    }

    private static RuntimeException failure(SQLException e) {
        if (UNIQUE_VIOLATION.equals(e.getSQLState())) {
            return new DuplicateRecordException("unique constraint violated");
        }
        // SQL text and parameters are intentionally not included.
        return new StoreFailureException("database operation failed (SQLState " + e.getSQLState() + ")", e);
    }
}
