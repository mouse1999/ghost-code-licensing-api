package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.store.JdbcLicenseStore;
import com.interviewassistant.licensing.store.JdbcTransactionRunner;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.TransactionRunner;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * Optional PostgreSQL mode for {@link Fixture}: when the system property {@code licensing.test.pgUrl} (a JDBC URL of the server's
 * "postgres" database; user in {@code licensing.test.pgUser}, default postgres) is set, every Fixture gets its OWN database cloned
 * from the migrated template database {@code lic_tmpl}, and the real {@link JdbcLicenseStore} and {@link JdbcTransactionRunner}.
 * Nothing but test-owned databases is touched. Without the property the in-memory store is used and nothing here runs.
 */
final class PgSupport {

    private static final AtomicInteger SEQ = new AtomicInteger();

    private PgSupport() {
    }

    static boolean enabled() {
        return System.getProperty("licensing.test.pgUrl") != null;
    }

    record Ds(String url, String user) implements DataSource {
        @Override public Connection getConnection() throws SQLException {
            java.util.Properties p = new java.util.Properties();
            p.setProperty("user", user);
            return DriverManager.getConnection(url, p);
        }
        @Override public Connection getConnection(String u, String p) throws SQLException { return getConnection(); }
        @Override public PrintWriter getLogWriter() { return null; }
        @Override public void setLogWriter(PrintWriter out) { }
        @Override public void setLoginTimeout(int s) { }
        @Override public int getLoginTimeout() { return 0; }
        @Override public Logger getParentLogger() { return Logger.getLogger("pg"); }
        @Override public <T> T unwrap(Class<T> c) throws SQLException { throw new SQLException("no"); }
        @Override public boolean isWrapperFor(Class<?> c) { return false; }
    }

    /** A fresh, migrated, empty database for one Fixture. */
    static final class Db implements Inspect {
        final Ds ds;
        final JdbcLicenseStore store = new JdbcLicenseStore();
        final TransactionRunner tx;
        final String name;

        Db() {
            String admin = System.getProperty("licensing.test.pgUrl");
            String user = System.getProperty("licensing.test.pgUser", "postgres");
            name = "t_" + ProcessHandle.current().pid() + "_" + SEQ.incrementAndGet() + "_" + Long.toHexString(System.nanoTime());
            try (Connection c = new Ds(admin, user).getConnection(); PreparedStatement ps = c.prepareStatement("CREATE DATABASE " + name + " TEMPLATE lic_tmpl")) {
                ps.executeUpdate();
            } catch (SQLException e) {
                throw new IllegalStateException("cannot create the test database: " + e.getMessage(), e);
            }
            ds = new Ds(admin.substring(0, admin.lastIndexOf('/') + 1) + name, user);
            tx = new JdbcTransactionRunner(ds);
        }

        LicenseStore licenses() { return store; }

        private String one(String sql) {
            try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getString(1) : null;
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        /** Runs one raw statement on its own connection; returns "OK" or the SQLState it failed with. */
        String tryExec(String sql) {
            try (Connection c = ds.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
                ps.executeUpdate();
                return "OK";
            } catch (SQLException e) {
                return e.getSQLState();
            }
        }

        String scalar(String sql) { return one(sql); }

        @Override public List<AuditEvent> allAudit() {
            List<AuditEvent> all = new ArrayList<>(tx.inTransaction(t -> store.findAudit(t, null, null, 200)));
            Collections.reverse(all);
            return all;
        }
        @Override public int licenseCount() { return Integer.parseInt(one("SELECT COUNT(*) FROM license")); }
        @Override public int countByEmail(String email) { return Integer.parseInt(one("SELECT COUNT(*) FROM license WHERE customer_email = '" + email.replace("'", "''") + "'")); }
        @Override public int deviceCount(UUID id) { return Integer.parseInt(one("SELECT COUNT(*) FROM device_registration WHERE license_id = '" + id + "'")); }
        @Override public License license(UUID id) { return tx.inTransaction(t -> store.findLicense(t, id)).orElse(null); }
        @Override public String dumpEverythingStored() {
            return one("SELECT concat_ws(E'\\n', (SELECT string_agg(t::text, E'\\n') FROM license t), (SELECT string_agg(t::text, E'\\n') FROM activation_credential t), "
                    + "(SELECT string_agg(t::text, E'\\n') FROM device_registration t), (SELECT string_agg(t::text, E'\\n') FROM issuance_request t), "
                    + "(SELECT string_agg(t::text, E'\\n') FROM audit_event t))");
        }
    }
}
