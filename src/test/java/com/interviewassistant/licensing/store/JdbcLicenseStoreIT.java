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
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test of the REAL SQL in {@link JdbcLicenseStore} against H2 in PostgreSQL mode, applying the real migration file.
 *
 * NOT EXECUTED in the Phase 128 authoring sandbox (no H2 or JUnit jars; Maven Central blocked): it compiles, but has never run.
 * Run it with "mvn verify". The same SQL statements were exercised against PostgreSQL 16 by src/test/db/postgres-db-tests.sh.
 * Differences from production: H2 (embedded, PostgreSQL compatibility mode) instead of PostgreSQL; the PostgreSQL-only V2 audit
 * triggers are not applied.
 */
class JdbcLicenseStoreIT {

    private static final Instant T0 = Instant.parse("2026-11-01T12:00:00Z");

    /** Minimal DataSource over DriverManager, so this test needs no pool and no H2 class at compile time. */
    private record Ds(String url, String user) implements DataSource {
        @Override
        public Connection getConnection() throws SQLException {
            return DriverManager.getConnection(url, user, "");
        }

        @Override
        public Connection getConnection(String u, String p) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() {
            return null;
        }

        @Override
        public void setLogWriter(PrintWriter out) {
        }

        @Override
        public void setLoginTimeout(int seconds) {
        }

        @Override
        public int getLoginTimeout() {
            return 0;
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            throw new SQLException("not a wrapper");
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }

    private Path dir;
    private String url;
    private String user;
    private final JdbcLicenseStore store = new JdbcLicenseStore();

    @BeforeEach
    void freshDatabase() throws Exception {
        dir = Files.createTempDirectory("lic-it");
        // Phase 137: with -Dlicensing.test.pgUrl=jdbc:postgresql://host:port/postgres (+ optional -Dlicensing.test.pgUser) every test gets its own
        // empty, test-owned PostgreSQL database instead of H2. Without the property this test is unchanged.
        String pgAdmin = System.getProperty("licensing.test.pgUrl");
        user = pgAdmin == null ? "sa" : System.getProperty("licensing.test.pgUser", "postgres");
        if (pgAdmin == null) {
            url = "jdbc:h2:file:" + dir.resolve("db") + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH";
        } else {
            String name = "it_" + ProcessHandle.current().pid() + "_" + System.nanoTime();
            try (Connection c = new Ds(pgAdmin, user).getConnection(); Statement s = c.createStatement()) {
                s.execute("CREATE DATABASE " + name);
            }
            url = pgAdmin.substring(0, pgAdmin.lastIndexOf('/') + 1) + name;
        }
        String sql = Files.readString(Path.of("src/main/resources/db/migration/common/V1__licensing_core.sql"));
        StringBuilder noComments = new StringBuilder();
        for (String line : sql.split("\n")) {
            if (!line.trim().startsWith("--")) {
                noComments.append(line).append('\n');
            }
        }
        try (Connection c = new Ds(url, user).getConnection(); Statement s = c.createStatement()) {
            for (String stmt : noComments.toString().split(";")) {
                if (!stmt.isBlank()) {
                    s.execute(stmt);
                }
            }
        }
    }

    private License newLicense(String email, int limit) {
        return License.issue(UUID.randomUUID(), email, new LicensePolicy(limit, 30, EnumSet.of(LicenseRight.LIVE, LicenseRight.DSA), 30), T0);
    }

    private String hash(char c) {
        return String.valueOf(c).repeat(64);
    }

    @Test
    void licenseRoundTripsAndIsFoundByIdEmailAndCodeHash() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("a@example.com", 2);
        tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('a'));
            return null;
        });
        License byId = tx.inTransaction(t -> store.findLicense(t, l.id())).orElseThrow();
        assertEquals(l, byId);
        assertEquals(l.id(), tx.inTransaction(t -> store.findByEmailAndCodeHash(t, "a@example.com", hash('a'))).orElseThrow().id());
        assertTrue(tx.inTransaction(t -> store.findByEmailAndCodeHash(t, "a@example.com", hash('b'))).isEmpty());
        assertTrue(tx.inTransaction(t -> store.findByEmailAndCodeHash(t, "other@example.com", hash('a'))).isEmpty());
        assertEquals(1, tx.inTransaction(t -> store.findLicensesByEmail(t, "a@example.com")).size());
    }

    @Test
    void dataSurvivesClosingAndReopeningTheDatabase() {
        License l = newLicense("persist@example.com", 1);
        new JdbcTransactionRunner(new Ds(url, user)).inTransaction(t -> {
            store.insertLicense(t, l, hash('p'));
            store.appendAudit(t, AuditEvent.of(T0, "admin:dev", AuditAction.LICENSE_ISSUED, l.id(), AuditOutcome.SUCCESS, "x=1"));
            return null;
        });
        // "restart": a brand-new runner and connections against the same database file
        TransactionRunner after = new JdbcTransactionRunner(new Ds(url, user));
        assertEquals(l, after.inTransaction(t -> store.findLicense(t, l.id())).orElseThrow());
        assertEquals(1, after.inTransaction(t -> store.findAudit(t, l.id(), null, 10)).size());
    }

    @Test
    void failedTransactionRollsBackEverything() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("rb@example.com", 1);
        assertThrows(IllegalStateException.class, () -> tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('r'));
            store.appendAudit(t, AuditEvent.of(T0, "x", AuditAction.LICENSE_ISSUED, l.id(), AuditOutcome.SUCCESS, ""));
            throw new IllegalStateException("boom");
        }));
        assertTrue(tx.inTransaction(t -> store.findLicense(t, l.id())).isEmpty());
        assertTrue(tx.inTransaction(t -> store.findAudit(t, null, null, 10)).isEmpty());
    }

    @Test
    void uniqueConstraintsSurfaceAsDuplicateRecordException() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License a = newLicense("a@example.com", 1);
        tx.inTransaction(t -> {
            store.insertLicense(t, a, hash('a'));
            return null;
        });
        assertThrows(DuplicateRecordException.class, () -> tx.inTransaction(t -> {
            store.insertLicense(t, newLicense("b@example.com", 1), hash('a')); // same credential hash
            return null;
        }));
        DeviceRegistration d = new DeviceRegistration(UUID.randomUUID(), a.id(), "pk", hash('t'), null, "x", T0, DeviceStatus.ACTIVE, null);
        tx.inTransaction(t -> {
            store.insertDevice(t, d);
            return null;
        });
        assertThrows(DuplicateRecordException.class, () -> tx.inTransaction(t -> {
            store.insertDevice(t, new DeviceRegistration(UUID.randomUUID(), a.id(), "pk", hash('t'), null, "y", T0, DeviceStatus.ACTIVE, null));
            return null;
        }));
        IssuanceRecord rec = new IssuanceRecord(hash('i'), hash('f'), a.id(), T0);
        tx.inTransaction(t -> {
            store.insertIssuance(t, rec);
            return null;
        });
        assertThrows(DuplicateRecordException.class, () -> tx.inTransaction(t -> {
            store.insertIssuance(t, rec);
            return null;
        }));
        assertEquals(rec, tx.inTransaction(t -> store.findIssuance(t, hash('i'))).orElseThrow());
    }

    @Test
    void optimisticVersionCheckAllowsExactlyOneWriter() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("v@example.com", 1);
        tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('v'));
            return null;
        });
        License suspended = l.suspend(T0.plusSeconds(5));
        boolean suspendedUpdated = tx.inTransaction(t -> store.updateLicense(t, suspended, 0));
        assertTrue(suspendedUpdated);
        boolean staleUpdated = tx.inTransaction(t -> store.updateLicense(t, l.revoke(T0.plusSeconds(6)), 0));
        assertFalse(staleUpdated, "stale version");
        License now = tx.inTransaction(t -> store.findLicense(t, l.id())).orElseThrow();
        assertEquals(LicenseStatus.SUSPENDED, now.status());
        assertEquals(1, now.version());
    }

    @Test
    void concurrentSlotReservationNeverExceedsTheLimit() throws Exception {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("slots@example.com", 3);
        tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('s'));
            return null;
        });
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger won = new AtomicInteger();
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            Thread th = new Thread(() -> {
                try {
                    go.await();
                    if (tx.inTransaction(t -> store.reserveDeviceSlot(t, l.id(), T0))) {
                        won.incrementAndGet();
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
            });
            threads.add(th);
            th.start();
        }
        go.countDown();
        for (Thread th : threads) {
            th.join();
        }
        assertEquals(3, won.get());
        assertEquals(3, tx.inTransaction(t -> store.findLicense(t, l.id())).orElseThrow().activeDeviceCount());
    }

    @Test
    void noSlotIsGrantedForANonUsableLicense() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("n@example.com", 3);
        tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('n'));
            return null;
        });
        tx.inTransaction(t -> store.updateLicense(t, l.revoke(T0.plusSeconds(1)), 0));
        boolean granted = tx.inTransaction(t -> store.reserveDeviceSlot(t, l.id(), T0));
        assertFalse(granted);
    }

    @Test
    void auditIsReturnedNewestFirstWithCursorAndLicenseFilter() {
        TransactionRunner tx = new JdbcTransactionRunner(new Ds(url, user));
        License l = newLicense("au@example.com", 1);
        tx.inTransaction(t -> {
            store.insertLicense(t, l, hash('u'));
            for (int i = 1; i <= 5; i++) {
                store.appendAudit(t, AuditEvent.of(T0.plusSeconds(i), "admin:dev", AuditAction.LICENSE_SUSPENDED, i % 2 == 0 ? l.id() : null,
                        AuditOutcome.SUCCESS, "n=" + i));
            }
            return null;
        });
        List<AuditEvent> all = tx.inTransaction(t -> store.findAudit(t, null, null, 3));
        assertEquals(List.of("n=5", "n=4", "n=3"), all.stream().map(AuditEvent::detail).toList());
        List<AuditEvent> next = tx.inTransaction(t -> store.findAudit(t, null, all.get(2).id(), 10));
        assertEquals(List.of("n=2", "n=1"), next.stream().map(AuditEvent::detail).toList());
        assertEquals(2, tx.inTransaction(t -> store.findAudit(t, l.id(), null, 10)).size());
    }
}
