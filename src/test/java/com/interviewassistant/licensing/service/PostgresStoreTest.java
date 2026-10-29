package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.DeviceRegistration;
import com.interviewassistant.licensing.domain.DeviceStatus;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.service.Fixture.Device;
import com.interviewassistant.licensing.service.IssuanceService.IssueCommand;
import com.interviewassistant.licensing.store.LicenseCounts;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import org.junit.jupiter.api.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Phase 134: persistence behaviour of the REAL {@link com.interviewassistant.licensing.store.JdbcLicenseStore} and
 * {@link com.interviewassistant.licensing.store.JdbcTransactionRunner} on PostgreSQL. Each test returns at once unless the system
 * property {@code licensing.test.pgUrl} is set (see PgSupport), so a plain build is unaffected. Every Fixture gets its own database.
 */
class PostgresStoreTest {

    private static final String CLIENT = "203.0.113.9";

    private static boolean skip() {
        return !PgSupport.enabled();
    }

    /** A store whose named method throws, to prove a unit of work leaves nothing behind. */
    private static LicenseStore failing(LicenseStore real, String method) {
        return (LicenseStore) Proxy.newProxyInstance(LicenseStore.class.getClassLoader(), new Class<?>[] {LicenseStore.class}, (p, m, a) -> {
            if (m.getName().equals(method)) {
                throw new IllegalStateException("injected failure in " + method);
            }
            try {
                return m.invoke(real, a);
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
        });
    }

    private static int count(PgSupport.Db db, String table) {
        return Integer.parseInt(db.scalar("SELECT COUNT(*) FROM " + table));
    }

    @Test
    void aFailedIssuanceLeavesNoLicenseCredentialIdempotencyRecordOrAuditRow() {
        if (skip()) return;
        for (String failAt : List.of("appendAudit", "insertIssuance", "insertLicense")) {
            Fixture f = new Fixture();
            PgSupport.Db db = (PgSupport.Db) f.store;
            IssuanceService broken = new IssuanceService(failing(f.ls, failAt), f.tr, f.codes, f.clock);
            assertThrows(IllegalStateException.class, () -> broken.issue(f.fullAdmin, new IssueCommand("a@example.com", true, "ref",
                    new com.interviewassistant.licensing.domain.LicensePolicy(1, 30, Fixture.rights(com.interviewassistant.licensing.domain.LicenseRight.LIVE), 30),
                    UUID.randomUUID().toString())));
            for (String t : List.of("license", "activation_credential", "issuance_request", "audit_event")) {
                assertEquals(0, count(db, t), failAt + " failed, so " + t + " must be empty");
            }
        }
    }

    @Test
    void aSuccessfulIssuanceCommitsAllFourRecordsTogether() {
        if (skip()) return;
        Fixture f = new Fixture();
        PgSupport.Db db = (PgSupport.Db) f.store;
        var issued = f.issue("one@example.com", 1, 30);
        assertEquals(1, count(db, "license"));
        assertEquals(1, count(db, "activation_credential"));
        assertEquals(1, count(db, "issuance_request"));
        assertEquals(1, count(db, "audit_event"));
        String stored = db.scalar("SELECT code_hash FROM activation_credential");
        assertNotEquals(issued.activationCode(), stored, "only a keyed hash is stored");
        assertFalse(db.dumpEverythingStored().contains(issued.activationCode()), "the raw key is nowhere in the database");
    }

    @Test
    void storedAndEffectiveStatusAgreeWithTheDomainAtEveryPointInTime() {
        if (skip()) return;
        Fixture f = new Fixture();
        PgSupport.Db db = (PgSupport.Db) f.store;
        UUID pending = f.issue("pending@example.com", 1, 365).license().id();
        UUID lapsing = f.issue("lapsing@example.com", 1, 365).license().id();          // window passes unactivated
        UUID fixedFuture = f.issuance.issue(f.fullAdmin, new IssueCommand("fixed@example.com", true, "r",
                new com.interviewassistant.licensing.domain.LicensePolicy(1, null, Fixture.rights(com.interviewassistant.licensing.domain.LicenseRight.LIVE), 30),
                UUID.randomUUID().toString(), f.clock.instant().plus(Duration.ofDays(20)))).license().id();
        UUID active = activated(f, "active@example.com", 365);
        UUID shortTerm = activated(f, "short@example.com", 10);
        UUID suspended = activated(f, "susp@example.com", 365);
        f.admin.suspend(f.fullAdmin, suspended, "");
        UUID revoked = f.issue("rev@example.com", 1, 30).license().id();
        f.admin.revoke(f.fullAdmin, revoked, "");
        UUID storedExpired = activated(f, "stored@example.com", 5);
        UUID openEnded = activated(f, "open@example.com", 0);
        Set<UUID> all = Set.of(pending, lapsing, fixedFuture, active, shortTerm, suspended, revoked, storedExpired, openEnded);

        for (int days : new int[] {0, 7, 12, 25, 45, 400}) {
            f.clock.advance(Duration.ofDays(days == 0 ? 0 : days));
            if (days == 7) {
                f.admin.get(f.fullAdmin, storedExpired);   // reading does not store; validation would (covered in the service tests)
            }
            Instant now = f.clock.instant();
            Map<LicenseStatus, Set<UUID>> expected = new EnumMap<>(LicenseStatus.class);
            for (UUID id : all) {
                License l = db.license(id);
                expected.computeIfAbsent(l.effectiveStatus(now), k -> new HashSet<>()).add(id);
            }
            for (LicenseStatus s : LicenseStatus.values()) {
                Set<UUID> viaSql = new HashSet<>();
                f.tr.inTransaction(t -> f.ls.searchLicenses(t, now, null, s, 100, 0)).forEach(l -> viaSql.add(l.id()));
                assertEquals(expected.getOrDefault(s, Set.of()), viaSql, "search by effective " + s + " after +" + days + " days");
            }
            LicenseCounts c = f.tr.inTransaction(t -> f.ls.countLicenses(t, now));
            Set<UUID> none = Set.of();
            assertEquals(all.size(), c.total());
            assertEquals(expected.getOrDefault(LicenseStatus.PENDING, none).size(), c.pending(), "pending @+" + days);
            assertEquals(expected.getOrDefault(LicenseStatus.ACTIVE, none).size(), c.active(), "active @+" + days);
            assertEquals(expected.getOrDefault(LicenseStatus.EXPIRED, none).size(), c.expiredAfterActivation() + c.lapsedUnactivated(), "expired @+" + days);
            assertEquals(expected.getOrDefault(LicenseStatus.SUSPENDED, none).size(), c.suspended());
            assertEquals(expected.getOrDefault(LicenseStatus.REVOKED, none).size(), c.revoked());
            long lapsedExpected = expected.getOrDefault(LicenseStatus.EXPIRED, none).stream().filter(id -> db.license(id).activatedAt() == null).count();
            assertEquals(lapsedExpected, c.lapsedUnactivated(), "lapsed-unactivated split @+" + days);
        }
    }

    private static UUID activated(Fixture f, String email, int days) {
        var issued = days == 0 ? f.issue(email, 1, null) : f.issue(email, 1, days);
        Device d = f.newDevice();
        f.client.activate(f.activation(d, email, issued.activationCode(), CLIENT));
        return issued.license().id();
    }

    @Test
    void searchPagesAreStableCompleteAndEscapeUserText() {
        if (skip()) return;
        Fixture f = new Fixture();
        List<UUID> ids = new ArrayList<>();
        for (int i = 0; i < 23; i++) {
            ids.add(f.issue("user" + i + "@example.com", 1, 30).license().id());
            f.clock.advance(Duration.ofSeconds(1));
        }
        f.issue("100%_odd@example.com", 1, 30);
        f.issue("100xxodd@example.com", 1, 30);
        Set<UUID> seen = new HashSet<>();
        List<UUID> order = new ArrayList<>();
        for (int off = 0; off < 30; off += 10) {
            int o = off;
            for (License l : f.tr.inTransaction(t -> f.ls.searchLicenses(t, f.clock.instant(), "@example.com", null, 10, o))) {
                assertTrue(seen.add(l.id()), "no row appears on two pages");
                order.add(l.id());
            }
        }
        assertEquals(25, seen.size(), "every row appears exactly once across pages");
        assertEquals(1, f.tr.inTransaction(t -> f.ls.searchLicenses(t, f.clock.instant(), "100%_odd", null, 10, 0)).size(), "% and _ are literal");
        assertEquals(0, f.tr.inTransaction(t -> f.ls.searchLicenses(t, f.clock.instant(), "x'; DROP TABLE license; --", null, 10, 0)).size());
        assertEquals(25, ((PgSupport.Db) f.store).licenseCount(), "the table is intact");
    }

    @Test
    void auditRowsCannotBeChangedAndTheOtherConstraintsStillHold() {
        if (skip()) return;
        Fixture f = new Fixture();
        PgSupport.Db db = (PgSupport.Db) f.store;
        UUID id = f.issue("c@example.com", 1, 30).license().id();
        assertNotEquals("OK", db.tryExec("UPDATE audit_event SET detail = 'tampered'"), "audit UPDATE refused");
        assertNotEquals("OK", db.tryExec("DELETE FROM audit_event"), "audit DELETE refused");
        assertNotEquals("OK", db.tryExec("TRUNCATE audit_event"), "audit TRUNCATE refused");
        assertEquals(1, count(db, "audit_event"));
        assertEquals("23503", db.tryExec("INSERT INTO audit_event (occurred_at, actor, action, license_id, outcome, detail) VALUES (now(),'x','X','" + UUID.randomUUID() + "','SUCCESS','')"), "FK on audit.license_id");
        assertEquals("23514", db.tryExec("UPDATE license SET active_device_count = 5 WHERE id = '" + id + "'"), "device count cannot exceed the limit");
        assertEquals("23514", db.tryExec("UPDATE license SET status = 'GRANTED' WHERE id = '" + id + "'"), "status domain");
        assertEquals("23514", db.tryExec("UPDATE license SET status = 'ACTIVE' WHERE id = '" + id + "'"), "ACTIVE needs an activation time");

        // duplicates through the store
        Device d = f.newDevice();
        DeviceRegistration reg = new DeviceRegistration(UUID.randomUUID(), id, d.publicKey(), d.thumbprint(), null, "x", f.clock.instant(), DeviceStatus.ACTIVE, null);
        f.tr.inTransaction(t -> { f.ls.insertDevice(t, reg); return null; });
        DeviceRegistration dup = new DeviceRegistration(UUID.randomUUID(), id, d.publicKey(), d.thumbprint(), null, "x", f.clock.instant(), DeviceStatus.ACTIVE, null);
        assertThrows(DuplicateRecordException.class, () -> f.tr.inTransaction(t -> { f.ls.insertDevice(t, dup); return null; }));
        assertEquals(1, db.deviceCount(id), "the failed duplicate left nothing");
    }

    @Test
    void auditHistoryRoundTripsThroughTheStoreNewestFirstWithPaging() {
        if (skip()) return;
        Fixture f = new Fixture();
        UUID id = f.issue("h@example.com", 1, 30).license().id();
        f.admin.suspend(f.fullAdmin, id, "one");
        f.admin.reinstate(f.fullAdmin, id, "two");
        List<AuditEvent> page = f.tr.inTransaction(t -> f.ls.findAudit(t, id, null, 2));
        assertEquals(2, page.size());
        assertTrue(page.get(0).id() > page.get(1).id(), "newest first");
        List<AuditEvent> rest = f.tr.inTransaction(t -> f.ls.findAudit(t, id, page.get(1).id(), 10));
        assertEquals(1, rest.size());
        assertEquals("LICENSE_ISSUED", rest.get(0).action().name());
        assertTrue(f.tr.inTransaction(t -> f.ls.earliestAudit(t)).isPresent());
        var counts = f.tr.inTransaction(t -> f.ls.countAuditSince(t, f.clock.instant().minus(Duration.ofDays(1))));
        assertEquals(Long.valueOf(1L), counts.get("LICENSE_ISSUED/SUCCESS"));
    }

    @Test
    void earliestAuditOnAnEmptyDatabaseIsEmptyNotAnError() {
        if (skip()) return;
        Fixture f = new Fixture();
        assertTrue(f.tr.inTransaction(t -> f.ls.earliestAudit(t)).isEmpty());
        assertEquals(0, f.tr.inTransaction(t -> f.ls.countLicenses(t, f.clock.instant())).total());
        assertTrue(f.tr.inTransaction(t -> f.ls.countAuditSince(t, Instant.EPOCH)).isEmpty());
    }
}
