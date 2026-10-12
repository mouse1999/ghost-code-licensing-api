package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.DeviceRegistration;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.store.IssuanceRecord;
import com.interviewassistant.licensing.store.LicenseCounts;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import com.interviewassistant.licensing.store.TransactionRunner;
import com.interviewassistant.licensing.store.Tx;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

/**
 * TEST-ONLY store used to test the SERVICE logic without a database driver. Each operation is atomic (one lock) and a failed
 * transaction is undone, mirroring what the database does; transactions themselves are NOT serialised, so concurrent
 * services genuinely race on versions and slots. It proves the service logic, not the SQL: the SQL's concurrency behaviour is
 * tested against real PostgreSQL by src/test/db/postgres-db-tests.sh and by JdbcLicenseStoreIT.
 */
final class InMemoryLicenseStore implements LicenseStore, TransactionRunner, Inspect {

    private final Object lock = new Object();
    private final Map<UUID, License> licenses = new HashMap<>();
    private final Map<String, UUID> codeHashes = new HashMap<>();
    private final Map<UUID, DeviceRegistration> devices = new HashMap<>();
    private final Map<String, IssuanceRecord> issuances = new HashMap<>();
    private final List<AuditEvent> audit = new ArrayList<>();
    private long auditSeq = 0;

    private static final class MemTx implements Tx {
        final Deque<Runnable> undo = new ArrayDeque<>();
        final List<java.util.concurrent.locks.ReentrantLock> held = new ArrayList<>();
    }

    /** Row locks, as a real database takes on UPDATE: held until the transaction commits or rolls back. */
    private final Map<UUID, java.util.concurrent.locks.ReentrantLock> rowLocks = new java.util.concurrent.ConcurrentHashMap<>();

    private void lockRow(Tx tx, UUID id) {
        java.util.concurrent.locks.ReentrantLock l = rowLocks.computeIfAbsent(id, k -> new java.util.concurrent.locks.ReentrantLock());
        if (!l.isHeldByCurrentThread()) {
            l.lock(); // blocks while another open transaction has written this row
            ((MemTx) tx).held.add(l);
        }
    }

    @Override
    public <T> T inTransaction(Function<Tx, T> work) {
        MemTx t = new MemTx();
        try {
            return work.apply(t);
        } catch (RuntimeException | Error e) {
            synchronized (lock) {
                while (!t.undo.isEmpty()) {
                    t.undo.pop().run();
                }
            }
            throw e;
        } finally {
            t.held.forEach(java.util.concurrent.locks.ReentrantLock::unlock);
        }
    }

    @Override
    public Optional<License> findLicense(Tx tx, UUID id) {
        synchronized (lock) {
            return Optional.ofNullable(licenses.get(id));
        }
    }

    @Override
    public List<License> findLicensesByEmail(Tx tx, String email) {
        synchronized (lock) {
            return licenses.values().stream().filter(l -> l.customerEmail().equals(email)).toList();
        }
    }

    @Override
    public Optional<License> findByEmailAndCodeHash(Tx tx, String email, String codeHash) {
        synchronized (lock) {
            UUID id = codeHashes.get(codeHash);
            return id == null ? Optional.empty() : Optional.ofNullable(licenses.get(id)).filter(l -> l.customerEmail().equals(email));
        }
    }

    @Override
    public void insertLicense(Tx tx, License license, String codeHash) {
        synchronized (lock) {
            if (licenses.containsKey(license.id()) || codeHashes.containsKey(codeHash)) {
                throw new DuplicateRecordException("license");
            }
            licenses.put(license.id(), license);
            codeHashes.put(codeHash, license.id());
            ((MemTx) tx).undo.push(() -> {
                licenses.remove(license.id());
                codeHashes.remove(codeHash);
            });
        }
    }

    @Override
    public boolean updateLicense(Tx tx, License u, long expectedVersion) {
        lockRow(tx, u.id());
        synchronized (lock) {
            License cur = licenses.get(u.id());
            if (cur == null || cur.version() != expectedVersion) {
                return false;
            }
            License next = new License(u.id(), u.customerEmail(), u.status(), u.policy(), u.createdAt(), u.activationDeadline(),
                    u.activatedAt(), u.expiresAt(), u.suspendedAt(), u.revokedAt(), u.updatedAt(), cur.activeDeviceCount(),
                    expectedVersion + 1);
            licenses.put(u.id(), next);
            ((MemTx) tx).undo.push(() -> licenses.put(u.id(), cur));
            return true;
        }
    }

    @Override
    public boolean reserveDeviceSlot(Tx tx, UUID id, Instant now) {
        lockRow(tx, id);
        synchronized (lock) {
            License cur = licenses.get(id);
            if (cur == null || (cur.status() != LicenseStatus.PENDING && cur.status() != LicenseStatus.ACTIVE)
                    || cur.activeDeviceCount() >= cur.policy().deviceLimit()) {
                return false;
            }
            licenses.put(id, new License(cur.id(), cur.customerEmail(), cur.status(), cur.policy(), cur.createdAt(),
                    cur.activationDeadline(), cur.activatedAt(), cur.expiresAt(), cur.suspendedAt(), cur.revokedAt(), now,
                    cur.activeDeviceCount() + 1, cur.version() + 1));
            ((MemTx) tx).undo.push(() -> licenses.put(id, cur));
            return true;
        }
    }

    @Override
    public Optional<DeviceRegistration> findDevice(Tx tx, UUID id) {
        synchronized (lock) {
            return Optional.ofNullable(devices.get(id));
        }
    }

    @Override
    public Optional<DeviceRegistration> findDeviceByThumbprint(Tx tx, UUID licenseId, String thumbprint) {
        synchronized (lock) {
            return devices.values().stream()
                    .filter(d -> d.licenseId().equals(licenseId) && d.keyThumbprint().equals(thumbprint)).findFirst();
        }
    }

    @Override
    public void insertDevice(Tx tx, DeviceRegistration d) {
        synchronized (lock) {
            boolean dup = devices.values().stream()
                    .anyMatch(x -> x.licenseId().equals(d.licenseId()) && x.keyThumbprint().equals(d.keyThumbprint()));
            if (dup) {
                throw new DuplicateRecordException("device");
            }
            devices.put(d.id(), d);
            ((MemTx) tx).undo.push(() -> devices.remove(d.id()));
        }
    }

    @Override
    public Optional<IssuanceRecord> findIssuance(Tx tx, String keyHash) {
        synchronized (lock) {
            return Optional.ofNullable(issuances.get(keyHash));
        }
    }

    @Override
    public void insertIssuance(Tx tx, IssuanceRecord r) {
        synchronized (lock) {
            if (issuances.putIfAbsent(r.keyHash(), r) != null) {
                throw new DuplicateRecordException("issuance");
            }
            ((MemTx) tx).undo.push(() -> issuances.remove(r.keyHash()));
        }
    }

    @Override
    public long appendAudit(Tx tx, AuditEvent e) {
        synchronized (lock) {
            long id = ++auditSeq;
            AuditEvent stored = new AuditEvent(id, e.occurredAt(), e.actor(), e.action(), e.licenseId(), e.outcome(), e.detail());
            audit.add(stored);
            ((MemTx) tx).undo.push(() -> audit.remove(stored));
            return id;
        }
    }

    @Override
    public List<AuditEvent> findAudit(Tx tx, UUID licenseId, Long beforeId, int limit) {
        synchronized (lock) {
            return audit.stream()
                    .filter(a -> licenseId == null || licenseId.equals(a.licenseId()))
                    .filter(a -> beforeId == null || a.id() < beforeId)
                    .sorted((a, b) -> Long.compare(b.id(), a.id()))
                    .limit(limit).toList();
        }
    }

    // ------------------------------------------------------------ test inspection helpers

    @Override
    public List<License> searchLicenses(Tx tx, Instant now, String emailContains, LicenseStatus effective, int limit, int offset) {
        synchronized (lock) {
            return licenses.values().stream()
                    .filter(l -> emailContains == null || l.customerEmail().contains(emailContains))   // a literal fragment, as in SQL
                    .filter(l -> effective == null || l.effectiveStatus(now) == effective)
                    .sorted(java.util.Comparator.comparing(License::createdAt).reversed().thenComparing(License::id))
                    .skip(offset).limit(limit).toList();
        }
    }

    @Override
    public LicenseCounts countLicenses(Tx tx, Instant now) {
        synchronized (lock) {
            long pending = 0, active = 0, expiredAfter = 0, lapsed = 0, suspended = 0, revoked = 0;
            for (License l : licenses.values()) {
                switch (l.effectiveStatus(now)) {
                    case PENDING -> pending++;
                    case ACTIVE -> active++;
                    case EXPIRED -> {
                        if (l.activatedAt() != null) {
                            expiredAfter++;
                        } else {
                            lapsed++;
                        }
                    }
                    case SUSPENDED -> suspended++;
                    case REVOKED -> revoked++;
                }
            }
            return new LicenseCounts(licenses.size(), pending, active, expiredAfter, lapsed, suspended, revoked);
        }
    }

    @Override
    public Map<String, Long> countAuditSince(Tx tx, Instant since) {
        synchronized (lock) {
            Map<String, Long> out = new java.util.TreeMap<>();
            for (AuditEvent a : audit) {
                if (!a.occurredAt().isBefore(since)) {
                    out.merge(a.action().name() + "/" + a.outcome().name(), 1L, Long::sum);
                }
            }
            return out;
        }
    }

    @Override
    public Optional<Instant> earliestAudit(Tx tx) {
        synchronized (lock) {
            return audit.stream().map(AuditEvent::occurredAt).min(Instant::compareTo);
        }
    }

    @Override
    public List<AuditEvent> allAudit() {
        synchronized (lock) {
            return List.copyOf(audit);
        }
    }

    @Override
    public int licenseCount() {
        synchronized (lock) {
            return licenses.size();
        }
    }

    @Override
    public int countByEmail(String email) {
        return findLicensesByEmail(null, email).size();
    }

    @Override
    public int deviceCount(UUID licenseId) {
        synchronized (lock) {
            return (int) devices.values().stream().filter(d -> d.licenseId().equals(licenseId)).count();
        }
    }

    @Override
    public License license(UUID id) {
        synchronized (lock) {
            return licenses.get(id);
        }
    }

    /** Everything that is persisted, as one string, so tests can assert a secret appears nowhere. */
    @Override
    public String dumpEverythingStored() {
        synchronized (lock) {
            return licenses + "\n" + codeHashes + "\n" + devices + "\n" + issuances + "\n" + audit;
        }
    }
}
