package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.crypto.ActivationCodes;
import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicensePolicy;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.store.IssuanceRecord;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import com.interviewassistant.licensing.store.TransactionRunner;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Manual issuance: an administrator who has verified payment OUTSIDE this system asks for a license. The activation code is
 * generated here, only its keyed hash is stored, and the raw code is returned exactly once in the result. A retry with the same
 * Idempotency-Key returns the same license WITHOUT the code (it cannot be recovered); revoke and reissue if the first response
 * was lost.
 */
public final class IssuanceService {

    private static final System.Logger LOG = System.getLogger(IssuanceService.class.getName());
    private static final Pattern KEY = Pattern.compile("[A-Za-z0-9_-]{16,128}");
    private static final Pattern PAYMENT_REF = Pattern.compile("[A-Za-z0-9 ._:/#-]{0,64}");

    /**
     * @param paymentVerified  the administrator's explicit confirmation that payment was verified outside the application
     * @param paymentReference a short, non-personal reference to the payment record (optional)
     */
    public record IssueCommand(String customerEmail, boolean paymentVerified, String paymentReference, LicensePolicy policy,
                               String idempotencyKey, Instant explicitExpiry) {
        /** No fixed end date: the term (if any) is the policy's {@code validityDays}, counted from activation. */
        public IssueCommand(String customerEmail, boolean paymentVerified, String paymentReference, LicensePolicy policy,
                            String idempotencyKey) {
            this(customerEmail, paymentVerified, paymentReference, policy, idempotencyKey, null);
        }
    }

    /** {@code activationCode} is null on a replay: it is shown once only. */
    public record IssueResult(License license, String activationCode, boolean replayed) {
        @Override
        public String toString() {
            return "IssueResult[license=" + license.id() + ", replayed=" + replayed + "]"; // never prints the code
        }
    }

    private final LicenseStore store;
    private final TransactionRunner tx;
    private final ActivationCodes codes;
    private final Clock clock;

    public IssuanceService(LicenseStore store, TransactionRunner tx, ActivationCodes codes, Clock clock) {
        this.store = store;
        this.tx = tx;
        this.codes = codes;
        this.clock = clock;
    }

    public IssueResult issue(AdminPrincipal admin, IssueCommand cmd) {
        admin.require(AdminScope.LICENSE_ISSUE);
        if (!cmd.paymentVerified()) {
            throw new LicensingException(ErrorCode.PAYMENT_NOT_CONFIRMED);
        }
        String email = Emails.normalize(cmd.customerEmail());
        if (cmd.idempotencyKey() == null || !KEY.matcher(cmd.idempotencyKey()).matches()) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "Idempotency-Key must be 16-128 characters of [A-Za-z0-9_-]");
        }
        Instant explicitExpiry = cmd.explicitExpiry();
        if (explicitExpiry != null) {
            if (cmd.policy().validityDays() != null) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, "choose either a duration or an end date, not both");
            }
            Instant checkedAt = clock.instant();
            if (!explicitExpiry.isAfter(checkedAt)) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, "the end date must be in the future");
            }
            if (explicitExpiry.isAfter(checkedAt.plus(Duration.ofDays(LicensePolicy.MAX_VALIDITY_DAYS)))) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED,
                        "the end date is more than " + LicensePolicy.MAX_VALIDITY_DAYS + " days away");
            }
            explicitExpiry = explicitExpiry.truncatedTo(java.time.temporal.ChronoUnit.SECONDS); // what the entitlement can carry
        }
        final Instant fixedEnd = explicitExpiry;
        String ref = cmd.paymentReference() == null ? "" : cmd.paymentReference().trim();
        if (!PAYMENT_REF.matcher(ref).matches()) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "paymentReference may use letters, digits and ' ._:/#-' (max 64)");
        }
        String keyHash = sha256(admin.id() + "\n" + cmd.idempotencyKey());
        String base = String.join("|", email, String.valueOf(cmd.policy().deviceLimit()),
                String.valueOf(cmd.policy().validityDays()), rightsKey(cmd.policy()),
                String.valueOf(cmd.policy().activationWindowDays()), ref);
        // Appended only when present, so the fingerprint of every request without a fixed end date is exactly what it always was.
        String fingerprint = sha256(fixedEnd == null ? base : base + "|end=" + fixedEnd.getEpochSecond());

        for (int attempt = 0; attempt < 2; attempt++) {
            String rawCode = codes.generate(); // fresh per attempt; only ever returned if THIS attempt commits
            try {
                return tx.inTransaction(t -> {
                    Instant now = clock.instant();
                    var existing = store.findIssuance(t, keyHash);
                    if (existing.isPresent()) {
                        IssuanceRecord rec = existing.get();
                        if (!rec.fingerprint().equals(fingerprint)) {
                            throw new LicensingException(ErrorCode.IDEMPOTENCY_KEY_REUSED);
                        }
                        License license = store.findLicense(t, rec.licenseId()).orElseThrow();
                        store.appendAudit(t, AuditEvent.of(now, admin.actor(), AuditAction.LICENSE_ISSUE_REPLAYED,
                                license.id(), AuditOutcome.SUCCESS, "replay of an earlier issuance; no code returned"));
                        return new IssueResult(license, null, true);
                    }
                    License license = License.issue(UUID.randomUUID(), email, cmd.policy(), now, fixedEnd);
                    store.insertLicense(t, license, codes.hash(rawCode));
                    store.insertIssuance(t, new IssuanceRecord(keyHash, fingerprint, license.id(), now));
                    store.appendAudit(t, AuditEvent.of(now, admin.actor(), AuditAction.LICENSE_ISSUED, license.id(),
                            AuditOutcome.SUCCESS, AuditEvent.detail(
                                    "paymentConfirmedByAdmin", "true",
                                    "paymentRef", ref.isEmpty() ? "-" : ref,
                                    "deviceLimit", String.valueOf(cmd.policy().deviceLimit()),
                                    "validityDays", String.valueOf(cmd.policy().validityDays()),
                                    "fixedEnd", fixedEnd == null ? "-" : fixedEnd.toString(),
                                    "rights", rightsKey(cmd.policy()),
                                    "activationWindowDays", String.valueOf(cmd.policy().activationWindowDays()),
                                    "customerRef", codes.reference("email", email).substring(0, 16))));
                    LOG.log(System.Logger.Level.INFO, "license issued id={0} by={1}", license.id(), admin.actor());
                    return new IssueResult(license, rawCode, false);
                });
            } catch (DuplicateRecordException race) {
                // A concurrent request with the same Idempotency-Key committed first; the next pass replays it.
            }
        }
        throw new LicensingException(ErrorCode.CONFLICT);
    }

    private static String rightsKey(LicensePolicy p) {
        return p.rights().stream().map(LicenseRight::name).sorted().collect(Collectors.joining(","));
    }

    private static String sha256(String s) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
