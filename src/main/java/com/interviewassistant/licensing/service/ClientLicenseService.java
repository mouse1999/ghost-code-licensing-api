package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.crypto.ActivationCodes;
import com.interviewassistant.licensing.crypto.DeviceKeys;
import com.interviewassistant.licensing.crypto.EntitlementTokens;
import com.interviewassistant.licensing.crypto.SigningKeyRing;
import com.interviewassistant.licensing.domain.AuditAction;
import com.interviewassistant.licensing.domain.AuditEvent;
import com.interviewassistant.licensing.domain.AuditOutcome;
import com.interviewassistant.licensing.domain.DeviceRegistration;
import com.interviewassistant.licensing.domain.DeviceStatus;
import com.interviewassistant.licensing.domain.Entitlement;
import com.interviewassistant.licensing.domain.License;
import com.interviewassistant.licensing.domain.LicenseRight;
import com.interviewassistant.licensing.domain.LicenseStatus;
import com.interviewassistant.licensing.security.NonceCache;
import com.interviewassistant.licensing.security.RateLimiter;
import com.interviewassistant.licensing.store.LicenseStore;
import com.interviewassistant.licensing.store.StoreExceptions.ConcurrentUpdateException;
import com.interviewassistant.licensing.store.StoreExceptions.DuplicateRecordException;
import com.interviewassistant.licensing.store.Tx;
import com.interviewassistant.licensing.store.TransactionRunner;

import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Customer / desktop-client operations: activate, validate and fetch/renew a signed entitlement.
 *
 * <h3>Who is believed</h3>
 * Nothing the client states about itself is trusted. Activation needs the email AND the activation code (knowledge) plus a
 * signature made with the device private key over a fresh timestamp and nonce (possession). Validation and renewal need the
 * same possession proof against the key registered at activation. License status, rights, limits and expiry come only from the
 * database.
 *
 * <h3>What is revealed</h3>
 * An unknown email, a wrong code, an unknown device and a bad signature all produce the same {@link ErrorCode#INVALID_CREDENTIALS}.
 * Only a caller who has proved the right to ask (correct email+code, or a verified device signature) is told the license is
 * suspended, revoked or expired, or that the device limit is reached.
 *
 * <h3>Atomicity</h3>
 * Each operation is one database transaction. Binding a device takes a slot with a single conditional UPDATE and the limit is
 * also a CHECK constraint, so concurrent activations can never exceed it. Outcomes (including failures that must be audited
 * or that bring a stored status up to date) are returned from the transaction rather than thrown, so they commit.
 */
public final class ClientLicenseService {

    private static final System.Logger LOG = System.getLogger(ClientLicenseService.class.getName());
    private static final Pattern NONCE = Pattern.compile("[A-Za-z0-9_-]{16,64}");
    private static final int MAX_ATTEMPTS = 3;

    public record ActivateCommand(String email, String activationCode, String devicePublicKey, long proofTimestamp,
                                  String proofNonce, String proofSignature, String deviceLabel,
                                  String supplementaryFingerprint, String clientKey) {
        @Override
        public String toString() {
            return "ActivateCommand[redacted]"; // the activation code must never reach a log line
        }
    }

    public record DeviceRequest(UUID licenseId, UUID deviceRegistrationId, long proofTimestamp, String proofNonce,
                                String proofSignature, String clientKey) {
    }

    public record ActivationResult(UUID licenseId, UUID deviceRegistrationId, LicenseStatus status, Set<LicenseRight> rights,
                                   Instant licenseExpiresAt, String entitlement, Instant entitlementExpiresAt,
                                   Instant renewAfter, boolean alreadyRegistered) {
    }

    public record ValidationResult(UUID licenseId, UUID deviceRegistrationId, LicenseStatus status, Set<LicenseRight> rights,
                                   Instant licenseExpiresAt, Instant serverTime) {
    }

    public record EntitlementResult(UUID licenseId, UUID deviceRegistrationId, Set<LicenseRight> rights, Instant licenseExpiresAt,
                                    String entitlement, Instant entitlementExpiresAt, Instant renewAfter) {
    }

    /** What a transaction decided: a value to return, or an error code to throw after the transaction has committed. */
    private record Outcome<T>(T value, ErrorCode failure) {
        static <T> Outcome<T> ok(T v) {
            return new Outcome<>(v, null);
        }

        static <T> Outcome<T> fail(ErrorCode c) {
            return new Outcome<>(null, c);
        }
    }

    private final LicenseStore store;
    private final TransactionRunner tx;
    private final ActivationCodes codes;
    private final SigningKeyRing keys;
    private final ServiceSettings settings;
    private final RateLimiter activationPerClient;
    private final RateLimiter activationFailures;
    private final RateLimiter validationPerClient;
    private final NonceCache nonces;
    private final Clock clock;

    public ClientLicenseService(LicenseStore store, TransactionRunner tx, ActivationCodes codes, SigningKeyRing keys,
                                ServiceSettings settings, RateLimiter activationPerClient, RateLimiter activationFailures,
                                RateLimiter validationPerClient, NonceCache nonces, Clock clock) {
        this.store = store;
        this.tx = tx;
        this.codes = codes;
        this.keys = keys;
        this.settings = settings;
        this.activationPerClient = activationPerClient;
        this.activationFailures = activationFailures;
        this.validationPerClient = validationPerClient;
        this.nonces = nonces;
        this.clock = clock;
    }

    // =================================================================== activate

    public ActivationResult activate(ActivateCommand cmd) {
        throttle(activationPerClient, cmd.clientKey());
        String email = Emails.normalize(cmd.email());
        String code;
        try {
            code = ActivationCodes.normalize(cmd.activationCode());
        } catch (IllegalArgumentException e) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "activation code is not in the expected format");
        }
        String subject = cmd.clientKey() + "|" + codes.reference("email", email);
        if (activationFailures.isExhausted(subject)) {
            throw new LicensingException(ErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED.defaultMessage(),
                    activationFailures.retryAfterSeconds(subject));
        }
        PublicKey devicePublicKey = parseKey(cmd.devicePublicKey());
        String thumbprint = DeviceKeys.thumbprint(cmd.devicePublicKey());
        requireFreshProof(cmd.proofTimestamp(), cmd.proofNonce());
        requireProofSignature(devicePublicKey, DeviceKeys.activateMessage(email, thumbprint, cmd.proofTimestamp(), cmd.proofNonce()),
                cmd.proofSignature(), ErrorCode.INVALID_DEVICE_PROOF);
        requireUnusedNonce("activate|" + thumbprint + "|" + cmd.proofNonce());
        String label = shortText(cmd.deviceLabel(), 64, "deviceLabel");
        String fingerprintRef = cmd.supplementaryFingerprint() == null || cmd.supplementaryFingerprint().isBlank() ? null
                : codes.reference("fingerprint", shortText(cmd.supplementaryFingerprint(), 256, "supplementaryFingerprint"));
        String codeHash = codes.hash(code);
        String emailRef = codes.reference("email", email).substring(0, 16);
        String actor = "device-key:" + thumbprint.substring(0, 16);

        Outcome<ActivationResult> outcome = retrying(() -> tx.inTransaction(t ->
                activateInTx(t, email, codeHash, emailRef, actor, cmd.devicePublicKey(), thumbprint, label, fingerprintRef)));
        if (outcome.failure() != null) {
            if (outcome.failure() == ErrorCode.INVALID_CREDENTIALS) {
                activationFailures.record(subject);
            }
            throw new LicensingException(outcome.failure());
        }
        return outcome.value();
    }

    private Outcome<ActivationResult> activateInTx(Tx t, String email, String codeHash, String emailRef, String actor,
                                                   String publicKey, String thumbprint, String label, String fingerprintRef) {
        Instant now = clock.instant();
        Optional<License> found = store.findByEmailAndCodeHash(t, email, codeHash);
        if (found.isEmpty()) {
            audit(t, now, actor, AuditAction.ACTIVATION, null, AuditOutcome.FAILURE, "reason=invalid_credentials; customerRef=" + emailRef);
            return Outcome.fail(ErrorCode.INVALID_CREDENTIALS);
        }
        License license = found.get();
        ErrorCode blocked = blockingState(t, license, now, actor, AuditAction.ACTIVATION);
        if (blocked != null) {
            return Outcome.fail(blocked);
        }
        Optional<DeviceRegistration> existing = store.findDeviceByThumbprint(t, license.id(), thumbprint);
        if (existing.isPresent()) {
            return existing.get().isActive() ? repeatActivation(t, license, existing.get(), now, actor)
                    : Outcome.fail(ErrorCode.DEVICE_NOT_REGISTERED);
        }
        boolean transitioned = false;
        if (license.status() == LicenseStatus.PENDING) {
            License activated = license.activate(now);
            if (!store.updateLicense(t, activated, license.version())) {
                throw new ConcurrentUpdateException("license changed during activation");
            }
            license = activated;
            transitioned = true;
        }
        if (!store.reserveDeviceSlot(t, license.id(), now)) {
            Optional<DeviceRegistration> raced = store.findDeviceByThumbprint(t, license.id(), thumbprint);
            if (raced.isPresent() && raced.get().isActive()) {
                return repeatActivation(t, license, raced.get(), now, actor); // same device retried concurrently
            }
            if (transitioned) {
                throw new ConcurrentUpdateException("device slot unavailable after activation; retrying");
            }
            audit(t, now, actor, AuditAction.ACTIVATION, license.id(), AuditOutcome.FAILURE, "reason=device_limit_reached");
            return Outcome.fail(ErrorCode.DEVICE_LIMIT_REACHED);
        }
        DeviceRegistration device = new DeviceRegistration(UUID.randomUUID(), license.id(), publicKey, thumbprint,
                fingerprintRef, label, now, DeviceStatus.ACTIVE, null);
        store.insertDevice(t, device); // a duplicate here rolls back (slot released) and the retry sees the existing row
        audit(t, now, actor, AuditAction.DEVICE_BOUND, license.id(), AuditOutcome.SUCCESS,
                AuditEvent.detail("device", device.id().toString(), "keyThumbprint", thumbprint.substring(0, 16)));
        audit(t, now, actor, AuditAction.ACTIVATION, license.id(), AuditOutcome.SUCCESS, "reason=activated");
        return Outcome.ok(activationResult(t, license, device, now, actor, false));
    }

    private Outcome<ActivationResult> repeatActivation(Tx t, License license, DeviceRegistration device, Instant now, String actor) {
        audit(t, now, actor, AuditAction.ACTIVATION, license.id(), AuditOutcome.SUCCESS, "reason=already_registered");
        return Outcome.ok(activationResult(t, license, device, now, actor, true));
    }

    private ActivationResult activationResult(Tx t, License license, DeviceRegistration device, Instant now, String actor,
                                              boolean already) {
        Entitlement e = entitlementFor(license, device, now);
        String token = EntitlementTokens.sign(keys, e);
        audit(t, now, actor, AuditAction.ENTITLEMENT_ISSUED, license.id(), AuditOutcome.SUCCESS,
                AuditEvent.detail("entitlementId", e.entitlementId().toString(), "via", "activation"));
        return new ActivationResult(license.id(), device.id(), LicenseStatus.ACTIVE, license.policy().rights(), license.expiresAt(),
                token, e.expiresAt(), e.renewAfter(), already);
    }

    // =================================================================== validate / entitlement

    public ValidationResult validate(DeviceRequest req) {
        return deviceOperation("validate", req, (license, device, now, t) ->
                new ValidationResult(license.id(), device.id(), LicenseStatus.ACTIVE, license.policy().rights(),
                        license.expiresAt(), now));
    }

    public EntitlementResult entitlement(DeviceRequest req) {
        return deviceOperation("entitlement", req, (license, device, now, t) -> {
            Entitlement e = entitlementFor(license, device, now);
            String token = EntitlementTokens.sign(keys, e);
            audit(t, now, "device:" + device.id(), AuditAction.ENTITLEMENT_ISSUED, license.id(), AuditOutcome.SUCCESS,
                    AuditEvent.detail("entitlementId", e.entitlementId().toString(), "via", "renewal"));
            return new EntitlementResult(license.id(), device.id(), license.policy().rights(), license.expiresAt(), token,
                    e.expiresAt(), e.renewAfter());
        });
    }

    @FunctionalInterface
    private interface OnSuccess<T> {
        T apply(License license, DeviceRegistration device, Instant now, Tx tx);
    }

    private <T> T deviceOperation(String operation, DeviceRequest req, OnSuccess<T> onSuccess) {
        throttle(validationPerClient, req.clientKey());
        if (req.licenseId() == null || req.deviceRegistrationId() == null) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "licenseId and deviceRegistrationId are required");
        }
        requireFreshProof(req.proofTimestamp(), req.proofNonce());

        boolean[] nonceUsed = {false}; // survives a transaction retry, so a retry is not mistaken for a replay
        Outcome<T> outcome = retrying(() -> tx.inTransaction(t -> {
            Instant now = clock.instant();
            Optional<DeviceRegistration> found = store.findDevice(t, req.deviceRegistrationId());
            if (found.isEmpty() || !found.get().licenseId().equals(req.licenseId())) {
                return Outcome.<T>fail(ErrorCode.INVALID_CREDENTIALS);
            }
            DeviceRegistration device = found.get();
            PublicKey key = DeviceKeys.parsePublicKey(device.publicKey());
            String message = DeviceKeys.operationMessage(operation, req.licenseId().toString(),
                    req.deviceRegistrationId().toString(), req.proofTimestamp(), req.proofNonce());
            if (!DeviceKeys.verify(key, message, req.proofSignature())) {
                return Outcome.<T>fail(ErrorCode.INVALID_CREDENTIALS);
            }
            // Only a verified signature may consume a nonce, so an unauthenticated caller cannot burn legitimate ones.
            if (!nonceUsed[0]) {
                if (!nonces.register(operation + "|" + device.id() + "|" + req.proofNonce())) {
                    return Outcome.<T>fail(ErrorCode.INVALID_DEVICE_PROOF);
                }
                nonceUsed[0] = true;
            }
            License license = store.findLicense(t, device.licenseId()).orElseThrow();
            String actor = "device:" + device.id();
            if (!device.isActive()) {
                audit(t, now, actor, AuditAction.VALIDATION_REJECTED, license.id(), AuditOutcome.FAILURE, "reason=device_not_registered");
                return Outcome.<T>fail(ErrorCode.DEVICE_NOT_REGISTERED);
            }
            ErrorCode blocked = blockingState(t, license, now, actor, AuditAction.VALIDATION_REJECTED);
            if (blocked != null) {
                return Outcome.<T>fail(blocked);
            }
            if (license.status() != LicenseStatus.ACTIVE) {
                audit(t, now, actor, AuditAction.VALIDATION_REJECTED, license.id(), AuditOutcome.FAILURE, "reason=pending");
                return Outcome.<T>fail(ErrorCode.LICENSE_PENDING);
            }
            return Outcome.ok(onSuccess.apply(license, device, now, t));
        }));
        if (outcome.failure() != null) {
            throw new LicensingException(outcome.failure());
        }
        return outcome.value();
    }

    // =================================================================== shared pieces

    /**
     * Returns the error to report for a SUSPENDED/REVOKED/EXPIRED license (auditing it, and bringing a lapsed stored status up
     * to date in the same transaction), or null if the license may proceed.
     */
    private ErrorCode blockingState(Tx t, License license, Instant now, String actor, AuditAction action) {
        LicenseStatus effective = license.effectiveStatus(now);
        ErrorCode code = switch (effective) {
            case SUSPENDED -> ErrorCode.LICENSE_SUSPENDED;
            case REVOKED -> ErrorCode.LICENSE_REVOKED;
            case EXPIRED -> ErrorCode.LICENSE_EXPIRED;
            default -> null;
        };
        if (code == null) {
            return null;
        }
        if (effective == LicenseStatus.EXPIRED && license.status() != LicenseStatus.EXPIRED) {
            License expired = license.expire(now);
            if (!store.updateLicense(t, expired, license.version())) {
                throw new ConcurrentUpdateException("license changed while expiring");
            }
            audit(t, now, "system", AuditAction.LICENSE_EXPIRED, license.id(), AuditOutcome.SUCCESS, "reason=time_limit_reached");
        }
        audit(t, now, actor, action, license.id(), AuditOutcome.FAILURE, "reason=" + effective.name().toLowerCase());
        return code;
    }

    private Entitlement entitlementFor(License license, DeviceRegistration device, Instant now) {
        Instant iat = now.truncatedTo(java.time.temporal.ChronoUnit.SECONDS); // tokens carry whole seconds
        Instant exp = iat.plus(settings.entitlementTtl());
        Instant licenseEnd = license.expiresAt() == null ? null : license.expiresAt().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        if (licenseEnd != null && licenseEnd.isBefore(exp)) {
            exp = licenseEnd;
        }
        if (!exp.isAfter(iat)) {
            exp = iat.plusSeconds(1);
        }
        Instant renew = iat.plus(Duration.between(iat, exp).dividedBy(2));
        return new Entitlement(Entitlement.CURRENT_VERSION, UUID.randomUUID(), license.id(), device.id(), device.keyThumbprint(),
                license.policy().rights(), iat, exp, renew, licenseEnd, settings.issuer());
    }

    private void audit(Tx t, Instant now, String actor, AuditAction action, UUID licenseId, AuditOutcome outcome, String detail) {
        store.appendAudit(t, AuditEvent.of(now, actor, action, licenseId, outcome, detail));
    }

    private void throttle(RateLimiter limiter, String clientKey) {
        if (!limiter.tryAcquire(clientKey)) {
            LOG.log(System.Logger.Level.WARNING, "rate limit hit");
            throw new LicensingException(ErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED.defaultMessage(),
                    limiter.retryAfterSeconds(clientKey));
        }
    }

    private void requireFreshProof(long timestamp, String nonce) {
        if (nonce == null || !NONCE.matcher(nonce).matches()) {
            throw new LicensingException(ErrorCode.INVALID_DEVICE_PROOF, "proofNonce must be 16-64 characters of [A-Za-z0-9_-]");
        }
        long skew = Math.abs(clock.instant().getEpochSecond() - timestamp);
        if (skew > settings.proofMaxSkew().toSeconds()) {
            throw new LicensingException(ErrorCode.INVALID_DEVICE_PROOF, "proof timestamp is outside the allowed clock skew");
        }
    }

    private void requireProofSignature(PublicKey key, String message, String signature, ErrorCode onFailure) {
        if (signature == null || !DeviceKeys.verify(key, message, signature)) {
            throw new LicensingException(onFailure);
        }
    }

    private void requireUnusedNonce(String key) {
        if (!nonces.register(key)) {
            throw new LicensingException(ErrorCode.INVALID_DEVICE_PROOF);
        }
    }

    private static PublicKey parseKey(String base64url) {
        try {
            return DeviceKeys.parsePublicKey(base64url);
        } catch (IllegalArgumentException e) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, "devicePublicKey must be a base64url Ed25519 SubjectPublicKeyInfo");
        }
    }

    private static String shortText(String value, int max, String field) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.length() > max) {
            throw new LicensingException(ErrorCode.VALIDATION_FAILED, field + " is too long");
        }
        for (int i = 0; i < v.length(); i++) {
            if (Character.isISOControl(v.charAt(i))) {
                throw new LicensingException(ErrorCode.VALIDATION_FAILED, field + " contains control characters");
            }
        }
        return v.isEmpty() ? null : v;
    }

    /** Re-runs a whole transaction when a concurrent request won a race (version, slot or unique-key conflict). */
    private <T> Outcome<T> retrying(java.util.function.Supplier<Outcome<T>> work) {
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return work.get();
            } catch (ConcurrentUpdateException | DuplicateRecordException race) {
                if (attempt == MAX_ATTEMPTS) {
                    throw new LicensingException(ErrorCode.CONFLICT);
                }
            }
        }
        throw new LicensingException(ErrorCode.CONFLICT);
    }
}
