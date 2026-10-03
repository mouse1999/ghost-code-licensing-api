package com.interviewassistant.licensing.service;

/**
 * Stable, documented error codes with their HTTP status. Messages are deliberately generic where revealing more would let a
 * caller probe for accounts or codes (see {@link #INVALID_CREDENTIALS}).
 */
public enum ErrorCode {
    VALIDATION_FAILED(400, "The request is not valid."),
    INVALID_DEVICE_PROOF(400, "The device proof is missing, stale, replayed or does not verify."),
    PAYMENT_NOT_CONFIRMED(400, "Payment must be confirmed by the administrator before a license is issued."),
    UNAUTHENTICATED(401, "Authentication is required."),
    /** One answer for unknown email, wrong code, unknown device and bad signature: it never says which. */
    INVALID_CREDENTIALS(401, "The email and activation code, or the device credentials, were not accepted."),
    FORBIDDEN(403, "This credential is not permitted to do that."),
    LICENSE_SUSPENDED(403, "This license is suspended."),
    LICENSE_REVOKED(403, "This license has been revoked."),
    LICENSE_EXPIRED(403, "This license has expired."),
    DEVICE_NOT_REGISTERED(403, "This device is no longer registered for the license."),
    LICENSE_NOT_FOUND(404, "No such license."),
    LICENSE_PENDING(409, "This license has not been activated yet."),
    DEVICE_LIMIT_REACHED(409, "This license is already activated on another device and its device limit has been reached."),
    ILLEGAL_TRANSITION(409, "The license is not in a state that allows this change."),
    IDEMPOTENCY_KEY_REUSED(409, "That Idempotency-Key was already used for a different request."),
    CONFLICT(409, "The license was changed by another request; please retry."),
    PAYLOAD_TOO_LARGE(413, "The request body is too large."),
    RATE_LIMITED(429, "Too many requests; please try again later."),
    HTTPS_REQUIRED(403, "This API must be called over HTTPS."),
    INTERNAL_ERROR(500, "An unexpected error occurred.");

    private final int httpStatus;
    private final String defaultMessage;

    ErrorCode(int httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
