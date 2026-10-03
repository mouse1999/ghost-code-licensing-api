package com.interviewassistant.licensing.service;

/** A business or protocol failure that maps to a documented {@link ErrorCode}. Messages must never contain secrets. */
public class LicensingException extends RuntimeException {

    private final ErrorCode code;
    private final long retryAfterSeconds;

    public LicensingException(ErrorCode code) {
        this(code, code.defaultMessage(), 0);
    }

    public LicensingException(ErrorCode code, String message) {
        this(code, message, 0);
    }

    public LicensingException(ErrorCode code, String message, long retryAfterSeconds) {
        super(message);
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public ErrorCode code() {
        return code;
    }

    /** Seconds the client should wait (for {@link ErrorCode#RATE_LIMITED}), else 0. */
    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
