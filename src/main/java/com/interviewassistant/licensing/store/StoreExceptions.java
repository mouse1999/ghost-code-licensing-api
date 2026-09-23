package com.interviewassistant.licensing.store;

/** Exceptions raised by stores, kept free of any database-vendor type. */
public final class StoreExceptions {

    private StoreExceptions() {
    }

    /** A unique constraint rejected an insert (a concurrent request won). Callers roll back and re-read. */
    public static final class DuplicateRecordException extends RuntimeException {
        public DuplicateRecordException(String what) {
            super(what);
        }
    }

    /** Any other storage failure. The message never contains SQL parameters. */
    public static final class StoreFailureException extends RuntimeException {
        public StoreFailureException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /** An optimistic-lock or slot race was lost; the whole transaction should be retried. */
    public static final class ConcurrentUpdateException extends RuntimeException {
        public ConcurrentUpdateException(String what) {
            super(what);
        }
    }
}
