package com.interviewassistant.licensing.store;

import java.util.function.Function;

/**
 * Runs a unit of work in one database transaction: commit if it returns, roll back if it throws. Services that must change a
 * license, a device binding and the audit trail together do all three inside one call.
 */
public interface TransactionRunner {
    <T> T inTransaction(Function<Tx, T> work);
}
