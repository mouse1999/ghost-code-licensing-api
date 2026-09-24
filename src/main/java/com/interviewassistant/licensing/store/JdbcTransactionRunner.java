package com.interviewassistant.licensing.store;

import com.interviewassistant.licensing.store.StoreExceptions.StoreFailureException;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.function.Function;

/**
 * One JDBC connection per unit of work, READ COMMITTED, explicit commit/rollback. Plain JDBC on purpose: the transaction
 * boundary is visible in the code and does not depend on proxies or annotations.
 */
public final class JdbcTransactionRunner implements TransactionRunner {

    /** The transaction handle handed to {@link JdbcLicenseStore}. */
    record JdbcTx(Connection connection) implements Tx {
    }

    private final DataSource dataSource;

    public JdbcTransactionRunner(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @Override
    public <T> T inTransaction(Function<Tx, T> work) {
        Connection c = null;
        try {
            c = dataSource.getConnection();
            c.setAutoCommit(false);
            c.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            T result;
            try {
                result = work.apply(new JdbcTx(c));
            } catch (RuntimeException | Error e) {
                rollbackQuietly(c);
                throw e;
            }
            c.commit();
            return result;
        } catch (SQLException e) {
            if (c != null) {
                rollbackQuietly(c);
            }
            throw new StoreFailureException("database transaction failed (SQLState " + e.getSQLState() + ")", e);
        } finally {
            if (c != null) {
                try {
                    c.close();
                } catch (SQLException ignored) {
                    // Nothing useful can be done; the pool discards broken connections.
                }
            }
        }
    }

    private static void rollbackQuietly(Connection c) {
        try {
            c.rollback();
        } catch (SQLException ignored) {
            // The original failure is the one worth reporting.
        }
    }
}
