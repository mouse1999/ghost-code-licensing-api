package com.interviewassistant.licensing.service;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/** Captures everything the services log (System.Logger delegates to java.util.logging here) for secret-leak assertions. */
final class LogCapture implements AutoCloseable {

    private final List<String> lines = new ArrayList<>();
    private final Handler handler = new Handler() {
        @Override
        public void publish(LogRecord r) {
            // Phase 137: the real PostgreSQL driver traces bind parameters (e-mail, device key) at FINEST when the root level is ALL.
            // That is third-party driver tracing, off at the production default (INFO); this capture is about what OUR code logs.
            // docs/SECURITY.md forbids enabling org.postgresql FINE/FINEST logging in production.
            if (r.getLoggerName() != null && r.getLoggerName().startsWith("org.postgresql")) {
                return;
            }
            StringBuilder sb = new StringBuilder(r.getLoggerName()).append(' ').append(r.getLevel()).append(' ');
            sb.append(new java.util.logging.SimpleFormatter().formatMessage(r));
            if (r.getThrown() != null) {
                sb.append(' ').append(r.getThrown());
            }
            synchronized (lines) {
                lines.add(sb.toString());
            }
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };
    private final Logger root = Logger.getLogger("");
    private final Level previous = root.getLevel();

    LogCapture() {
        root.setLevel(Level.ALL);
        root.addHandler(handler);
    }

    String text() {
        synchronized (lines) {
            return String.join("\n", lines);
        }
    }

    @Override
    public void close() {
        root.removeHandler(handler);
        root.setLevel(previous);
    }
}
