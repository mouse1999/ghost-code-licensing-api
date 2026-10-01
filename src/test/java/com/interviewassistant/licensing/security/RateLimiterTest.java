package com.interviewassistant.licensing.security;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {

    private static final class TestClock extends Clock {
        final AtomicLong ms = new AtomicLong(1_000_000);

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId z) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(ms.get());
        }
    }

    @Test
    void allowsUpToTheLimitThenBlocksUntilTheWindowResets() {
        TestClock c = new TestClock();
        RateLimiter l = new RateLimiter(3, Duration.ofMinutes(1), c);
        assertTrue(l.tryAcquire("k"));
        assertTrue(l.tryAcquire("k"));
        assertTrue(l.tryAcquire("k"));
        assertFalse(l.tryAcquire("k"));
        assertEquals(60, l.retryAfterSeconds("k"));
        c.ms.addAndGet(30_000);
        assertFalse(l.tryAcquire("k"));
        assertEquals(30, l.retryAfterSeconds("k"));
        c.ms.addAndGet(30_000);
        assertTrue(l.tryAcquire("k"));
    }

    @Test
    void keysAreIndependent() {
        RateLimiter l = new RateLimiter(1, Duration.ofMinutes(1), new TestClock());
        assertTrue(l.tryAcquire("a"));
        assertFalse(l.tryAcquire("a"));
        assertTrue(l.tryAcquire("b"));
    }

    @Test
    void failureCountingLocksOutOnlyAfterTheBudgetIsSpent() {
        TestClock c = new TestClock();
        RateLimiter l = new RateLimiter(2, Duration.ofMinutes(15), c);
        assertFalse(l.isExhausted("client|email"));
        l.record("client|email");
        assertFalse(l.isExhausted("client|email"));
        l.record("client|email");
        assertTrue(l.isExhausted("client|email"));
        assertFalse(l.isExhausted("client|other-email"));
        c.ms.addAndGet(15 * 60_000);
        assertFalse(l.isExhausted("client|email"));
    }

    @Test
    void concurrentCallersNeverExceedTheLimit() throws Exception {
        RateLimiter l = new RateLimiter(50, Duration.ofMinutes(1), new TestClock());
        java.util.concurrent.atomic.AtomicInteger ok = new java.util.concurrent.atomic.AtomicInteger();
        Thread[] ts = new Thread[16];
        for (int i = 0; i < ts.length; i++) {
            ts[i] = new Thread(() -> {
                for (int j = 0; j < 100; j++) {
                    if (l.tryAcquire("shared")) {
                        ok.incrementAndGet();
                    }
                }
            });
            ts[i].start();
        }
        for (Thread t : ts) {
            t.join();
        }
        assertEquals(50, ok.get());
    }

    @Test
    void nonceCacheRejectsReplaysUntilTheyExpire() {
        TestClock c = new TestClock();
        NonceCache n = new NonceCache(Duration.ofMinutes(10), c);
        assertTrue(n.register("dev|nonce1"));
        assertFalse(n.register("dev|nonce1"));
        assertTrue(n.register("dev|nonce2"));
        c.ms.addAndGet(10 * 60_000);
        assertTrue(n.register("dev|nonce1"));
    }
}
