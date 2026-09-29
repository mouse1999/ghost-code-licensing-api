package com.interviewassistant.licensing.security;

import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A fixed-window counter per key: at most {@code max} events per {@code window}. Two uses:
 * <ul>
 *   <li>{@link #tryAcquire} counts every attempt (request-rate limiting);</li>
 *   <li>{@link #isExhausted} / {@link #record} count only failures (brute-force lockout of one client + subject).</li>
 * </ul>
 *
 * <p><b>Limits:</b> state is per process (in memory). Behind several instances the effective limit multiplies, and a restart
 * clears it. This is an abuse brake, not the only defence: activation codes carry 160 bits, so guessing is infeasible
 * regardless. Put a gateway/WAF limit in front for volumetric abuse.
 */
public final class RateLimiter {

    private static final int SWEEP_THRESHOLD = 10_000;

    private record Window(long startMillis, int count) {
    }

    private final int max;
    private final long windowMillis;
    private final Clock clock;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimiter(int max, Duration window, Clock clock) {
        if (max < 1 || window.isNegative() || window.isZero()) {
            throw new IllegalArgumentException("max and window must be positive");
        }
        this.max = max;
        this.windowMillis = window.toMillis();
        this.clock = clock;
    }

    /** Counts one event for {@code key}; returns false (and does not count) if the window is already full. */
    public boolean tryAcquire(String key) {
        long now = clock.millis();
        boolean[] allowed = {false};
        windows.compute(key, (k, w) -> {
            Window cur = fresh(w, now);
            if (cur.count() < max) {
                allowed[0] = true;
                return new Window(cur.startMillis(), cur.count() + 1);
            }
            return cur;
        });
        sweepIfLarge(now);
        return allowed[0];
    }

    /** Counts one event unconditionally (for failure tracking). */
    public void record(String key) {
        long now = clock.millis();
        windows.compute(key, (k, w) -> {
            Window cur = fresh(w, now);
            return new Window(cur.startMillis(), cur.count() + 1);
        });
        sweepIfLarge(now);
    }

    /** True if {@code key} has used up its window. */
    public boolean isExhausted(String key) {
        Window w = windows.get(key);
        long now = clock.millis();
        return w != null && now - w.startMillis() < windowMillis && w.count() >= max;
    }

    /** Whole seconds until the window for {@code key} resets (at least 1). */
    public long retryAfterSeconds(String key) {
        Window w = windows.get(key);
        if (w == null) {
            return 1;
        }
        long remaining = windowMillis - (clock.millis() - w.startMillis());
        return Math.max(1, (remaining + 999) / 1000);
    }

    private Window fresh(Window w, long now) {
        return w == null || now - w.startMillis() >= windowMillis ? new Window(now, 0) : w;
    }

    private void sweepIfLarge(long now) {
        if (windows.size() < SWEEP_THRESHOLD) {
            return;
        }
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext(); ) {
            if (now - it.next().getValue().startMillis() >= windowMillis) {
                it.remove();
            }
        }
    }
}
