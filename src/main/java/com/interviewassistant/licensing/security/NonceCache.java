package com.interviewassistant.licensing.security;

import java.time.Clock;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers recently used proof nonces so a captured client request cannot be replayed inside its timestamp window.
 * Entries live for {@code ttl} (set to at least twice the allowed clock skew). In-memory and per process: see the report's
 * known limitations. If the cache is full of live entries it refuses new nonces (fails closed).
 */
public final class NonceCache {

    private static final int MAX_ENTRIES = 200_000;

    private final long ttlMillis;
    private final Clock clock;
    private final Map<String, Long> seen = new ConcurrentHashMap<>();

    public NonceCache(Duration ttl, Clock clock) {
        this.ttlMillis = ttl.toMillis();
        this.clock = clock;
    }

    /** Returns true if {@code key} was not seen before (and remembers it); false if it is a replay or the cache is full. */
    public boolean register(String key) {
        long now = clock.millis();
        if (seen.size() >= MAX_ENTRIES) {
            evictExpired(now);
            if (seen.size() >= MAX_ENTRIES) {
                return false;
            }
        }
        boolean[] fresh = {false};
        seen.compute(key, (k, expiry) -> {
            if (expiry == null || expiry <= now) {
                fresh[0] = true;
                return now + ttlMillis;
            }
            return expiry;
        });
        return fresh[0];
    }

    private void evictExpired(long now) {
        for (Iterator<Map.Entry<String, Long>> it = seen.entrySet().iterator(); it.hasNext(); ) {
            if (it.next().getValue() <= now) {
                it.remove();
            }
        }
    }
}
