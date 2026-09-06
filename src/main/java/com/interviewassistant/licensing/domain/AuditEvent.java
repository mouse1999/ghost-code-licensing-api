package com.interviewassistant.licensing.domain;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * One append-only audit record: who did what to which license, when, and whether it worked.
 *
 * <p>{@code detail} is short, single-line, non-secret metadata. It is scrubbed on construction: control characters are removed,
 * anything shaped like an activation code is replaced, and the length is capped, so a coding mistake elsewhere cannot put a raw
 * credential into the trail. Customer email addresses are NOT written here; use a keyed reference instead.
 *
 * @param id        database identity, or null before the event is stored
 * @param actor     {@code admin:<credential id>}, {@code device:<registration id>} or {@code client:anonymous}
 * @param licenseId the license concerned, or null when none could be identified
 */
public record AuditEvent(Long id, Instant occurredAt, String actor, AuditAction action, UUID licenseId, AuditOutcome outcome,
                         String detail) {

    public static final int MAX_DETAIL = 1000;
    public static final int MAX_ACTOR = 100;

    /**
     * Eight groups of four characters joined by dashes (or spaces): the printed shape of an activation code. Requiring the
     * separators keeps UUIDs (8-4-4-4-12) and hex digests out of the net.
     */
    private static final Pattern CODE_SHAPE = Pattern.compile("(?i)(?:[0-9A-Z]{4}-){7}[0-9A-Z]{4}|(?:[0-9A-Z]{4} ){7}[0-9A-Z]{4}");

    public AuditEvent {
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(actor, "actor");
        Objects.requireNonNull(action, "action");
        Objects.requireNonNull(outcome, "outcome");
        actor = clean(actor, MAX_ACTOR);
        detail = detail == null ? "" : clean(detail, MAX_DETAIL);
    }

    public static AuditEvent of(Instant now, String actor, AuditAction action, UUID licenseId, AuditOutcome outcome, String detail) {
        return new AuditEvent(null, now, actor, action, licenseId, outcome, detail);
    }

    /** Builds {@code k1=v1; k2=v2} from alternating keys and values. */
    public static String detail(String... keyValues) {
        if (keyValues.length % 2 != 0) {
            throw new IllegalArgumentException("keys and values must pair up");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < keyValues.length; i += 2) {
            if (i > 0) {
                sb.append("; ");
            }
            sb.append(keyValues[i]).append('=').append(keyValues[i + 1]);
        }
        return sb.toString();
    }

    private static String clean(String value, int max) {
        String s = CODE_SHAPE.matcher(value).replaceAll("[redacted]");
        StringBuilder out = new StringBuilder(Math.min(s.length(), max));
        for (int i = 0; i < s.length() && out.length() < max; i++) {
            char c = s.charAt(i);
            out.append(Character.isISOControl(c) ? ' ' : c);
        }
        return out.toString();
    }
}
