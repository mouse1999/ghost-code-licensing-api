package com.interviewassistant.licensing.service;

import com.interviewassistant.licensing.web.HttpHarness;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Phase 134 replacement of the Phase 129 test adapter with the SAME API, so the same desktop tests now run against: the real
 * AdminController/ClientController and Dtos, the real services and the real JdbcLicenseStore on PostgreSQL, behind HttpHarness
 * (a test HTTP server standing in for Spring MVC/Jackson/Bean Validation). Admin actions go over real HTTP with real bearer tokens.
 */
public final class RealServerHarness implements AutoCloseable {

    public record Lic(UUID id) { }

    public record Issued(Lic license, String activationCode, boolean replayed, int status) { }

    private final HttpHarness.Running running;
    private final HttpClient http = HttpClient.newHttpClient();
    private final String base;

    public RealServerHarness() throws Exception {
        String url = System.getProperty("licensing.test.pgUrl");
        running = HttpHarness.start(0, url, System.getProperty("licensing.test.pgUser", "postgres"),
                Files.createTempDirectory("h134").toString(), System.getProperty("licensing.portalDir"));
        base = "http://127.0.0.1:" + running.port();
    }

    public String baseUrl() { return base + ""; }

    public Clock clock() { return HttpHarness.CLOCK; }

    public void advance(Duration d) { HttpHarness.CLOCK_SKEW_SECONDS.addAndGet(d.toSeconds()); }

    public String issuer() { return running.issuer(); }

    public String kid() { return running.ring().activeKid(); }

    public java.security.PublicKey publicKey() { return running.ring().publicKeys().get(running.ring().activeKid()); }

    @Override public void close() { running.stop(); }

    // ------------------------------------------------------------------ admin over HTTP
    public record Reply(int status, String body) { }

    public Reply call(String token, String method, String path, String body, String idemKey) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(base + path));
            if (token != null) b.header("Authorization", "Bearer " + token);
            if (idemKey != null) b.header("Idempotency-Key", idemKey);
            if (body != null) b.header("Content-Type", "application/json");
            b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            return new Reply(r.statusCode(), r.body());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String token(String which) { return running.tokens().get(which); }

    private Reply admin(String method, String path, String body) { return call(token("full"), method, path, body, UUID.randomUUID().toString().replace("-", "")); }

    private static String field(String json, String name) {
        Matcher m = Pattern.compile("\"" + name + "\":(\"([^\"]*)\"|null|[0-9a-z]+)").matcher(json);
        if (!m.find()) return null;
        return m.group(2) != null ? m.group(2) : m.group(1).equals("null") ? null : m.group(1);
    }

    private Issued issueBody(String body) {
        Reply r = call(token("full"), "POST", "/api/v1/admin/licenses", body, UUID.randomUUID().toString().replace("-", ""));
        if (r.status() != 201) throw new IllegalStateException("issue failed " + r.status() + " " + r.body());
        return new Issued(new Lic(UUID.fromString(field(r.body(), "id"))), field(r.body(), "activationCode"), false, r.status());
    }

    public Issued issue(String email, int deviceLimit) {
        return issueBody("{\"customerEmail\":\"" + email + "\",\"paymentVerified\":true,\"paymentReference\":\"it-ref\",\"policy\":{\"deviceLimit\":" + deviceLimit
                + ",\"validityDays\":365,\"rights\":[\"LIVE\",\"DSA\"],\"activationWindowDays\":30}}");
    }

    public Issued issuePreset(String email, int days) {
        return issueBody("{\"customerEmail\":\"" + email + "\",\"paymentVerified\":true,\"policy\":{\"deviceLimit\":1,\"validityDays\":" + days + ",\"rights\":[\"LIVE\",\"DSA\"]}}");
    }

    public Issued issueFixed(String email, Instant end) {
        return issueBody("{\"customerEmail\":\"" + email + "\",\"paymentVerified\":true,\"expiresAt\":\"" + end + "\",\"policy\":{\"deviceLimit\":1,\"rights\":[\"LIVE\",\"DSA\"]}}");
    }

    public Reply suspend(UUID id) { return admin("POST", "/api/v1/admin/licenses/" + id + "/suspend", "{\"reason\":\"integration test\"}"); }
    public Reply reinstate(UUID id) { return admin("POST", "/api/v1/admin/licenses/" + id + "/reinstate", "{}"); }
    public Reply revoke(UUID id) { return admin("POST", "/api/v1/admin/licenses/" + id + "/revoke", "{\"reason\":\"integration test\"}"); }
    public Reply renewDays(UUID id, int days) { return admin("POST", "/api/v1/admin/licenses/" + id + "/renew", "{\"mode\":\"EXTEND_DAYS\",\"days\":" + days + "}"); }
    public Reply renewTo(UUID id, Instant end) { return admin("POST", "/api/v1/admin/licenses/" + id + "/renew", "{\"mode\":\"SET_END\",\"endsAt\":\"" + end + "\"}"); }
    public Reply get(UUID id) { return admin("GET", "/api/v1/admin/licenses/" + id, null); }
    public Reply audit(UUID id) { return admin("GET", "/api/v1/admin/licenses/" + id + "/audit?limit=100", null); }

    public int activeDevices(UUID id) { return Integer.parseInt(field(get(id).body(), "activeDeviceCount")); }
}
