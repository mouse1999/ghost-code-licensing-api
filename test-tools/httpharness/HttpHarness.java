package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.crypto.ActivationCodes;
import com.interviewassistant.licensing.crypto.SigningKeyRing;
import com.interviewassistant.licensing.security.AdminAuthenticator;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.AdminScope;
import com.interviewassistant.licensing.security.NonceCache;
import com.interviewassistant.licensing.security.RateLimiter;
import com.interviewassistant.licensing.service.*;
import com.interviewassistant.licensing.store.JdbcLicenseStore;
import com.interviewassistant.licensing.store.JdbcTransactionRunner;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import jakarta.servlet.http.HttpServletRequest;

import javax.sql.DataSource;
import java.io.*;
import java.lang.annotation.Annotation;
import java.lang.reflect.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.time.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TEST-ONLY HTTP harness (Phase 134). It is NOT the Spring application. REAL: AdminController, ClientController, Dtos, the services,
 * JdbcLicenseStore/JdbcTransactionRunner on PostgreSQL, AdminAuthenticator, RateLimiter, the crypto, and the portal files. REPLACED
 * by harness code: Spring MVC routing/argument binding (read from the controllers' own annotations), Jackson (a small reflective
 * JSON mapper), Bean Validation (a small interpreter of the @NotNull/@Min/@Max/@Size/@NotBlank/@NotEmpty annotations), and copies of
 * SecurityFilter / AdminAuthFilter / ApiExceptionHandler behaviour. So it can show the controllers, DTO shapes and services work
 * together on PostgreSQL; it cannot show that Spring/Jackson/Bean Validation behave the same.
 */
public final class HttpHarness {

    public static final AtomicLong CLOCK_SKEW_SECONDS = new AtomicLong();
    public static final Clock CLOCK = new Clock() {
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId z) { return this; }
        @Override public Instant instant() { return Instant.now().plusSeconds(CLOCK_SKEW_SECONDS.get()); }
    };

    record Ds(String url, String user) implements DataSource {
        public Connection getConnection() throws SQLException { Properties p = new Properties(); p.setProperty("user", user); return DriverManager.getConnection(url, p); }
        public Connection getConnection(String u, String p) throws SQLException { return getConnection(); }
        public PrintWriter getLogWriter() { return null; } public void setLogWriter(PrintWriter o) { } public void setLoginTimeout(int s) { }
        public int getLoginTimeout() { return 0; } public java.util.logging.Logger getParentLogger() { return null; }
        public <T> T unwrap(Class<T> c) throws SQLException { throw new SQLException(); } public boolean isWrapperFor(Class<?> c) { return false; }
    }

    record Route(String[] segs, String method, Object controller, Method handler) { }

    static final List<Route> ROUTES = new ArrayList<>();

    /** What a started harness exposes to in-process tests. */
    public record Running(HttpServer server, int port, String db, Map<String, String> tokens, SigningKeyRing ring, String issuer) {
        public void stop() { server.stop(0); }
    }

    public static void main(String[] a) throws Exception {
        start(Integer.parseInt(a[0]), a[1], a[2], a[3], a[4]);
    }

    public static Running start(int port, String adminUrl, String user, String outDir, String portalDir) throws Exception {
        ROUTES.clear(); CLOCK_SKEW_SECONDS.set(0);
        Class.forName("pgbridge.PgBridgeDriver");
        String db = "h_" + Long.toHexString(System.nanoTime());
        try (Connection c = new Ds(adminUrl, user).getConnection(); PreparedStatement ps = c.prepareStatement("CREATE DATABASE " + db + " TEMPLATE lic_tmpl")) { ps.executeUpdate(); }
        Ds ds = new Ds(adminUrl.substring(0, adminUrl.lastIndexOf('/') + 1) + db, user);
        JdbcLicenseStore store = new JdbcLicenseStore(); JdbcTransactionRunner tx = new JdbcTransactionRunner(ds);
        SecureRandom r = new SecureRandom();
        ActivationCodes codes = new ActivationCodes(new byte[32], r);
        SigningKeyRing ring = SigningKeyRing.ephemeral("harness-key-1");
        ServiceSettings settings = new ServiceSettings("https://licensing.test", Duration.ofDays(7), Duration.ofMinutes(5));
        RateLimiter actClient = new RateLimiter(1000, Duration.ofMinutes(1), CLOCK), actFail = new RateLimiter(50, Duration.ofMinutes(15), CLOCK), valClient = new RateLimiter(1000, Duration.ofMinutes(1), CLOCK);
        RateLimiter adminFail = new RateLimiter(Integer.getInteger("harness.adminFailLimit", 10), Duration.ofMinutes(1), CLOCK);
        IssuanceService issuance = new IssuanceService(store, tx, codes, CLOCK);
        ClientLicenseService client = new ClientLicenseService(store, tx, codes, ring, settings, actClient, actFail, valClient, new NonceCache(Duration.ofMinutes(10), CLOCK), CLOCK);
        AdminLicenseService admin = new AdminLicenseService(store, tx, CLOCK);
        LicensingProperties props = new LicensingProperties(null, null, null, null, null, null, new LicensingProperties.Defaults(30));
        String fullTok = AdminAuthenticator.generateToken(r), readTok = AdminAuthenticator.generateToken(r), lifeTok = AdminAuthenticator.generateToken(r), issueTok = AdminAuthenticator.generateToken(r);
        AdminAuthenticator auth = new AdminAuthenticator(List.of(
                AdminAuthenticator.Credential.ofHex("full", AdminAuthenticator.hashHex(fullTok), EnumSet.allOf(AdminScope.class)),
                AdminAuthenticator.Credential.ofHex("reader", AdminAuthenticator.hashHex(readTok), EnumSet.of(AdminScope.LICENSE_READ)),
                AdminAuthenticator.Credential.ofHex("lifecycle", AdminAuthenticator.hashHex(lifeTok), EnumSet.of(AdminScope.LICENSE_READ, AdminScope.LICENSE_LIFECYCLE)),
                AdminAuthenticator.Credential.ofHex("issuer", AdminAuthenticator.hashHex(issueTok), EnumSet.of(AdminScope.LICENSE_ISSUE))));
        register(constructor(AdminController.class, issuance, admin, props));
        register(constructor(ClientController.class, client, ring));
        Files.createDirectories(Path.of(outDir));
        Files.writeString(Path.of(outDir, "harness.json"), "{\"db\":\"" + db + "\",\"full\":\"" + fullTok + "\",\"reader\":\"" + readTok + "\",\"lifecycle\":\"" + lifeTok + "\",\"issuer\":\"" + issueTok
                + "\",\"publicKeys\":" + "\"" + ring.publicKeys().keySet().iterator().next() + "\"}");
        String portalCsp = (String) field(PortalController.class, "PORTAL_CSP");

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.setExecutor(Executors.newFixedThreadPool(32));
        server.createContext("/", ex -> {
            try { handle(ex, auth, adminFail, portalCsp, Path.of(portalDir)); } catch (Throwable t) { t.printStackTrace(); send(ex, 500, "{\"code\":\"INTERNAL_ERROR\",\"message\":\"Unexpected error.\"}", null); }
        });
        server.start();
        System.out.println("harness up on 127.0.0.1:" + server.getAddress().getPort() + " db=" + db);
        return new Running(server, server.getAddress().getPort(), db, Map.of("full", fullTok, "reader", readTok, "lifecycle", lifeTok, "issuer", issueTok), ring, settings.issuer());
    }

    static Object field(Class<?> c, String name) throws Exception { Field f = c.getDeclaredField(name); f.setAccessible(true); return f.get(null); }

    static Object constructor(Class<?> c, Object... args) throws Exception {
        for (Constructor<?> k : c.getDeclaredConstructors()) if (k.getParameterCount() == args.length) { k.setAccessible(true); return k.newInstance(args); }
        throw new IllegalStateException("no constructor on " + c);
    }

    static void register(Object controller) {
        Class<?> c = controller.getClass();
        String base = c.isAnnotationPresent(org.springframework.web.bind.annotation.RequestMapping.class) ? c.getAnnotation(org.springframework.web.bind.annotation.RequestMapping.class).value()[0] : "";
        for (Method m : c.getDeclaredMethods()) {
            String path = null, verb = null;
            var g = m.getAnnotation(org.springframework.web.bind.annotation.GetMapping.class);
            var p = m.getAnnotation(org.springframework.web.bind.annotation.PostMapping.class);
            if (g != null) { verb = "GET"; path = g.value()[0]; } else if (p != null) { verb = "POST"; path = p.value()[0]; } else continue;
            m.setAccessible(true);
            ROUTES.add(new Route((base + path).substring(1).split("/"), verb, controller, m));
        }
        ROUTES.sort(Comparator.comparingInt((Route x) -> (int) Arrays.stream(x.segs()).filter(s -> s.startsWith("{")).count()));
    }

    // ------------------------------------------------------------------ request handling
    static void handle(HttpExchange ex, AdminAuthenticator auth, RateLimiter adminFail, String portalCsp, Path portalDir) throws Exception {
        String path = ex.getRequestURI().getRawPath(); String verb = ex.getRequestMethod();
        Map<String, String> hdr = new LinkedHashMap<>();
        // SecurityFilter copy: headers on every response
        hdr.put("X-Content-Type-Options", "nosniff"); hdr.put("Cache-Control", "no-store"); hdr.put("Referrer-Policy", "no-referrer");
        hdr.put("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
        if (path.equals("/__advance")) { CLOCK_SKEW_SECONDS.addAndGet(Long.parseLong(ex.getRequestURI().getQuery().split("=")[1])); send(ex, 200, "{}", hdr); return; }
        if (path.equals("/__now")) { send(ex, 200, "{\"now\":\"" + CLOCK.instant() + "\"}", hdr); return; }
        // PortalController (three fixed files)
        Map<String, String[]> portal = Map.of("/admin", new String[] {"index.html", "text/html"}, "/admin/", new String[] {"index.html", "text/html"},
                "/admin/portal.css", new String[] {"portal.css", "text/css"}, "/admin/portal.js", new String[] {"portal.js", "text/javascript"});
        if (verb.equals("GET") && portal.containsKey(path)) {
            hdr.put("Content-Security-Policy", portalCsp); hdr.put("Content-Type", portal.get(path)[1] + ";charset=utf-8");
            byte[] body = Files.readAllBytes(portalDir.resolve(portal.get(path)[0])); ex.getResponseHeaders().add("X-Portal", "1");
            sendBytes(ex, 200, body, hdr); return;
        }
        AdminPrincipal principal = null;
        // AdminAuthFilter copy
        if (path.equals("/api/v1/admin") || path.startsWith("/api/v1/admin/")) {
            String client = ex.getRemoteAddress().getAddress().getHostAddress();
            if (adminFail.isExhausted(client)) { error(ex, hdr, ErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED.defaultMessage(), adminFail.retryAfterSeconds(client)); return; }
            principal = auth.authenticate(ex.getRequestHeaders().getFirst("Authorization")).orElse(null);
            if (principal == null) { adminFail.record(client); hdr.put("WWW-Authenticate", "Bearer"); error(ex, hdr, ErrorCode.UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED.defaultMessage(), 0); return; }
        }
        byte[] body = ex.getRequestBody().readNBytes(16385);
        if (body.length > 16384) { error(ex, hdr, ErrorCode.PAYLOAD_TOO_LARGE, ErrorCode.PAYLOAD_TOO_LARGE.defaultMessage(), 0); return; }
        String[] req = path.substring(1).split("/");
        Route chosen = null; Map<String, String> vars = new HashMap<>(); boolean pathMatched = false;
        for (Route r : ROUTES) {
            if (r.segs().length != req.length) continue;
            Map<String, String> v = new HashMap<>(); boolean ok = true;
            for (int i = 0; i < req.length && ok; i++) { if (r.segs()[i].startsWith("{")) v.put(r.segs()[i].substring(1, r.segs()[i].length() - 1), java.net.URLDecoder.decode(req[i], StandardCharsets.UTF_8)); else ok = r.segs()[i].equals(req[i]); }
            if (!ok) continue; pathMatched = true;
            if (r.method().equals(verb)) { chosen = r; vars = v; break; }
        }
        if (chosen == null) { error(ex, hdr, pathMatched ? ErrorCode.VALIDATION_FAILED : ErrorCode.VALIDATION_FAILED, pathMatched ? "Method not allowed." : "No such endpoint.", 0, pathMatched ? 405 : 404); return; }
        Map<String, String> query = new HashMap<>();
        String qs = ex.getRequestURI().getRawQuery();
        if (qs != null) for (String kv : qs.split("&")) { int i = kv.indexOf('='); query.put(java.net.URLDecoder.decode(i < 0 ? kv : kv.substring(0, i), StandardCharsets.UTF_8), i < 0 ? "" : java.net.URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8)); }
        final AdminPrincipal pr = principal; final String remote = ex.getRemoteAddress().getAddress().getHostAddress();
        HttpServletRequest sreq = (HttpServletRequest) Proxy.newProxyInstance(HttpHarness.class.getClassLoader(), new Class<?>[] {HttpServletRequest.class},
                (p, m, args) -> m.getName().equals("getRemoteAddr") ? remote : args[0].equals(AdminAuthFilter.PRINCIPAL_ATTRIBUTE) ? pr : null);
        try {
            Parameter[] ps = chosen.handler().getParameters(); Object[] args = new Object[ps.length];
            for (int i = 0; i < ps.length; i++) {
                Parameter p = ps[i]; Class<?> t = p.getType();
                if (t == HttpServletRequest.class) { args[i] = sreq; continue; }
                var pv = p.getAnnotation(org.springframework.web.bind.annotation.PathVariable.class);
                var rp = p.getAnnotation(org.springframework.web.bind.annotation.RequestParam.class);
                var rh = p.getAnnotation(org.springframework.web.bind.annotation.RequestHeader.class);
                var rb = p.getAnnotation(org.springframework.web.bind.annotation.RequestBody.class);
                if (pv != null) args[i] = Json.scalar(vars.get(p.getName()), t);
                else if (rp != null) { String v = query.get(p.getName()); if (v == null && !rp.defaultValue().isEmpty()) v = rp.defaultValue(); if (v == null && rp.required() && !rp.defaultValue().equals("") ) v = rp.defaultValue();
                    if (v == null && rp.required()) throw new LicensingException(ErrorCode.VALIDATION_FAILED, "missing parameter"); args[i] = v == null ? null : Json.scalar(v, t); }
                else if (rh != null) { String v = ex.getRequestHeaders().getFirst(rh.value()); if (v == null && rh.required()) throw new LicensingException(ErrorCode.VALIDATION_FAILED, "missing header"); args[i] = v; }
                else if (rb != null) {
                    if (body.length == 0) { if (rb.required()) throw new LicensingException(ErrorCode.VALIDATION_FAILED, "Request body is required."); args[i] = null; }
                    else { String ct = ex.getRequestHeaders().getFirst("Content-Type"); if (ct == null || !ct.startsWith("application/json")) { error(ex, hdr, ErrorCode.VALIDATION_FAILED, "Unsupported media type; send application/json.", 0, 415); return; }
                        Object parsed; try { parsed = Json.parse(new String(body, StandardCharsets.UTF_8)); args[i] = Json.convert(parsed, p.getParameterizedType()); } catch (RuntimeException e) { throw new LicensingException(ErrorCode.VALIDATION_FAILED, ErrorCode.VALIDATION_FAILED.defaultMessage()); }
                        if (p.isAnnotationPresent(jakarta.validation.Valid.class)) Validator.check(args[i]); }
                }
            }
            Object out;
            try { out = chosen.handler().invoke(chosen.controller(), args); } catch (InvocationTargetException e) { throw e.getCause(); }
            int status = 200; Object payload = out;
            if (out != null && out.getClass().getSimpleName().equals("ResponseEntity")) { status = (int) out.getClass().getMethod("statusCode").invoke(out); payload = out.getClass().getMethod("body").invoke(out); }
            hdr.put("Content-Type", "application/json");
            send(ex, status, Json.write(payload), hdr);
        } catch (LicensingException e) {
            error(ex, hdr, e.code(), e.getMessage(), e.retryAfterSeconds());
        } catch (Throwable t) {
            System.err.println("unexpected " + t.getClass().getName() + ": " + t.getMessage());
            error(ex, hdr, ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.defaultMessage(), 0);
        }
    }

    static void error(HttpExchange ex, Map<String, String> hdr, ErrorCode c, String m, long retry) throws IOException { error(ex, hdr, c, m, retry, c.httpStatus()); }
    static void error(HttpExchange ex, Map<String, String> hdr, ErrorCode c, String m, long retry, int status) throws IOException {
        hdr.put("Content-Type", "application/json"); if (retry > 0) hdr.put("Retry-After", Long.toString(retry));
        send(ex, status, "{\"code\":\"" + c.name() + "\",\"message\":" + Json.str(m) + "}", hdr);
    }
    static void send(HttpExchange ex, int status, String body, Map<String, String> hdr) throws IOException { sendBytes(ex, status, body.getBytes(StandardCharsets.UTF_8), hdr == null ? Map.of() : hdr); }
    static void sendBytes(HttpExchange ex, int status, byte[] body, Map<String, String> hdr) throws IOException {
        hdr.forEach((k, v) -> ex.getResponseHeaders().set(k, v)); ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream o = ex.getResponseBody()) { o.write(body); } else ex.close();
    }

    // ------------------------------------------------------------------ bean validation interpreter (NOT Hibernate Validator)
    static final class Validator {
        static void check(Object o) {
            if (o == null) return;
            for (RecordComponent rc : o.getClass().getRecordComponents()) {
                Object v; try { v = rc.getAccessor().invoke(o); } catch (Exception e) { throw new IllegalStateException(e); }
                if (rc.isAnnotationPresent(jakarta.validation.constraints.NotNull.class) && v == null) bad(rc);
                if (rc.isAnnotationPresent(jakarta.validation.constraints.NotBlank.class) && (v == null || v.toString().isBlank())) bad(rc);
                if (rc.isAnnotationPresent(jakarta.validation.constraints.NotEmpty.class) && (v == null || ((Collection<?>) v).isEmpty())) bad(rc);
                var mn = rc.getAnnotation(jakarta.validation.constraints.Min.class); var mx = rc.getAnnotation(jakarta.validation.constraints.Max.class);
                if (v instanceof Number n) { if (mn != null && n.longValue() < mn.value()) bad(rc); if (mx != null && n.longValue() > mx.value()) bad(rc); }
                var sz = rc.getAnnotation(jakarta.validation.constraints.Size.class); if (sz != null && v instanceof String s && s.length() > sz.max()) bad(rc);
                if (rc.isAnnotationPresent(jakarta.validation.Valid.class) && v != null) check(v);
            }
        }
        static void bad(RecordComponent rc) { throw new LicensingException(ErrorCode.VALIDATION_FAILED, ErrorCode.VALIDATION_FAILED.defaultMessage()); }
    }

    // ------------------------------------------------------------------ JSON (NOT Jackson)
    static final class Json {
        static String str(String s) { StringBuilder b = new StringBuilder("\""); for (char c : s.toCharArray()) { switch (c) { case '"' -> b.append("\\\""); case '\\' -> b.append("\\\\"); case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t"); default -> { if (c < 32) b.append(String.format("\\u%04x", (int) c)); else b.append(c); } } } return b.append('"').toString(); }
        static String write(Object o) {
            try {
                if (o == null) return "null";
                if (o instanceof String s) return str(s);
                if (o instanceof Number || o instanceof Boolean) return o.toString();
                if (o instanceof Enum<?> e) return str(e.name());
                if (o instanceof Instant || o instanceof UUID) return str(o.toString());
                if (o instanceof Collection<?> c) { StringJoiner j = new StringJoiner(",", "[", "]"); for (Object x : c) j.add(write(x)); return j.toString(); }
                if (o.getClass().isRecord()) { StringJoiner j = new StringJoiner(",", "{", "}"); for (RecordComponent rc : o.getClass().getRecordComponents()) { Method m = rc.getAccessor(); m.setAccessible(true); j.add(str(rc.getName()) + ":" + write(m.invoke(o))); } return j.toString(); }
                throw new IllegalStateException("cannot serialise " + o.getClass());
            } catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
        }
        // parser
        static Object parse(String s) { int[] i = {0}; Object v = val(s, i); ws(s, i); if (i[0] != s.length()) throw new IllegalArgumentException("trailing"); return v; }
        static void ws(String s, int[] i) { while (i[0] < s.length() && Character.isWhitespace(s.charAt(i[0]))) i[0]++; }
        static Object val(String s, int[] i) {
            ws(s, i); char c = s.charAt(i[0]);
            if (c == '{') { i[0]++; Map<String, Object> m = new LinkedHashMap<>(); ws(s, i); if (s.charAt(i[0]) == '}') { i[0]++; return m; } for (;;) { ws(s, i); String k = (String) val(s, i); ws(s, i); if (s.charAt(i[0]++) != ':') throw new IllegalArgumentException(); m.put(k, val(s, i)); ws(s, i); char d = s.charAt(i[0]++); if (d == '}') return m; if (d != ',') throw new IllegalArgumentException(); } }
            if (c == '[') { i[0]++; List<Object> l = new ArrayList<>(); ws(s, i); if (s.charAt(i[0]) == ']') { i[0]++; return l; } for (;;) { l.add(val(s, i)); ws(s, i); char d = s.charAt(i[0]++); if (d == ']') return l; if (d != ',') throw new IllegalArgumentException(); } }
            if (c == '"') { i[0]++; StringBuilder b = new StringBuilder(); for (;;) { char d = s.charAt(i[0]++); if (d == '"') return b.toString(); if (d == '\\') { char e = s.charAt(i[0]++); switch (e) { case 'n' -> b.append('\n'); case 't' -> b.append('\t'); case 'r' -> b.append('\r'); case 'u' -> { b.append((char) Integer.parseInt(s.substring(i[0], i[0] + 4), 16)); i[0] += 4; } default -> b.append(e); } } else b.append(d); } }
            if (s.startsWith("true", i[0])) { i[0] += 4; return Boolean.TRUE; } if (s.startsWith("false", i[0])) { i[0] += 5; return Boolean.FALSE; } if (s.startsWith("null", i[0])) { i[0] += 4; return null; }
            int st = i[0]; while (i[0] < s.length() && "+-0123456789.eE".indexOf(s.charAt(i[0])) >= 0) i[0]++; if (st == i[0]) throw new IllegalArgumentException("bad json"); String n = s.substring(st, i[0]);
            return n.contains(".") || n.contains("e") || n.contains("E") ? (Object) Double.valueOf(n) : (Object) Long.valueOf(n);
        }
        static Object scalar(String v, Class<?> t) { if (t == UUID.class) { try { return UUID.fromString(v); } catch (IllegalArgumentException e) { throw new LicensingException(ErrorCode.VALIDATION_FAILED, "bad id"); } } if (t == int.class || t == Integer.class) return Integer.valueOf(v); if (t == long.class || t == Long.class) return Long.valueOf(v); return v; }
        @SuppressWarnings({"unchecked", "rawtypes"})
        static Object convert(Object v, Type t) {
            if (v == null) return null;
            Class<?> c = t instanceof ParameterizedType pt ? (Class<?>) pt.getRawType() : (Class<?>) t;
            if (c == String.class) { if (!(v instanceof String)) throw new IllegalArgumentException("string expected"); return v; }
            if (c == Integer.class || c == int.class) { if (!(v instanceof Long l) || l > Integer.MAX_VALUE || l < Integer.MIN_VALUE) throw new IllegalArgumentException(); return ((Long) v).intValue(); }
            if (c == Long.class || c == long.class) { if (!(v instanceof Long)) throw new IllegalArgumentException(); return v; }
            if (c == Boolean.class || c == boolean.class) { if (!(v instanceof Boolean)) throw new IllegalArgumentException(); return v; }
            if (c == Instant.class) return Instant.parse((String) v);
            if (c == UUID.class) return UUID.fromString((String) v);
            if (c.isEnum()) return Enum.valueOf((Class) c, (String) v);
            if (Collection.class.isAssignableFrom(c)) { Type el = ((ParameterizedType) t).getActualTypeArguments()[0]; List<Object> l = new ArrayList<>(); for (Object x : (List<?>) v) l.add(convert(x, el)); if (c == Set.class) { Set<Object> s = new LinkedHashSet<>(l); return s; } return l; }
            if (c.isRecord()) {
                Map<String, Object> m = (Map<String, Object>) v; RecordComponent[] rcs = c.getRecordComponents(); Object[] args = new Object[rcs.length]; Class<?>[] types = new Class<?>[rcs.length];
                for (int i = 0; i < rcs.length; i++) { args[i] = convert(m.get(rcs[i].getName()), rcs[i].getGenericType()); types[i] = rcs[i].getType(); }
                for (String k : m.keySet()) if (Arrays.stream(rcs).noneMatch(rc -> rc.getName().equals(k))) { /* Jackson (Spring Boot default) ignores unknown properties */ }
                try { Constructor<?> k = c.getDeclaredConstructor(types); k.setAccessible(true); return k.newInstance(args); } catch (InvocationTargetException e) { throw new IllegalArgumentException(e.getCause()); } catch (ReflectiveOperationException e) { throw new IllegalStateException(e); }
            }
            throw new IllegalArgumentException("unsupported " + t);
        }
    }

    static final class SecureRandom extends java.security.SecureRandom { }
}
