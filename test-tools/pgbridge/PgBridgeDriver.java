package pgbridge;

import java.io.*;
import java.lang.reflect.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.logging.Logger;

/**
 * TEST-ONLY minimal JDBC driver that speaks the PostgreSQL wire protocol v3 (trust authentication, simple-query protocol). It exists
 * only because the real PostgreSQL JDBC driver could not be downloaded in the Phase 134 sandbox. It is NOT pgjdbc: it substitutes
 * parameters into the SQL text on the client, so it proves nothing about server-side parameter binding or injection resistance, and
 * it implements only the handful of JDBC calls that JdbcLicenseStore and JdbcTransactionRunner use. URL: jdbc:pgbridge://host:port/db
 * with properties user. Never ship or use it in production; with Maven, the real org.postgresql driver replaces it.
 */
public final class PgBridgeDriver implements Driver {

    static { try { DriverManager.registerDriver(new PgBridgeDriver()); } catch (SQLException e) { throw new ExceptionInInitializerError(e); } }

    public static void register() { /* triggers the static block */ }

    @Override public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) return null;
        String rest = url.substring("jdbc:pgbridge://".length());
        String hostPort = rest.substring(0, rest.indexOf('/')); String db = rest.substring(rest.indexOf('/') + 1);
        String host = hostPort.split(":")[0]; int port = Integer.parseInt(hostPort.split(":")[1]);
        String user = info.getProperty("user", "postgres");
        try { return proxyConnection(new Wire(host, port, user, db)); } catch (IOException e) { throw new SQLException("connect failed: " + e.getMessage(), "08001"); }
    }
    @Override public boolean acceptsURL(String url) { return url != null && url.startsWith("jdbc:pgbridge://"); }
    @Override public DriverPropertyInfo[] getPropertyInfo(String u, Properties p) { return new DriverPropertyInfo[0]; }
    @Override public int getMajorVersion() { return 0; } @Override public int getMinorVersion() { return 1; }
    @Override public boolean jdbcCompliant() { return false; }
    @Override public Logger getParentLogger() { return Logger.getLogger("pgbridge"); }

    // ------------------------------------------------------------------ wire
    static final class Result { List<String> cols = new ArrayList<>(); List<String[]> rows = new ArrayList<>(); long updated; }

    static final class Wire {
        final Socket s; final DataInputStream in; final DataOutputStream out; boolean inTx, autoCommit = true, broken;
        Wire(String host, int port, String user, String db) throws IOException {
            s = new Socket(host, port); in = new DataInputStream(new BufferedInputStream(s.getInputStream())); out = new DataOutputStream(new BufferedOutputStream(s.getOutputStream()));
            ByteArrayOutputStream b = new ByteArrayOutputStream(); DataOutputStream d = new DataOutputStream(b);
            d.writeInt(196608);
            for (String x : new String[] {"user", user, "database", db, "client_encoding", "UTF8", "TimeZone", "UTC", "DateStyle", "ISO"}) { d.write(x.getBytes(StandardCharsets.UTF_8)); d.write(0); }
            d.write(0);
            out.writeInt(b.size() + 4); out.write(b.toByteArray()); out.flush();
            for (;;) { char t = (char) in.readByte(); int len = in.readInt(); byte[] body = new byte[len - 4]; in.readFully(body);
                if (t == 'R' && ByteBuffer4(body) != 0) throw new IOException("only trust authentication is supported");
                if (t == 'E') throw new IOException("startup error: " + new String(body, StandardCharsets.UTF_8));
                if (t == 'Z') break; }
        }
        static int ByteBuffer4(byte[] b) { return ((b[0] & 255) << 24) | ((b[1] & 255) << 16) | ((b[2] & 255) << 8) | (b[3] & 255); }

        synchronized Result query(String sql) throws SQLException {
            try {
                byte[] q = sql.getBytes(StandardCharsets.UTF_8); out.writeByte('Q'); out.writeInt(q.length + 5); out.write(q); out.writeByte(0); out.flush();
                Result r = new Result(); SQLException err = null;
                for (;;) {
                    char t = (char) in.readByte(); int len = in.readInt(); byte[] body = new byte[len - 4]; in.readFully(body); ByteArrayInputStream bi = new ByteArrayInputStream(body); DataInputStream d = new DataInputStream(bi);
                    switch (t) {
                        case 'T' -> { int n = d.readShort(); r.cols.clear(); for (int i = 0; i < n; i++) { r.cols.add(cstr(d)); d.skipBytes(18); } }
                        case 'D' -> { int n = d.readShort(); String[] row = new String[n]; for (int i = 0; i < n; i++) { int l = d.readInt(); if (l >= 0) { byte[] v = new byte[l]; d.readFully(v); row[i] = new String(v, StandardCharsets.UTF_8); } } r.rows.add(row); }
                        case 'C' -> { String tag = cstr(d); String[] p = tag.split(" "); try { r.updated = Long.parseLong(p[p.length - 1]); } catch (NumberFormatException ignore) { } }
                        case 'E' -> { String code = "", msg = ""; for (;;) { int f = d.readByte(); if (f == 0) break; String v = cstr(d); if (f == 'C') code = v; if (f == 'M') msg = v; } err = new SQLException(msg, code); }
                        case 'Z' -> { inTx = body[0] != 'I'; if (err != null) throw err; return r; }
                        default -> { }
                    }
                }
            } catch (IOException e) { broken = true; throw new SQLException("connection lost: " + e.getMessage(), "08006"); }
        }
        static String cstr(DataInputStream d) throws IOException { ByteArrayOutputStream b = new ByteArrayOutputStream(); int c; while ((c = d.read()) > 0) b.write(c); return b.toString(StandardCharsets.UTF_8); }
        void close() { try { out.writeByte('X'); out.writeInt(4); out.flush(); s.close(); } catch (IOException ignored) { } }
    }

    // ------------------------------------------------------------------ literals
    static String literal(Object v) {
        if (v == null) return "NULL";
        if (v instanceof Integer || v instanceof Long || v instanceof Short) return v.toString();
        if (v instanceof Boolean b) return b ? "TRUE" : "FALSE";
        if (v instanceof UUID u) return "'" + u + "'::uuid";
        if (v instanceof OffsetDateTime t) return "'" + t + "'::timestamptz";
        if (v instanceof byte[] bytes) { StringBuilder sb = new StringBuilder("'\\x"); for (byte x : bytes) sb.append(String.format("%02x", x)); return sb.append("'::bytea").toString(); }
        if (v instanceof String s) { if (s.indexOf(0) >= 0) throw new IllegalArgumentException("NUL in string"); return "'" + s.replace("'", "''") + "'"; }
        throw new IllegalArgumentException("unsupported parameter type " + v.getClass());
    }

    static String bind(String sql, Map<Integer, Object> p) throws SQLException {
        StringBuilder out = new StringBuilder(); boolean q = false; int n = 0;
        for (int i = 0; i < sql.length(); i++) { char c = sql.charAt(i);
            if (c == '\'') q = !q;
            if (c == '?' && !q) { n++; if (!p.containsKey(n)) throw new SQLException("parameter " + n + " not set"); out.append(literal(p.get(n))); } else out.append(c); }
        if (p.size() != n) throw new SQLException("parameter count mismatch: sql has " + n + ", bound " + p.size());
        return out.toString();
    }

    // ------------------------------------------------------------------ proxies
    static Connection proxyConnection(Wire w) {
        return (Connection) Proxy.newProxyInstance(PgBridgeDriver.class.getClassLoader(), new Class<?>[] {Connection.class}, (px, m, a) -> {
            { switch (m.getName()) {
                case "setAutoCommit" -> { w.autoCommit = (Boolean) a[0]; return null; }
                case "getAutoCommit" -> { return w.autoCommit; }
                case "setTransactionIsolation" -> { if ((Integer) a[0] != Connection.TRANSACTION_READ_COMMITTED) throw new SQLException("only READ COMMITTED"); return null; }
                case "commit" -> { if (w.inTx) w.query("COMMIT"); return null; }
                case "rollback" -> { if (w.inTx) w.query("ROLLBACK"); return null; }
                case "close" -> { w.close(); return null; }
                case "isClosed" -> { return w.s.isClosed(); }
                case "prepareStatement" -> { boolean keys = a.length > 1; return proxyStatement(w, (String) a[0], keys); }
                case "toString" -> { return "PgBridgeConnection"; }
                default -> throw new SQLFeatureNotSupportedException("Connection." + m.getName());
            } }
        });
    }

    static PreparedStatement proxyStatement(Wire w, String sql, boolean keys) {
        Map<Integer, Object> p = new TreeMap<>(); Result[] last = new Result[1]; Result[] gen = new Result[1];
        return (PreparedStatement) Proxy.newProxyInstance(PgBridgeDriver.class.getClassLoader(), new Class<?>[] {PreparedStatement.class}, (px, m, a) -> {
            switch (m.getName()) {
                case "setObject", "setString", "setInt", "setLong" -> { p.put((Integer) a[0], a[1]); return null; }
                case "setNull" -> { p.put((Integer) a[0], null); return null; }
                case "executeUpdate", "executeQuery" -> {
                    String text = bind(sql, p); boolean ret = keys && m.getName().equals("executeUpdate");
                    if (w.autoCommit == false && !w.inTx) w.query("BEGIN");
                    Result r = w.query(ret ? text + " RETURNING *" : text);
                    if (ret) { gen[0] = r; return (int) r.updated; }
                    last[0] = r; return m.getName().equals("executeQuery") ? proxyResult(r) : (Object) (int) r.updated;
                }
                case "getGeneratedKeys" -> { return proxyResult(gen[0]); }
                case "close" -> { return null; }
                default -> throw new SQLFeatureNotSupportedException("PreparedStatement." + m.getName());
            }
        });
    }

    static ResultSet proxyResult(Result r) {
        int[] pos = {-1}; boolean[] wasNull = {false};
        return (ResultSet) Proxy.newProxyInstance(PgBridgeDriver.class.getClassLoader(), new Class<?>[] {ResultSet.class}, (px, m, a) -> {
            String n = m.getName();
            if (n.equals("next")) return ++pos[0] < r.rows.size();
            if (n.equals("close")) return null;
            if (n.equals("wasNull")) return wasNull[0];
            if (n.startsWith("get")) {
                String v = r.rows.get(pos[0])[(Integer) a[0] - 1]; wasNull[0] = v == null;
                switch (n) {
                    case "getString": return v;
                    case "getLong": return v == null ? 0L : Long.parseLong(v);
                    case "getInt": return v == null ? 0 : Integer.parseInt(v);
                    case "getObject":
                        if (a.length == 1) return v;
                        Class<?> c = (Class<?>) a[1];
                        if (v == null) return null;
                        if (c == UUID.class) return UUID.fromString(v);
                        if (c == OffsetDateTime.class) return OffsetDateTime.parse(v.replace(' ', 'T').replaceAll("([+-]\\d\\d)$", "$1:00"));
                        if (c == String.class) return v;
                        throw new SQLFeatureNotSupportedException("getObject " + c);
                    default: throw new SQLFeatureNotSupportedException("ResultSet." + n);
                }
            }
            throw new SQLFeatureNotSupportedException("ResultSet." + n);
        });
    }
}
