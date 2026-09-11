package com.interviewassistant.licensing.crypto;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A deliberately tiny JSON writer and STRICT reader for the one shape the entitlement token needs: a single flat object whose
 * values are strings, integers, or arrays of strings. Anything else (nesting, floats, booleans, null, duplicate keys, trailing
 * text) is rejected. It exists so the signed-token code has no dependency on the web framework's JSON library; the signature is
 * over the exact bytes of the payload segment, so no canonicalisation is needed.
 */
public final class FlatJson {

    private FlatJson() {
    }

    /** Builds a flat object, keeping insertion order. */
    public static final class Writer {
        private final StringBuilder sb = new StringBuilder("{");
        private boolean first = true;

        public Writer str(String key, String value) {
            key(key);
            quote(value);
            return this;
        }

        public Writer num(String key, long value) {
            key(key);
            sb.append(value);
            return this;
        }

        public Writer strings(String key, List<String> values) {
            key(key);
            sb.append('[');
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    sb.append(',');
                }
                quote(values.get(i));
            }
            sb.append(']');
            return this;
        }

        public String build() {
            return sb.toString() + "}";
        }

        private void key(String key) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            quote(key);
            sb.append(':');
        }

        private void quote(String s) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    case '\b' -> sb.append("\\b");
                    case '\f' -> sb.append("\\f");
                    default -> {
                        if (c < 0x20) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                    }
                }
            }
            sb.append('"');
        }
    }

    /** Parses one flat object. Values are {@link String}, {@link Long} or {@code List<String>}. */
    public static Map<String, Object> parse(String json) {
        return new Parser(json).parseObject();
    }

    private static final class Parser {
        private final String s;
        private int pos;

        Parser(String s) {
            if (s == null || s.length() > 8192) {
                throw new IllegalArgumentException("json missing or too long");
            }
            this.s = s;
        }

        Map<String, Object> parseObject() {
            Map<String, Object> out = new LinkedHashMap<>();
            ws();
            expect('{');
            ws();
            if (peek() == '}') {
                pos++;
            } else {
                while (true) {
                    ws();
                    String key = string();
                    ws();
                    expect(':');
                    ws();
                    Object value = value();
                    if (out.put(key, value) != null) {
                        throw new IllegalArgumentException("duplicate key");
                    }
                    ws();
                    char c = next();
                    if (c == '}') {
                        break;
                    }
                    if (c != ',') {
                        throw new IllegalArgumentException("expected , or }");
                    }
                }
            }
            ws();
            if (pos != s.length()) {
                throw new IllegalArgumentException("trailing characters");
            }
            return out;
        }

        private Object value() {
            char c = peek();
            if (c == '"') {
                return string();
            }
            if (c == '[') {
                return array();
            }
            if (c == '-' || (c >= '0' && c <= '9')) {
                return number();
            }
            throw new IllegalArgumentException("unsupported value");
        }

        private List<String> array() {
            expect('[');
            List<String> items = new ArrayList<>();
            ws();
            if (peek() == ']') {
                pos++;
                return items;
            }
            while (true) {
                ws();
                items.add(string());
                ws();
                char c = next();
                if (c == ']') {
                    return items;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("expected , or ]");
                }
            }
        }

        private Long number() {
            int start = pos;
            if (peek() == '-') {
                pos++;
            }
            int digitsStart = pos;
            while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') {
                pos++;
            }
            int digits = pos - digitsStart;
            if (digits == 0 || digits > 18 || (digits > 1 && s.charAt(digitsStart) == '0')) {
                throw new IllegalArgumentException("bad integer");
            }
            if (pos < s.length() && (s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                throw new IllegalArgumentException("only integers are allowed");
            }
            return Long.parseLong(s.substring(start, pos));
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= s.length()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c < 0x20) {
                    throw new IllegalArgumentException("control character in string");
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= s.length()) {
                    throw new IllegalArgumentException("bad escape");
                }
                char e = s.charAt(pos++);
                switch (e) {
                    case '"', '\\', '/' -> sb.append(e);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) {
                            throw new IllegalArgumentException("bad unicode escape");
                        }
                        try {
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException ex) {
                            throw new IllegalArgumentException("bad unicode escape");
                        }
                        pos += 4;
                    }
                    default -> throw new IllegalArgumentException("bad escape");
                }
            }
        }

        private void ws() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private char peek() {
            if (pos >= s.length()) {
                throw new IllegalArgumentException("unexpected end");
            }
            return s.charAt(pos);
        }

        private char next() {
            char c = peek();
            pos++;
            return c;
        }

        private void expect(char c) {
            if (next() != c) {
                throw new IllegalArgumentException("expected " + c);
            }
        }
    }
}
