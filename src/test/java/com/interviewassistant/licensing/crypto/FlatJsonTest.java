package com.interviewassistant.licensing.crypto;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class FlatJsonTest {

    @Test
    void writerOutputParsesBackIncludingEscapes() {
        String json = new FlatJson.Writer().str("a", "q\"uote\\slash\nnl\u0001ctl").num("n", -42).strings("r", List.of("x", "y")).build();
        Map<String, Object> m = FlatJson.parse(json);
        assertEquals("q\"uote\\slash\nnl\u0001ctl", m.get("a"));
        assertEquals(-42L, m.get("n"));
        assertEquals(List.of("x", "y"), m.get("r"));
    }

    @Test
    void parserIsStrict() {
        String[] bad = {"", "[]", "{\"a\":1,\"a\":2}", "{\"a\":1.5}", "{\"a\":01}", "{\"a\":true}", "{\"a\":null}", "{\"a\":{}}",
                "{\"a\":[1]}", "{\"a\":1} x", "{\"a\":\"unterminated}", "{\"a\":\"\\q\"}", "{\"a\":1,}", "{a:1}",
                "{\"a\":" + "9".repeat(30) + "}", "{\"a\":1e5}"};
        for (String b : bad) {
            assertThrows(IllegalArgumentException.class, () -> FlatJson.parse(b), b);
        }
        assertThrows(IllegalArgumentException.class, () -> FlatJson.parse("{\"a\":\"" + "x".repeat(9000) + "\"}"));
    }

    @Test
    void emptyObjectAndWhitespaceAreAccepted() {
        assertTrue(FlatJson.parse(" { } ").isEmpty());
        assertEquals(1L, FlatJson.parse("{ \"a\" : 1 }").get("a"));
    }
}
