package com.interviewassistant.licensing.web;

import jakarta.servlet.http.HttpServletRequest;

/**
 * The client key used for rate limiting. It is the connection's remote address as the servlet container reports it. Forwarded
 * headers are deliberately NOT read here: with {@code server.forward-headers-strategy=native} Tomcat replaces the remote address
 * only for requests from the configured trusted proxies, so a caller cannot spoof it by sending X-Forwarded-For.
 */
final class ClientAddress {

    private ClientAddress() {
    }

    static String of(HttpServletRequest request) {
        String a = request.getRemoteAddr();
        return a == null ? "unknown" : a;
    }
}
