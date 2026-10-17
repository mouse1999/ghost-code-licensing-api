package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.service.ErrorCode;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Writes the error body from inside servlet filters, where Spring's message converters are not available. */
final class ErrorWriter {

    private ErrorWriter() {
    }

    static void write(HttpServletResponse response, ErrorCode code, String message, long retryAfterSeconds) throws IOException {
        response.setStatus(code.httpStatus());
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        if (retryAfterSeconds > 0) {
            response.setHeader("Retry-After", Long.toString(retryAfterSeconds));
        }
        if (code == ErrorCode.UNAUTHENTICATED) {
            response.setHeader("WWW-Authenticate", "Bearer");
        }
        String json = "{\"code\":\"" + code.name() + "\",\"message\":\"" + message.replace("\\", "\\\\").replace("\"", "\\\"") + "\"}";
        response.getWriter().write(json);
    }
}
