package com.interviewassistant.licensing.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;

/**
 * Serves the administrator portal: three fixed static files (page, style, script). The files contain no data and no secret, so
 * they are public like any login page; every call the page makes goes to {@code /api/v1/admin/**}, which
 * {@link AdminAuthFilter} protects. The page is served with its own strict Content-Security-Policy (same-origin scripts and styles
 * only, no inline code, no framing, no form posts), replacing the API's blanket {@code default-src 'none'}.
 *
 * <p>Only these three exact paths exist; there is no directory serving, so nothing else on the classpath can be reached.
 */
@RestController
class PortalController {

    static final String PORTAL_CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
            + "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

    @GetMapping({"/admin", "/admin/"})
    ResponseEntity<byte[]> page(HttpServletResponse response) throws IOException {
        return serve("portal/index.html", MediaType.TEXT_HTML, response);
    }

    @GetMapping("/admin/portal.css")
    ResponseEntity<byte[]> css(HttpServletResponse response) throws IOException {
        return serve("portal/portal.css", MediaType.valueOf("text/css"), response);
    }

    @GetMapping("/admin/portal.js")
    ResponseEntity<byte[]> js(HttpServletResponse response) throws IOException {
        return serve("portal/portal.js", MediaType.valueOf("text/javascript"), response);
    }

    private static ResponseEntity<byte[]> serve(String path, MediaType type, HttpServletResponse response) throws IOException {
        try (InputStream in = new ClassPathResource(path).getInputStream()) {
            byte[] body = in.readAllBytes();
            response.setHeader("Content-Security-Policy", PORTAL_CSP);   // replaces the blanket policy set by SecurityFilter
            return ResponseEntity.ok().contentType(new MediaType(type, java.util.Map.of("charset", "utf-8"))).body(body);
        }
    }
}
