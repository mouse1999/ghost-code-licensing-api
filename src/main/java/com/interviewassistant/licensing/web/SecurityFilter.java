package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.service.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * First filter in the chain: HTTPS enforcement, security response headers and the request-size cap.
 *
 * <ul>
 *   <li>HTTPS: when {@code licensing.security.require-https} is on, a request that did not arrive over TLS (after the reverse
 *       proxy's {@code X-Forwarded-Proto} has been applied by the container) is refused. The health probe is exempt so a
 *       load balancer can check the process.</li>
 *   <li>Size: a declared Content-Length above the cap is refused at once; a body without a length (chunked) is counted as it
 *       is read and aborted when it passes the cap.</li>
 *   <li>CORS is not configured anywhere, so browsers get no cross-origin permission. No cookies or sessions are used.</li>
 * </ul>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class SecurityFilter extends OncePerRequestFilter {

    private final LicensingProperties props;

    SecurityFilter(LicensingProperties props) {
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");

        boolean health = request.getRequestURI().startsWith("/actuator/health");
        if (request.isSecure()) {
            response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        } else if (props.security().requireHttps() && !health) {
            ErrorWriter.write(response, ErrorCode.HTTPS_REQUIRED, ErrorCode.HTTPS_REQUIRED.defaultMessage(), 0);
            return;
        }
        int max = props.security().maxBodyBytes();
        if (request.getContentLengthLong() > max) {
            ErrorWriter.write(response, ErrorCode.PAYLOAD_TOO_LARGE, ErrorCode.PAYLOAD_TOO_LARGE.defaultMessage(), 0);
            return;
        }
        chain.doFilter(new LimitedRequest(request, max), response);
    }

    /** Thrown from the body stream when a chunked body passes the cap; the exception handler maps it to 413. */
    static final class BodyTooLargeException extends IOException {
        private static final long serialVersionUID = 1L;

        BodyTooLargeException() {
            super("request body too large");
        }
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final int max;
        private ServletInputStream stream;

        LimitedRequest(HttpServletRequest request, int max) {
            super(request);
            this.max = max;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new CountingStream(super.getInputStream(), max);
            }
            return stream;
        }
    }

    private static final class CountingStream extends ServletInputStream {
        private final ServletInputStream in;
        private final int max;
        private long count;

        CountingStream(ServletInputStream in, int max) {
            this.in = in;
            this.max = max;
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            if (b >= 0 && ++count > max) {
                throw new BodyTooLargeException();
            }
            return b;
        }

        @Override
        public int read(byte[] buf, int off, int len) throws IOException {
            int n = in.read(buf, off, len);
            if (n > 0) {
                count += n;
                if (count > max) {
                    throw new BodyTooLargeException();
                }
            }
            return n;
        }

        @Override
        public boolean isFinished() {
            return in.isFinished();
        }

        @Override
        public boolean isReady() {
            return in.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            in.setReadListener(listener);
        }
    }
}
