package com.interviewassistant.licensing.web;

import com.interviewassistant.licensing.security.AdminAuthenticator;
import com.interviewassistant.licensing.security.AdminPrincipal;
import com.interviewassistant.licensing.security.RateLimiter;
import com.interviewassistant.licensing.service.ErrorCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Deny-by-default gate for everything under {@code /api/v1/admin/}: no controller code runs without a valid administrator
 * token. Because the gate is a path-prefix filter, a new admin endpoint is protected automatically, and forgetting an
 * annotation cannot expose it. Per-endpoint authorisation (scopes) is then checked in the services.
 *
 * <p>Failed attempts are counted per client address; after the limit the client gets 429 until the window passes. The token
 * itself is never logged.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
class AdminAuthFilter extends OncePerRequestFilter {

    static final String PRINCIPAL_ATTRIBUTE = AdminAuthFilter.class.getName() + ".principal";
    private static final System.Logger LOG = System.getLogger(AdminAuthFilter.class.getName());

    private final AdminAuthenticator authenticator;
    private final RateLimiter failureLimiter;

    AdminAuthFilter(AdminAuthenticator authenticator, RateLimiter adminAuthFailureLimiter) {
        this.authenticator = authenticator;
        this.failureLimiter = adminAuthFailureLimiter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.equals("/api/v1/admin") || path.startsWith("/api/v1/admin/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String client = ClientAddress.of(request);
        if (failureLimiter.isExhausted(client)) {
            ErrorWriter.write(response, ErrorCode.RATE_LIMITED, ErrorCode.RATE_LIMITED.defaultMessage(),
                    failureLimiter.retryAfterSeconds(client));
            return;
        }
        AdminPrincipal principal = authenticator.authenticate(request.getHeader("Authorization")).orElse(null);
        if (principal == null) {
            failureLimiter.record(client);
            LOG.log(System.Logger.Level.WARNING, "rejected unauthenticated admin request to {0}", request.getRequestURI());
            ErrorWriter.write(response, ErrorCode.UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED.defaultMessage(), 0);
            return;
        }
        request.setAttribute(PRINCIPAL_ATTRIBUTE, principal);
        chain.doFilter(request, response);
    }
}
