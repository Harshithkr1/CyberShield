package com.cybershield.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Adds essential standard security headers to all HTTP responses:
 * <ul>
 *   <li>Content-Security-Policy: restricts script, style, font, and image origins</li>
 *   <li>X-Content-Type-Options: nosniff prevents MIME type sniffing</li>
 *   <li>Referrer-Policy: strict-origin-when-cross-origin</li>
 *   <li>X-Frame-Options: DENY prevents clickjacking</li>
 * </ul>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityHeadersFilter implements Filter {

    public static final String CSP_POLICY =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
            "font-src 'self' https://fonts.gstatic.com; " +
            "img-src 'self' data:; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "base-uri 'self'; " +
            "form-action 'self'";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (response instanceof HttpServletResponse httpRes) {
            httpRes.setHeader("Content-Security-Policy", CSP_POLICY);
            httpRes.setHeader("X-Content-Type-Options", "nosniff");
            httpRes.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
            httpRes.setHeader("X-Frame-Options", "DENY");
        }
        chain.doFilter(request, response);
    }
}

