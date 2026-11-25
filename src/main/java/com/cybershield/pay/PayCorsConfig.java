package com.cybershield.pay;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;

/**
 * Configures CORS for /api/pay/** using the CORS_ALLOWED_ORIGIN env var.
 */
@Configuration
public class PayCorsConfig implements WebMvcConfigurer {

    private final String allowedOriginConfig;

    public PayCorsConfig(@Value("${cybershield.pay.cors-allowed-origin:}") String allowedOriginConfig) {
        this.allowedOriginConfig = allowedOriginConfig == null ? "" : allowedOriginConfig.trim();
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        if (allowedOriginConfig.isEmpty()) {
            return;
        }
        String[] origins = Arrays.stream(allowedOriginConfig.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);
        if (origins.length == 0) {
            return;
        }
        registry.addMapping("/api/pay/**")
                .allowedOriginPatterns(origins)
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("Content-Type", "Accept");
    }
}

