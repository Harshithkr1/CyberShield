package com.cybershield.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stateless utility for extracting raw URL strings from free text.
 *
 * <p>Uses a broad regex to capture http/https URLs including encoded characters,
 * IPv4 addresses, ports, and bare www.* domains. The caller is responsible for
 * all further parsing; this class <strong>never</strong> opens or fetches a URL.</p>
 *
 * <p>The extractor preserves the start/end character offsets of every match so
 * that detectors can produce accurate {@code Signal.start / Signal.end} values.</p>
 */
public final class UrlExtractor {

    /**
     * Matches http(s):// URLs.
     * <ul>
     *   <li>Handles IPv4 hosts (192.168.1.1)</li>
     *   <li>Handles ports (:8080)</li>
     *   <li>Handles paths, query strings, fragments</li>
     *   <li>Handles @ in authority section (user@host)</li>
     *   <li>Handles punycode (xn--) IDN labels</li>
     *   <li>Handles percent-encoded chars</li>
     * </ul>
     */
    private static final Pattern HTTP_URL = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+",
            Pattern.CASE_INSENSITIVE
    );

    /**
     * Matches bare hostnames without a scheme, e.g. {@code www.evil.com/page}.
     * Requires a {@code www.} prefix to avoid too many false positives.
     */
    private static final Pattern BARE_DOMAIN = Pattern.compile(
            "\\b(?:www\\.)[\\w\\-]+(?:\\.[a-zA-Z]{2,})+(?:[/?#][^\\s]*)?",
            Pattern.CASE_INSENSITIVE
    );

    private UrlExtractor() {}

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Extract all URL-like strings from {@code text} (deduplicated, encounter order).
     *
     * @param text input (not null)
     * @return unmodifiable list of URL strings
     */
    public static List<String> extract(String text) {
        List<UrlMatch> matches = extractWithOffsets(text);
        List<String> result = new ArrayList<>(matches.size());
        for (UrlMatch m : matches) result.add(m.url());
        return List.copyOf(result);
    }

    /**
     * Extract all URL-like strings together with their character offsets in {@code text}.
     * Duplicate URLs are collapsed to their first occurrence.
     *
     * @param text input (not null)
     * @return unmodifiable list of {@link UrlMatch} in encounter order
     */
    public static List<UrlMatch> extractWithOffsets(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        // LinkedHashMap preserves encounter order and de-duplicates by URL string
        Map<String, UrlMatch> seen = new LinkedHashMap<>();

        Matcher m1 = HTTP_URL.matcher(text);
        while (m1.find()) {
            String url = trimTrailingPunct(m1.group());
            seen.putIfAbsent(url, new UrlMatch(url, m1.start(), m1.start() + url.length()));
        }

        Matcher m2 = BARE_DOMAIN.matcher(text);
        while (m2.find()) {
            String url = trimTrailingPunct(m2.group());
            seen.putIfAbsent(url, new UrlMatch(url, m2.start(), m2.start() + url.length()));
        }

        return List.copyOf(seen.values());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Strip trailing punctuation characters that are often attached to a URL in prose
     * (e.g. a period at the end of a sentence, or a closing parenthesis).
     */
    private static String trimTrailingPunct(String url) {
        // Remove trailing ), ], >, ., , characters that are unlikely part of the URL
        return url.replaceAll("[)\\]>.,'\"]+$", "");
    }

    // ── Value type ────────────────────────────────────────────────────────────

    /**
     * A URL extracted from text together with its character-offset span.
     *
     * @param url   the extracted URL string
     * @param start inclusive start offset in the source text
     * @param end   exclusive end offset in the source text
     */
    public record UrlMatch(String url, int start, int end) {}
}
