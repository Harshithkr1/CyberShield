package com.cybershield.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link UrlExtractor} and {@link Levenshtein}.
 */
class UtilTest {

    // ── UrlExtractor ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("Extracts http URL from plain text")
    void extractHttpUrl() {
        List<String> urls = UrlExtractor.extract("Click here: http://example.com/path?q=1");
        assertTrue(urls.stream().anyMatch(u -> u.startsWith("http://example.com")));
    }

    @Test
    @DisplayName("Extracts https URL")
    void extractHttpsUrl() {
        List<String> urls = UrlExtractor.extract("Visit https://secure.bank.com now");
        assertEquals(1, urls.size());
        assertTrue(urls.get(0).startsWith("https://secure.bank.com"));
    }

    @Test
    @DisplayName("Extracts bare www. domain")
    void extractBareDomain() {
        List<String> urls = UrlExtractor.extract("Go to www.example.com for more info");
        assertFalse(urls.isEmpty());
    }

    @Test
    @DisplayName("Returns empty list for text without URLs")
    void noUrls_returnsEmpty() {
        List<String> urls = UrlExtractor.extract("Hello world, no links here.");
        assertTrue(urls.isEmpty());
    }

    @Test
    @DisplayName("Deduplicates repeated URLs")
    void deduplicatesUrls() {
        List<String> urls = UrlExtractor.extract("http://x.com http://x.com http://x.com");
        assertEquals(1, urls.size());
    }

    // ── Levenshtein ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("Identical strings have distance 0")
    void levenshtein_identical() {
        assertEquals(0, Levenshtein.distance("paypal", "paypal"));
    }

    @Test
    @DisplayName("Single substitution has distance 1")
    void levenshtein_singleSub() {
        assertEquals(1, Levenshtein.distance("paypal", "paypa1"));
    }

    @Test
    @DisplayName("Empty string vs non-empty equals length")
    void levenshtein_emptyVsWord() {
        assertEquals(6, Levenshtein.distance("", "paypal"));
    }

    @Test
    @DisplayName("Case-insensitive distance works")
    void levenshtein_caseInsensitive() {
        assertEquals(0, Levenshtein.distanceIgnoreCase("PayPal", "paypal"));
    }
}
