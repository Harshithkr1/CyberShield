package com.cybershield.ml;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Extracts the 9 features used for malicious URL classification,
 * strictly matching {@code ml/train_url.py}.
 *
 * <p>Features:
 * <ol>
 *   <li>url_length: total character length</li>
 *   <li>dot_count: count of '.' in URL</li>
 *   <li>hyphen_count: count of '-' in URL</li>
 *   <li>digit_count: count of numeric digits in URL</li>
 *   <li>entropy: Shannon entropy of character distribution</li>
 *   <li>has_ip_host: 1.0 if host is an IPv4 address, else 0.0</li>
 *   <li>suspicious_tld: 1.0 if TLD is in known high-risk abuse list, else 0.0</li>
 *   <li>uses_https: 1.0 if URL starts with "https://", else 0.0</li>
 *   <li>subdomain_count: count of subdomains excluding domain and SLD/TLD</li>
 * </ol>
 */
@Component
public class UrlFeatureExtractor {

    public static final List<String> FEATURE_NAMES = List.of(
            "url_length",
            "dot_count",
            "hyphen_count",
            "digit_count",
            "entropy",
            "has_ip_host",
            "suspicious_tld",
            "uses_https",
            "subdomain_count"
    );

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "xyz", "top", "club", "site", "online", "work", "click", "buzz",
            "rest", "fit", "gq", "cf", "ga", "ml", "tk", "cc", "icu", "fun", "live", "vip"
    );

    private static final Set<String> MULTI_PART_TLDS = Set.of(
            "co", "gov", "org", "net", "ac", "res", "gen"
    );

    private static final Pattern IP_PATTERN = Pattern.compile("^(\\d{1,3}\\.){3}\\d{1,3}$");

    /**
     * Extracts raw 9-element feature vector from the given URL.
     *
     * @param url input URL string
     * @return double[9] matching FEATURE_NAMES in exact order
     */
    public double[] extractFeatures(String url) {
        String rawUrl = (url == null) ? "" : url.trim();
        String urlLower = rawUrl.toLowerCase(Locale.ROOT);

        // 1. url_length
        double urlLength = (double) rawUrl.length();

        // 2. dot_count
        double dotCount = 0.0;
        for (int i = 0; i < rawUrl.length(); i++) {
            if (rawUrl.charAt(i) == '.') dotCount++;
        }

        // 3. hyphen_count
        double hyphenCount = 0.0;
        for (int i = 0; i < rawUrl.length(); i++) {
            if (rawUrl.charAt(i) == '-') hyphenCount++;
        }

        // 4. digit_count
        double digitCount = 0.0;
        for (int i = 0; i < rawUrl.length(); i++) {
            if (Character.isDigit(rawUrl.charAt(i))) digitCount++;
        }

        // 5. entropy
        double entropy = calculateEntropy(rawUrl);

        // Parse host matching urllib.parse.urlparse
        String host = extractHost(rawUrl);

        // 6. has_ip_host
        double isIp = IP_PATTERN.matcher(host).matches() ? 1.0 : 0.0;

        // 7. suspicious_tld
        String tld = "";
        int lastDot = host.lastIndexOf('.');
        if (lastDot >= 0 && lastDot < host.length() - 1) {
            tld = host.substring(lastDot + 1);
        }
        double suspiciousTld = SUSPICIOUS_TLDS.contains(tld) ? 1.0 : 0.0;

        // 8. uses_https
        double usesHttps = urlLower.startsWith("https://") ? 1.0 : 0.0;

        // 9. subdomain_count
        String[] split = host.split("\\.");
        List<String> hostParts = new ArrayList<>();
        for (String p : split) {
            if (!p.isEmpty()) hostParts.add(p);
        }

        double subdomainCount;
        if (hostParts.size() >= 3 && MULTI_PART_TLDS.contains(hostParts.get(hostParts.size() - 2))) {
            subdomainCount = (double) Math.max(0, hostParts.size() - 3);
        } else {
            subdomainCount = (double) Math.max(0, hostParts.size() - 2);
        }

        return new double[] {
                urlLength,
                dotCount,
                hyphenCount,
                digitCount,
                entropy,
                isIp,
                suspiciousTld,
                usesHttps,
                subdomainCount
        };
    }

    /**
     * Scales raw features using StandardScaler parameters (means and stds).
     *
     * @param raw   unscaled feature values
     * @param means training set means
     * @param stds  training set standard deviations
     * @return scaled features: z_i = (x_i - mean_i) / std_i
     */
    public double[] scaleFeatures(double[] raw, double[] means, double[] stds) {
        if (raw.length != means.length || raw.length != stds.length) {
            throw new IllegalArgumentException("Feature vector length does not match scaler dimensions");
        }
        double[] scaled = new double[raw.length];
        for (int i = 0; i < raw.length; i++) {
            scaled[i] = (raw[i] - means[i]) / stds[i];
        }
        return scaled;
    }

    /**
     * Calculates Shannon entropy: -sum(p * log2(p)).
     */
    public static double calculateEntropy(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }
        int length = text.length();
        Map<Character, Integer> counts = new HashMap<>();
        for (int i = 0; i < length; i++) {
            char c = text.charAt(i);
            counts.put(c, counts.getOrDefault(c, 0) + 1);
        }
        double entropy = 0.0;
        for (int count : counts.values()) {
            double p = (double) count / length;
            entropy -= p * (Math.log(p) / Math.log(2.0));
        }
        return entropy;
    }

    /**
     * Extracts host name replicating Python {@code urllib.parse.urlparse}.
     */
    public static String extractHost(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "";
        }
        String u = rawUrl;
        int schemeIdx = u.indexOf("://");
        if (schemeIdx != -1) {
            u = u.substring(schemeIdx + 3);
        }
        // Take part before next '/', '?', or '#'
        int end = u.length();
        for (int i = 0; i < u.length(); i++) {
            char c = u.charAt(i);
            if (c == '/' || c == '?' || c == '#') {
                end = i;
                break;
            }
        }
        String netloc = u.substring(0, end);
        // If port present, strip port
        int colon = netloc.indexOf(':');
        if (colon != -1) {
            netloc = netloc.substring(0, colon);
        }
        return netloc.toLowerCase(Locale.ROOT);
    }
}

