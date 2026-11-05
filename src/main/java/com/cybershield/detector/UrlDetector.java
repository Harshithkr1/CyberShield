package com.cybershield.detector;

import com.cybershield.config.Brand;
import com.cybershield.config.RulesConfig;
import com.cybershield.config.SignalWeights;
import com.cybershield.model.Signal;
import com.cybershield.util.Levenshtein;
import com.cybershield.util.UrlExtractor;
import com.cybershield.util.UrlExtractor.UrlMatch;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects suspicious URL patterns in submitted text.
 *
 * <h2>Checks performed (per URL)</h2>
 * <ol>
 * <li><b>Raw IP host</b> — host is a dotted-decimal IPv4 address.</li>
 * <li><b>Punycode / homograph</b> — any label starts with {@code xn--} or
 * the raw URL contains non-ASCII characters (Unicode lookalikes).</li>
 * <li><b>@ in URL / excessive subdomains</b> — {@code @} present in authority
 * or the host has 3+ subdomain levels.</li>
 * <li><b>URL shortener</b> — host matches a known shortener from
 * {@code rules.json}.</li>
 * <li><b>Suspicious TLD</b> — host ends with a flagged TLD.</li>
 * <li><b>No HTTPS</b> — scheme is plain {@code http}.</li>
 * <li><b>Brand impersonation</b> — a brand keyword appears in a subdomain or
 * path but the registrable domain is not an official brand domain.</li>
 * <li><b>Levenshtein typosquatting</b> — the registrable domain is within
 * edit-distance 1 (high risk) or 2 (medium risk) of a brand canonical
 * domain root, but is not that domain.</li>
 * <li><b>Suspicious URL keywords</b> — the URL contains keywords such as
 * {@code login}, {@code verify}, {@code kyc}, {@code otp}, etc.</li>
 * <li><b>Very long URL</b> — total URL length ≥ 100 characters.</li>
 * <li><b>Many hyphens in host</b> — the host segment contains 3+ hyphens.</li>
 * <li><b>Port in URL</b> — URL specifies a non-standard port.</li>
 * <li><b>Double scheme</b> — URL contains nested scheme indicators.</li>
 * </ol>
 *
 * <p>
 * <strong>Safety guarantee:</strong> URLs are parsed with
 * {@link URI#create(String)} in a try/catch and are <em>never</em> fetched,
 * resolved, or connected to.
 * </p>
 */
@Component
public class UrlDetector implements Detector {

    // ── Constants ─────────────────────────────────────────────────────────────

    static final String CATEGORY = "URL";

    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^(\\d{1,3}\\.){3}\\d{1,3}$");

    private static final Pattern PUNYCODE_LABEL = Pattern.compile(
            "(?i)\\bxn--");

    // Matches any code point outside Basic Latin (U+0080 and above)
    private static final Pattern NON_ASCII = Pattern.compile("[^\\x00-\\x7F]");

    private static final Pattern DOUBLE_SCHEME = Pattern.compile(
            "(?i)https?://.*https?://");

    private static final int LONG_URL_THRESHOLD = 100;
    private static final int MANY_HYPHENS_THRESHOLD = 3;
    private static final int EXCESSIVE_SUBDOMAINS = 3; // host labels > this → signal
    private static final int TYPO_DIST_HIGH = 1;
    private static final int TYPO_DIST_MEDIUM = 2;
    private static final int MIN_BRAND_ROOT_LEN = 5; // skip short roots (e.g. "pay", "dhl") to avoid noise in path
                                                     // checks
    // Standard HTTP(S) ports — others are flagged
    private static final Set<Integer> STANDARD_PORTS = Set.of(80, 443, 8080, 8443);

    // ── State ────────────────────────────────────────────────────────────────

    private final RulesConfig rules;

    public UrlDetector(RulesConfig rules) {
        this.rules = rules;
    }

    // ── Detector contract ─────────────────────────────────────────────────────

    @Override
    public String name() {
        return "UrlDetector";
    }

    @Override
    public List<Signal> detect(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        List<Signal> signals = new ArrayList<>();

        for (UrlMatch match : UrlExtractor.extractWithOffsets(text)) {
            signals.addAll(analyseUrl(match, text));
        }

        return Collections.unmodifiableList(signals);
    }

    // ── Per-URL analysis ──────────────────────────────────────────────────────

    private List<Signal> analyseUrl(UrlMatch match, String fullText) {
        String rawUrl = match.url();
        int urlStart = match.start();

        // Ensure it has a scheme for URI parsing; bare www.* domains get https://
        // prepended
        String parseableUrl = rawUrl.startsWith("http") ? rawUrl : "https://" + rawUrl;

        URI uri;
        try {
            // Encode spaces and non-ASCII before parsing; never connect
            String sanitised = encodeForUri(parseableUrl);
            uri = new URI(sanitised);
        } catch (Exception e) {
            // Unparseable URL – emit a low-weight signal noting the issue
            return List.of(signal("url.unparseable", 2,
                    "URL could not be parsed safely: " + e.getMessage(),
                    rawUrl, urlStart, match.end()));
        }

        List<Signal> signals = new ArrayList<>();
        SignalWeights w = rules.getSignalWeights();

        String host = uri.getHost() != null ? uri.getHost().toLowerCase(Locale.ROOT) : "";
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase(Locale.ROOT) : "";
        String path = uri.getPath() != null ? uri.getPath().toLowerCase(Locale.ROOT) : "";
        String rawAuthority = uri.getRawAuthority() != null ? uri.getRawAuthority() : "";
        int port = uri.getPort(); // -1 if not present

        // 1. Double scheme
        if (DOUBLE_SCHEME.matcher(rawUrl).find()) {
            signals.add(signal("url.doubleScheme", w.getUrlDoubleScheme(),
                    "URL contains a nested scheme (e.g. http://...http://) which is a phishing technique.",
                    rawUrl, urlStart, match.end()));
        }

        // 2. Non-ASCII / Unicode lookalike characters in URL
        if (NON_ASCII.matcher(rawUrl).find()) {
            signals.add(signal("url.homograph", 18,
                    "URL contains non-ASCII characters that may be visual lookalikes (homograph attack).",
                    rawUrl, urlStart, match.end()));
        } else if (host.contains("xn--") || PUNYCODE_LABEL.matcher(rawUrl).find()) {
            // Punycode in the original URL (after ASCII encoding it may not appear)
            signals.add(signal("url.punycode", 15,
                    "URL uses punycode (xn--) labels that may disguise lookalike domain names.",
                    rawUrl, urlStart, match.end()));
        }

        // 3. @ in URL or excessive subdomains
        if (rawAuthority.contains("@")) {
            signals.add(signal("url.atSymbol", w.getUrlAtSymbol(),
                    "URL contains '@' in the authority section, which is a classic phishing trick to disguise the real host.",
                    rawUrl, urlStart, match.end()));
        }

        if (!host.isEmpty()) {
            String[] labels = host.split("\\.");
            if (labels.length > EXCESSIVE_SUBDOMAINS) {
                signals.add(signal("url.excessiveSubdomains", w.getUrlExcessiveSubdomains(),
                        "URL has " + labels.length + " host labels, suggesting a deceptive subdomain structure.",
                        rawUrl, urlStart, match.end()));
            }
        }

        // 4. Raw IPv4 host
        if (!host.isEmpty() && IPV4_PATTERN.matcher(host).matches()) {
            signals.add(signal("url.ipAddress", w.getUrlIpAddress(),
                    "URL uses a raw IP address as host rather than a domain name — a common phishing indicator.",
                    rawUrl, urlStart, match.end()));
        }

        // 5. Port in URL
        if (port != -1 && !STANDARD_PORTS.contains(port)) {
            signals.add(signal("url.portInUrl", w.getUrlPortInUrl(),
                    "URL specifies a non-standard port (" + port + "), which may indicate a malicious server.",
                    rawUrl, urlStart, match.end()));
        }

        // 6. URL shortener
        if (isShortener(host)) {
            signals.add(signal("url.shortener", w.getUrlShortener(),
                    "URL uses a known link-shortening service (" + host + ") that hides the real destination.",
                    rawUrl, urlStart, match.end()));
            // Shorteners: skip further host-based checks since we can't see the destination
            return Collections.unmodifiableList(signals);
        }

        // 7. Suspicious TLD
        String suspiciousTld = matchSuspiciousTld(host);
        if (suspiciousTld != null) {
            signals.add(signal("url.suspiciousTld", w.getUrlSuspiciousTld(),
                    "URL uses the suspicious top-level domain '" + suspiciousTld + "'.",
                    rawUrl, urlStart, match.end()));
        }

        // 8. No HTTPS
        if ("http".equals(scheme)) {
            signals.add(signal("url.noHttps", 6,
                    "URL uses plain HTTP rather than HTTPS, leaving data unencrypted.",
                    rawUrl, urlStart, match.end()));
        }

        // 9. Brand impersonation + 10. Levenshtein typosquatting
        // (these require knowing the registrable domain so compute once)
        String registrable = registrableDomain(host);

        brandAndTypoChecks(rawUrl, urlStart, match.end(), host, path, registrable, signals, w);

        // 11. Suspicious URL keywords
        String urlLower = rawUrl.toLowerCase(Locale.ROOT);
        List<String> hitKeywords = new ArrayList<>();
        for (String kw : rules.getUrlKeywords()) {
            if (urlLower.contains(kw.toLowerCase(Locale.ROOT))) {
                hitKeywords.add(kw);
            }
        }
        if (!hitKeywords.isEmpty()) {
            signals.add(signal("url.keyword", w.getUrlKeyword(),
                    "URL contains suspicious keyword(s): " + String.join(", ", hitKeywords) + ".",
                    rawUrl, urlStart, match.end()));
        }

        // 12. Very long URL
        if (rawUrl.length() >= LONG_URL_THRESHOLD) {
            signals.add(signal("url.longUrl", 5,
                    "URL is unusually long (" + rawUrl.length() + " chars), which may indicate obfuscation.",
                    rawUrl, urlStart, match.end()));
        }

        // 13. Many hyphens in host
        long hyphenCount = host.chars().filter(c -> c == '-').count();
        if (hyphenCount >= MANY_HYPHENS_THRESHOLD) {
            signals.add(signal("url.manyHyphens", 7,
                    "URL host contains " + hyphenCount + " hyphens, a pattern common in phishing domains.",
                    rawUrl, urlStart, match.end()));
        }

        return Collections.unmodifiableList(signals);
    }

    // ── Brand impersonation & typosquatting ───────────────────────────────────

    private void brandAndTypoChecks(
            String rawUrl, int urlStart, int urlEnd,
            String host, String path, String registrable,
            List<Signal> signals, SignalWeights w) {

        if (registrable.isEmpty())
            return;

        // Extract the SLD part (first label of registrable domain, e.g. "hdfc" from
        // "hdfc.co")
        String sld = registrable.contains(".") ? registrable.split("\\.")[0] : registrable;

        for (Brand brand : rules.getBrands()) {
            for (String officialDomain : brand.officialDomains()) {
                // Derive the official SLD (registrable root without TLD)
                String officialRoot = domainRoot(officialDomain);

                // --- Levenshtein typosquatting first (before impersonation check) ---
                // This fires when the registrable domain itself closely resembles a brand
                // domain.
                // Only meaningful for roots of 3+ chars (shorter roots produce too many false
                // positives).
                if (officialRoot.length() >= 3
                        && !sld.equals(officialRoot)
                        && !brand.isOfficialDomain(registrable)) {
                    int dist = Levenshtein.distanceIgnoreCase(sld, officialRoot);
                    if (dist == TYPO_DIST_HIGH) {
                        signals.add(signal("url.typosquatLev1", w.getUrlTyposquatLevenshtein1(),
                                "Domain '" + sld + "' is 1 edit away from '" + officialRoot
                                        + "' (" + brand.name() + ") — likely typosquatting.",
                                rawUrl, urlStart, urlEnd));
                        return;
                    } else if (dist == TYPO_DIST_MEDIUM) {
                        signals.add(signal("url.typosquatLev2", w.getUrlTyposquatLevenshtein2(),
                                "Domain '" + sld + "' is 2 edits away from '" + officialRoot
                                        + "' (" + brand.name() + ") — possible typosquatting.",
                                rawUrl, urlStart, urlEnd));
                        return;
                    }
                }

                // --- Brand impersonation: brand keyword in subdomain or path ---
                // Only fire when the registrable domain is NOT already an official brand
                // domain.
                if (brand.isOfficialDomain(registrable) || brand.isOfficialDomain(host))
                    continue;

                // Subdomain check: any label in the host exactly equals the brand root (any
                // length ≥ 2)
                boolean brandInSubdomain = officialRoot.length() >= 2
                        && containsWholeLabel(host, officialRoot);

                // Path check: restrict to roots ≥ MIN_BRAND_ROOT_LEN to avoid noise ("pay",
                // "dhl", etc.)
                boolean brandInPath = officialRoot.length() >= MIN_BRAND_ROOT_LEN
                        && containsWholePathSegment(path, officialRoot);

                if (brandInSubdomain || brandInPath) {
                    String where = brandInSubdomain ? "subdomain" : "path";
                    signals.add(signal("url.brandImpersonation", 22,
                            "URL contains brand name '" + brand.name()
                                    + "' in the " + where + " but the registrable domain '"
                                    + registrable + "' is not an official " + brand.name() + " domain.",
                            rawUrl, urlStart, urlEnd));
                    return; // One impersonation signal per URL is enough
                }
            }
        }
    }

    /**
     * Returns true if {@code label} appears as a complete dot-separated host label
     * in {@code host}.
     * E.g. "sbi" matches "sbi.fake.com" (label "sbi") but not "onlinesbi.com"
     * (label "onlinesbi").
     */
    private static boolean containsWholeLabel(String host, String label) {
        String[] parts = host.split("\\.");
        for (String part : parts) {
            if (part.equalsIgnoreCase(label))
                return true;
        }
        return false;
    }

    /**
     * Returns true if {@code segment} appears as a complete slash-separated path
     * segment.
     * E.g. "paytm" matches "/paytm/wallet" but not "/paytmlite/".
     */
    private static boolean containsWholePathSegment(String path, String segment) {
        String[] parts = path.split("[/\\-_]");
        for (String part : parts) {
            if (part.equalsIgnoreCase(segment))
                return true;
        }
        return false;
    }

    // ── Domain helpers ────────────────────────────────────────────────────────

    /**
     * Derive the "registrable domain" from a host, i.e. the last two labels
     * (e.g. "evil.com" from "secure.kyc.evil.com") or three labels for
     * known two-part ccTLDs like .co.in, .co.uk, .com.au.
     */
    static String registrableDomain(String host) {
        if (host == null || host.isEmpty())
            return "";
        String[] labels = host.split("\\.");
        if (labels.length == 0)
            return "";
        if (labels.length == 1)
            return labels[0];

        // Known two-part ccTLD second-level: co, net, org, gov, ac, edu, com
        String last = labels[labels.length - 1];
        String secondLast = labels[labels.length - 2];
        boolean twoPartCcTld = secondLast.matches("co|net|org|gov|ac|edu|com|res|nic|mil")
                && last.length() == 2; // heuristic: ccTLD is 2 chars (in, uk, au, etc.)

        if (twoPartCcTld && labels.length >= 3) {
            return labels[labels.length - 3] + "." + secondLast + "." + last;
        }
        return secondLast + "." + last;
    }

    /**
     * Return the SLD portion of a domain (everything before the final dot-TLD
     * segment).
     * E.g. "hdfcbank.com" → "hdfcbank", "sbi.co.in" → "sbi".
     */
    private static String domainRoot(String officialDomain) {
        String[] parts = officialDomain.split("\\.");
        if (parts.length == 0)
            return officialDomain;
        // Take first part: for "sbi.co.in" → "sbi"; "onlinesbi.sbi" → "onlinesbi"
        return parts[0].toLowerCase(Locale.ROOT);
    }

    // ── Rules helpers ─────────────────────────────────────────────────────────

    private boolean isShortener(String host) {
        if (host.isEmpty())
            return false;
        for (String s : rules.getUrlShorteners()) {
            if (host.equals(s) || host.endsWith("." + s))
                return true;
        }
        return false;
    }

    private String matchSuspiciousTld(String host) {
        if (host.isEmpty())
            return null;
        for (String tld : rules.getSuspiciousTlds()) {
            // tld entries are like ".xyz", ".top" — match end of host
            if (host.endsWith(tld.startsWith(".") ? tld : "." + tld)) {
                return tld;
            }
        }
        return null;
    }

    // ── URI encoding helper ───────────────────────────────────────────────────

    /**
     * Percent-encode non-ASCII bytes so that {@link URI} can parse the string
     * without throwing. This does <em>not</em> normalise the URL; it only
     * makes the raw string syntactically parseable.
     *
     * <p>
     * The connection is never opened.
     * </p>
     */
    private static String encodeForUri(String url) {
        StringBuilder sb = new StringBuilder(url.length());
        for (char c : url.toCharArray()) {
            if (c > 0x7F) {
                byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                for (byte b : bytes) {
                    sb.append(String.format("%%%02X", b & 0xFF));
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    // ── Signal factory ────────────────────────────────────────────────────────

    private static Signal signal(String id, int points, String explanation,
            String matchedText, int start, int end) {
        return Signal.builder()
                .id(id)
                .category(CATEGORY)
                .points(points)
                .explanation(explanation)
                .matchedText(matchedText)
                .start(start)
                .end(end)
                .build();
    }
}
