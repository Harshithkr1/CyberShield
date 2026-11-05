package com.cybershield.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * Loads detection rules, brand lists, phrase patterns, and scoring thresholds
 * from {@code rules.json} into typed classes at application startup.
 *
 * <p>Validates all required data at startup and fails fast with a clear error
 * message if the file is missing, malformed, or incomplete.</p>
 */
@Component
public class RulesConfig {

    private static final Logger log = LoggerFactory.getLogger(RulesConfig.class);

    public static final String DEFAULT_RULES_PATH = "rules.json";

    public static final Set<String> REQUIRED_BRANDS = Set.of(
            "SBI", "HDFC", "ICICI", "Paytm", "PhonePe", "Google Pay",
            "Amazon", "Flipkart", "India Post", "FedEx", "DHL",
            "IRCTC", "Income Tax", "UIDAI"
    );

    private ScoringThresholds scoringThresholds;
    private SignalWeights signalWeights;
    private List<Brand> brands;
    private List<String> urlShorteners;
    private List<String> suspiciousTlds;
    private List<String> freeHostingDomains;
    private List<String> urlKeywords;
    private List<String> phishingPhrases;
    private List<String> digitalArrestPhrases;
    private List<String> maliciousAppPhrases;
    private List<String> urgencyPhrases;
    private List<String> otpSolicitationPhrases;
    private List<String> sensitiveDataPhrases;
    private List<String> prizeBaitPhrases;
    private List<String> kycThreatPhrases;
    private List<String> pressureCtaPhrases;
    private RulesData.MlScoringConfig mlScoring;

    // Fast domain-lookup cache
    private Map<String, Brand> domainToBrandMap = Map.of();

    /**
     * Default no-arg constructor loading {@code rules.json} from classpath.
     */
    public RulesConfig() {
        this(new ObjectMapper(), DEFAULT_RULES_PATH);
    }

    /**
     * Constructor injecting custom ObjectMapper, loading default {@code rules.json}.
     */
    public RulesConfig(ObjectMapper objectMapper) {
        this(objectMapper, DEFAULT_RULES_PATH);
    }

    /**
     * Primary constructor used by Spring or tests with custom rules path.
     */
    @Autowired
    public RulesConfig(
            @Autowired(required = false) ObjectMapper objectMapper,
            @Value("${cybershield.rules.file:" + DEFAULT_RULES_PATH + "}") String rulesPath) {
        ObjectMapper mapper = (objectMapper != null) ? objectMapper : new ObjectMapper();
        loadFromClasspath(mapper, rulesPath);
    }

    /**
     * Factory method to load rules directly from an input stream (useful for tests).
     */
    public static RulesConfig load(InputStream inputStream, ObjectMapper mapper) {
        RulesConfig config = new RulesConfig(mapper, null, false);
        config.loadFromStream(inputStream, mapper != null ? mapper : new ObjectMapper(), "custom-stream");
        return config;
    }

    /**
     * Factory method to load rules directly from a JSON string (useful for tests).
     */
    public static RulesConfig fromJson(String json, ObjectMapper mapper) {
        ObjectMapper m = (mapper != null) ? mapper : new ObjectMapper();
        try {
            RulesData data = m.readValue(json, RulesData.class);
            RulesConfig config = new RulesConfig(m, null, false);
            config.populateAndValidate(data, "inline-json");
            return config;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse rules JSON from inline-json: " + e.getMessage(), e);
        }
    }

    public static RulesConfig fromJson(String json) {
        return fromJson(json, new ObjectMapper());
    }

    private RulesConfig(ObjectMapper mapper, String path, boolean load) {
        if (load) {
            loadFromClasspath(mapper, path);
        }
    }

    private void loadFromClasspath(ObjectMapper mapper, String resourcePath) {
        log.info("Loading Cyber Shield detection rules from classpath: {}", resourcePath);
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = getClass().getClassLoader();
        }

        try (InputStream is = cl.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Rules configuration file not found on classpath: " + resourcePath);
            }
            loadFromStream(is, mapper, resourcePath);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read rules file from " + resourcePath + ": " + e.getMessage(), e);
        }
    }

    private void loadFromStream(InputStream is, ObjectMapper mapper, String sourceName) {
        RulesData data;
        try {
            data = mapper.readValue(is, RulesData.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to parse rules JSON from " + sourceName + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read rules input from " + sourceName + ": " + e.getMessage(), e);
        }

        if (data == null) {
            throw new IllegalStateException("Rules configuration from " + sourceName + " is empty or resolved to null");
        }

        populateAndValidate(data, sourceName);
    }

    private void populateAndValidate(RulesData data, String sourceName) {
        // 1. Scoring Thresholds
        ScoringThresholds thresholds = data.resolveScoringThresholds();
        if (thresholds == null) {
            throw new IllegalStateException(sourceName + " is invalid: scoringThresholds cannot be null");
        }
        try {
            thresholds.validate();
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(sourceName + " is invalid: " + e.getMessage(), e);
        }
        this.scoringThresholds = thresholds;

        // 2. Signal Weights
        SignalWeights weights = data.resolveSignalWeights();
        if (weights == null || weights.isEmpty()) {
            throw new IllegalStateException(sourceName + " is invalid: signalWeights cannot be empty");
        }
        this.signalWeights = weights;

        // 3. Brands
        List<Brand> brandList = data.getBrands();
        if (brandList == null || brandList.isEmpty()) {
            throw new IllegalStateException(sourceName + " is invalid: brands list cannot be empty");
        }
        for (Brand b : brandList) {
            if (b.name() == null || b.name().isBlank()) {
                throw new IllegalStateException(sourceName + " is invalid: brand name cannot be null or blank");
            }
            if (b.officialDomains() == null || b.officialDomains().isEmpty()) {
                throw new IllegalStateException(
                        sourceName + " is invalid: brand '" + b.name() + "' must have at least one official domain");
            }
        }

        // Validate required brands
        Set<String> brandNames = new HashSet<>();
        for (Brand b : brandList) {
            brandNames.add(b.name().toLowerCase(Locale.ROOT));
        }
        for (String req : REQUIRED_BRANDS) {
            if (!brandNames.contains(req.toLowerCase(Locale.ROOT))) {
                throw new IllegalStateException(
                        sourceName + " is invalid: required brand '" + req + "' is missing from brands list");
            }
        }
        this.brands = List.copyOf(brandList);

        // Build domain lookup map
        Map<String, Brand> domainMap = new LinkedHashMap<>();
        for (Brand b : this.brands) {
            for (String domain : b.officialDomains()) {
                domainMap.putIfAbsent(domain.toLowerCase(Locale.ROOT), b);
            }
        }
        this.domainToBrandMap = Collections.unmodifiableMap(domainMap);

        // 4. URL Shorteners
        this.urlShorteners = validateList(data.getUrlShorteners(), "urlShorteners", sourceName);

        // 5. Suspicious TLDs
        this.suspiciousTlds = validateList(data.getSuspiciousTlds(), "suspiciousTlds", sourceName);

        // 6. Free Hosting Domains (optional list, defaults to empty if absent)
        this.freeHostingDomains = data.getFreeHostingDomains() != null
                ? List.copyOf(data.getFreeHostingDomains())
                : List.of();

        // 7. URL Keywords
        this.urlKeywords = validateList(data.getUrlKeywords(), "urlKeywords", sourceName);

        // 8. Phishing Phrases
        this.phishingPhrases = validateList(data.resolvePhishingPhrases(), "phishingPhrases", sourceName);

        // 9. Digital Arrest Phrases
        this.digitalArrestPhrases = validateList(data.resolveDigitalArrestPhrases(), "digitalArrestPhrases", sourceName);

        // 10. Malicious App Phrases
        this.maliciousAppPhrases = validateList(data.resolveMaliciousAppPhrases(), "maliciousAppPhrases", sourceName);

        // 11. Urgency Phrases
        List<String> urgency = data.resolveUrgencyPhrases();
        this.urgencyPhrases = (urgency != null) ? List.copyOf(urgency) : List.of();

        // 12–16. TextDetector phrase categories (optional; default to empty if absent)
        this.otpSolicitationPhrases = optionalList(data.getOtpSolicitationPhrases());
        this.sensitiveDataPhrases   = optionalList(data.getSensitiveDataPhrases());
        this.prizeBaitPhrases       = optionalList(data.getPrizeBaitPhrases());
        this.kycThreatPhrases       = optionalList(data.getKycThreatPhrases());
        this.pressureCtaPhrases     = optionalList(data.getPressureCtaPhrases());

        // 17. ML scoring configuration (weights and safe-message cap)
        this.mlScoring = (data.getMlScoring() != null) ? data.getMlScoring() : RulesData.MlScoringConfig.DEFAULT;

        log.info("Cyber Shield detection rules successfully loaded: {} brands, {} shorteners, {} TLDs, {} phishing phrases, {} digital arrest phrases, {} app phrases",
                this.brands.size(), this.urlShorteners.size(), this.suspiciousTlds.size(),
                this.phishingPhrases.size(), this.digitalArrestPhrases.size(), this.maliciousAppPhrases.size());
    }

    private static List<String> validateList(List<String> list, String fieldName, String sourceName) {
        if (list == null || list.isEmpty()) {
            throw new IllegalStateException(sourceName + " is invalid: " + fieldName + " list cannot be empty");
        }
        return List.copyOf(list);
    }

    private static List<String> optionalList(List<String> list) {
        return (list != null) ? List.copyOf(list) : List.of();
    }

    // ── Getters for detection data ───────────────────────────────────────────

    public ScoringThresholds getScoringThresholds() {
        return scoringThresholds;
    }

    public SignalWeights getSignalWeights() {
        return signalWeights;
    }

    public List<Brand> getBrands() {
        return brands;
    }

    public List<String> getUrlShorteners() {
        return urlShorteners;
    }

    public List<String> getSuspiciousTlds() {
        return suspiciousTlds;
    }

    public List<String> getFreeHostingDomains() {
        return freeHostingDomains;
    }

    public List<String> getUrlKeywords() {
        return urlKeywords;
    }

    public List<String> getPhishingPhrases() {
        return phishingPhrases;
    }

    public List<String> getDigitalArrestPhrases() {
        return digitalArrestPhrases;
    }

    public List<String> getMaliciousAppPhrases() {
        return maliciousAppPhrases;
    }

    public List<String> getUrgencyPhrases() {
        return urgencyPhrases;
    }

    public List<String> getOtpSolicitationPhrases() {
        return otpSolicitationPhrases;
    }

    public List<String> getSensitiveDataPhrases() {
        return sensitiveDataPhrases;
    }

    public List<String> getPrizeBaitPhrases() {
        return prizeBaitPhrases;
    }

    public List<String> getKycThreatPhrases() {
        return kycThreatPhrases;
    }

    public List<String> getPressureCtaPhrases() {
        return pressureCtaPhrases;
    }

    public RulesData.MlScoringConfig getMlScoring() {
        return mlScoring != null ? mlScoring : RulesData.MlScoringConfig.DEFAULT;
    }

    // ── Helper methods for domain & brand queries ────────────────────────────

    /**
     * Looks up a brand by exact or partial name match.
     */
    public Optional<Brand> findBrandByName(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        String clean = name.trim().toLowerCase(Locale.ROOT);
        return brands.stream()
                .filter(b -> b.name().equalsIgnoreCase(clean)
                        || b.name().toLowerCase(Locale.ROOT).startsWith(clean)
                        || clean.startsWith(b.name().toLowerCase(Locale.ROOT)))
                .findFirst();
    }

    /**
     * Checks if a domain is an official domain for any known brand.
     */
    public boolean isOfficialDomain(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String clean = host.trim().toLowerCase(Locale.ROOT);
        for (Brand b : brands) {
            if (b.isOfficialDomain(clean)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the Brand matching the given host if it is an official domain.
     */
    public Optional<Brand> findBrandByHost(String host) {
        if (host == null || host.isBlank()) {
            return Optional.empty();
        }
        String clean = host.trim().toLowerCase(Locale.ROOT);
        return brands.stream()
                .filter(b -> b.isOfficialDomain(clean))
                .findFirst();
    }

    // ── Backward-compatible getters ──────────────────────────────────────────

    public List<String> getUrgencyKeywords() {
        return urgencyPhrases;
    }

    public List<String> getTrustedBrands() {
        return brands.stream().map(Brand::name).toList();
    }

    public List<String> getMaliciousApps() {
        return maliciousAppPhrases;
    }
}
