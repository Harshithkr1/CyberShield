package com.cybershield.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RulesConfigTest {

    private RulesConfig rulesConfig;

    @BeforeEach
    void setUp() {
        rulesConfig = new RulesConfig();
    }

    @Nested
    @DisplayName("rules.json loading and non-empty key lists")
    class RulesLoadingTests {

        @Test
        @DisplayName("RulesConfig loads successfully and is non-null")
        void rulesConfig_loadsSuccessfully() {
            assertThat(rulesConfig).isNotNull();
        }

        @Test
        @DisplayName("Brands list is not empty and contains all required brands")
        void brands_isNotEmptyAndContainsAllRequired() {
            List<Brand> brands = rulesConfig.getBrands();
            assertThat(brands)
                    .as("Brands list must not be empty")
                    .isNotEmpty();

            Set<String> brandNames = brands.stream()
                    .map(b -> b.name().toLowerCase(Locale.ROOT))
                    .collect(Collectors.toSet());

            // Validate all 14 brands specified in the requirements
            List<String> requiredBrands = List.of(
                    "SBI", "HDFC", "ICICI", "Paytm", "PhonePe", "Google Pay",
                    "Amazon", "Flipkart", "India Post", "FedEx", "DHL",
                    "IRCTC", "Income Tax", "UIDAI");

            for (String requiredBrand : requiredBrands) {
                assertThat(brandNames)
                        .as("Rules must contain required brand: " + requiredBrand)
                        .contains(requiredBrand.toLowerCase(Locale.ROOT));
            }
        }

        @Test
        @DisplayName("Each brand has a valid name and non-empty official domains")
        void brands_eachHasOfficialDomains() {
            List<Brand> brands = rulesConfig.getBrands();
            for (Brand brand : brands) {
                assertThat(brand.name())
                        .as("Brand name must not be blank")
                        .isNotBlank();
                assertThat(brand.officialDomains())
                        .as("Official domains for brand " + brand.name() + " must not be empty")
                        .isNotEmpty();
                assertThat(brand.canonicalDomains())
                        .as("canonicalDomains alias must equal officialDomains")
                        .isEqualTo(brand.officialDomains());
            }
        }

        @ParameterizedTest(name = "Brand {0} has expected official domains")
        @ValueSource(strings = {
                "SBI", "HDFC", "ICICI", "Paytm", "PhonePe", "Google Pay",
                "Amazon", "Flipkart", "India Post", "FedEx", "DHL",
                "IRCTC", "Income Tax", "UIDAI"
        })
        void requiredBrands_haveExpectedDomains(String brandName) {
            Brand brand = rulesConfig.findBrandByName(brandName)
                    .orElseThrow(() -> new AssertionError("Brand not found: " + brandName));

            assertThat(brand.officialDomains()).isNotEmpty();

            // Validate official domain matching helper
            String sampleDomain = brand.officialDomains().get(0);
            assertThat(brand.isOfficialDomain(sampleDomain)).isTrue();
            assertThat(brand.isOfficialDomain("sub." + sampleDomain)).isTrue();
            assertThat(rulesConfig.isOfficialDomain(sampleDomain)).isTrue();
        }

        @Test
        @DisplayName("URL shorteners list is not empty and contains known shorteners")
        void urlShorteners_isNotEmpty() {
            List<String> shorteners = rulesConfig.getUrlShorteners();
            assertThat(shorteners)
                    .as("URL shorteners list must not be empty")
                    .isNotEmpty()
                    .contains("bit.ly", "tinyurl.com", "t.co");
        }

        @Test
        @DisplayName("Suspicious TLDs list is not empty and contains known suspicious TLDs")
        void suspiciousTlds_isNotEmpty() {
            List<String> tlds = rulesConfig.getSuspiciousTlds();
            assertThat(tlds)
                    .as("Suspicious TLDs list must not be empty")
                    .isNotEmpty()
                    .contains(".xyz", ".top", ".club");
        }

        @Test
        @DisplayName("URL keywords list is not empty and contains keywords")
        void urlKeywords_isNotEmpty() {
            List<String> keywords = rulesConfig.getUrlKeywords();
            assertThat(keywords)
                    .as("URL keywords list must not be empty")
                    .isNotEmpty()
                    .contains("login", "verify", "kyc", "otp");
        }

        @Test
        @DisplayName("Phishing phrases list is not empty")
        void phishingPhrases_isNotEmpty() {
            List<String> phrases = rulesConfig.getPhishingPhrases();
            assertThat(phrases)
                    .as("Phishing phrases list must not be empty")
                    .isNotEmpty()
                    .contains("your account has been blocked", "complete your kyc");
        }

        @Test
        @DisplayName("Digital arrest phrases list is not empty")
        void digitalArrestPhrases_isNotEmpty() {
            List<String> phrases = rulesConfig.getDigitalArrestPhrases();
            assertThat(phrases)
                    .as("Digital arrest phrases list must not be empty")
                    .isNotEmpty()
                    .contains("digital arrest", "narcotics control bureau");
        }

        @Test
        @DisplayName("Malicious app phrases list is not empty")
        void maliciousAppPhrases_isNotEmpty() {
            List<String> phrases = rulesConfig.getMaliciousAppPhrases();
            assertThat(phrases)
                    .as("Malicious app phrases list must not be empty")
                    .isNotEmpty()
                    .contains("download this apk", "install anydesk");
        }

        @Test
        @DisplayName("Signal weights map is not empty and contains heuristic weights")
        void signalWeights_isNotEmpty() {
            SignalWeights weights = rulesConfig.getSignalWeights();
            assertThat(weights).isNotNull();
            assertThat(weights.isEmpty()).isFalse();
            assertThat(weights.size()).isGreaterThan(0);

            Map<String, Integer> map = weights.getWeights();
            assertThat(map).isNotEmpty();
            assertThat(weights.getPhraseCategoryPhishing()).isPositive();
            assertThat(weights.getPhraseCategoryDigitalArrest()).isPositive();
            assertThat(weights.getPhraseCategoryMaliciousApp()).isPositive();
            assertThat(weights.getUrlSuspiciousTld()).isPositive();
            assertThat(weights.getUrlShortener()).isPositive();
        }

        @Test
        @DisplayName("Scoring thresholds are valid and properly ordered")
        void scoringThresholds_areValid() {
            ScoringThresholds thresholds = rulesConfig.getScoringThresholds();
            assertThat(thresholds).isNotNull();
            assertThat(thresholds.low()).isEqualTo(0);
            assertThat(thresholds.medium()).isEqualTo(25);
            assertThat(thresholds.high()).isEqualTo(50);
            assertThat(thresholds.critical()).isEqualTo(75);
            thresholds.validate(); // Should not throw
        }

        @Test
        @DisplayName("Backward-compatible helper methods return non-empty lists")
        void backwardCompatibleMethods_returnPopulatedLists() {
            assertThat(rulesConfig.getTrustedBrands()).isNotEmpty();
            assertThat(rulesConfig.getMaliciousApps()).isNotEmpty();
            assertThat(rulesConfig.getUrgencyKeywords()).isNotEmpty();
        }
    }

    @Nested
    @DisplayName("Failure on invalid configuration")
    class ValidationFailureTests {

        private static final String BASELINE_VALID_JSON = """
                {
                  "scoringThresholds": { "low": 0, "medium": 25, "high": 50, "critical": 75 },
                  "signalWeights": { "phraseCategoryPhishing": 12 },
                  "brands": [
                    { "name": "SBI", "officialDomains": ["sbi.co.in"] },
                    { "name": "HDFC", "officialDomains": ["hdfcbank.com"] },
                    { "name": "ICICI", "officialDomains": ["icicibank.com"] },
                    { "name": "Paytm", "officialDomains": ["paytm.com"] },
                    { "name": "PhonePe", "officialDomains": ["phonepe.com"] },
                    { "name": "Google Pay", "officialDomains": ["pay.google.com"] },
                    { "name": "Amazon", "officialDomains": ["amazon.in"] },
                    { "name": "Flipkart", "officialDomains": ["flipkart.com"] },
                    { "name": "India Post", "officialDomains": ["indiapost.gov.in"] },
                    { "name": "FedEx", "officialDomains": ["fedex.com"] },
                    { "name": "DHL", "officialDomains": ["dhl.com"] },
                    { "name": "IRCTC", "officialDomains": ["irctc.co.in"] },
                    { "name": "Income Tax", "officialDomains": ["incometax.gov.in"] },
                    { "name": "UIDAI", "officialDomains": ["uidai.gov.in"] }
                  ],
                  "urlShorteners": ["bit.ly"],
                  "suspiciousTlds": [".xyz"],
                  "urlKeywords": ["login"],
                  "phishingPhrases": ["account blocked"],
                  "digitalArrestPhrases": ["digital arrest"],
                  "maliciousAppPhrases": ["download apk"]
                }
                """;

        @Test
        @DisplayName("Non-existent classpath file fails with clear error")
        void nonExistentFile_failsWithClearError() {
            assertThatThrownBy(() -> new RulesConfig(null, "non-existent-rules.json"))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Rules configuration file not found on classpath: non-existent-rules.json");
        }

        @Test
        @DisplayName("Malformed JSON fails with clear error")
        void malformedJson_failsWithClearError() {
            String malformedJson = "{ this is not valid json }";
            assertThatThrownBy(() -> RulesConfig.fromJson(malformedJson))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Failed to parse rules JSON");
        }

        @Test
        @DisplayName("Missing required brand fails with clear error")
        void missingRequiredBrand_failsWithClearError() {
            String jsonMissingSbi = BASELINE_VALID_JSON.replace(
                    "{ \"name\": \"SBI\", \"officialDomains\": [\"sbi.co.in\"] },", "");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonMissingSbi))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("required brand 'SBI' is missing from brands list");
        }

        @Test
        @DisplayName("Brand with no official domains fails with clear error")
        void brandWithEmptyDomains_failsWithClearError() {
            String jsonEmptyDomains = BASELINE_VALID_JSON.replace(
                    "[\"sbi.co.in\"]", "[]");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonEmptyDomains))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("brand 'SBI' must have at least one official domain");
        }

        @Test
        @DisplayName("Empty phishing phrases list fails with clear error")
        void emptyPhishingPhrases_failsWithClearError() {
            String jsonEmptyPhrases = BASELINE_VALID_JSON.replace(
                    "\"phishingPhrases\": [\"account blocked\"]", "\"phishingPhrases\": []");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonEmptyPhrases))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("phishingPhrases list cannot be empty");
        }

        @Test
        @DisplayName("Empty digital arrest phrases list fails with clear error")
        void emptyDigitalArrestPhrases_failsWithClearError() {
            String jsonEmpty = BASELINE_VALID_JSON.replace(
                    "\"digitalArrestPhrases\": [\"digital arrest\"]", "\"digitalArrestPhrases\": []");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonEmpty))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("digitalArrestPhrases list cannot be empty");
        }

        @Test
        @DisplayName("Empty malicious app phrases list fails with clear error")
        void emptyMaliciousAppPhrases_failsWithClearError() {
            String jsonEmpty = BASELINE_VALID_JSON.replace(
                    "\"maliciousAppPhrases\": [\"download apk\"]", "\"maliciousAppPhrases\": []");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonEmpty))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("maliciousAppPhrases list cannot be empty");
        }

        @Test
        @DisplayName("Empty signal weights map fails with clear error")
        void emptySignalWeights_failsWithClearError() {
            String jsonEmpty = BASELINE_VALID_JSON.replace(
                    "\"signalWeights\": { \"phraseCategoryPhishing\": 12 }", "\"signalWeights\": {}");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonEmpty))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("signalWeights cannot be empty");
        }

        @Test
        @DisplayName("Invalid thresholds (medium < low) fails with clear error")
        void invalidThresholdOrdering_failsWithClearError() {
            String jsonBadThresholds = BASELINE_VALID_JSON.replace(
                    "\"scoringThresholds\": { \"low\": 0, \"medium\": 25, \"high\": 50, \"critical\": 75 }",
                    "\"scoringThresholds\": { \"low\": 50, \"medium\": 20, \"high\": 70, \"critical\": 90 }");

            assertThatThrownBy(() -> RulesConfig.fromJson(jsonBadThresholds))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("Medium threshold (20) cannot be less than low threshold (50)");
        }
}

@Nested
@SpringBootTest
@DisplayName("Spring Context Startup Test")
static class SpringStartupTest {

@Autowired
        private RulesConfig injectedRulesConfig;

@Test
        @DisplayName("RulesConfig is injected into Spring context and rules are loaded")
        void rulesConfig_isInjectedBySpring() {
            assertThat(injectedRulesConfig).isNotNull();
            assertThat(injectedRulesConfig.getBrands()).isNotEmpty();
            assertThat(injectedRulesConfig.getPhishingPhrases()).isNotEmpty();
            assertThat(injectedRulesConfig.getSignalWeights().isEmpty()).isFalse();
            assertThat(injectedRulesConfig.getScoringThresholds()).isNotNull();
        }
    }
}
