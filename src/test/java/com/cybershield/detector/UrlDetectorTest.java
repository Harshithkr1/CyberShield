package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link UrlDetector} and {@link com.cybershield.util.UrlExtractor}.
 *
 * <p>Covers 12+ distinct URLs — both safe (should emit ≤ 1 minor signal) and
 * malicious (must emit ≥ 1 medium-or-high signal matching the expected check).</p>
 *
 * <p><strong>No network connections are made in any test.</strong></p>
 */
@DisplayName("UrlDetector — signal detection for safe and malicious URLs")
class UrlDetectorTest {

    // Shared detector instance (rules loaded from classpath rules.json)
    private static UrlDetector detector;

    @BeforeAll
    static void setUpDetector() {
        RulesConfig rules = new RulesConfig();
        detector = new UrlDetector(rules);
    }

    // ── Safe URL tests ────────────────────────────────────────────────────────

    @Nested
    @DisplayName("Safe URLs — should produce low or zero risk signals")
    class SafeUrlTests {

        @Test
        @DisplayName("1. Official SBI HTTPS URL produces no malicious signals")
        void sbi_officialDomain_noSignals() {
            List<Signal> signals = detector.detect("Log in at https://onlinesbi.sbi/login.htm");
            // May produce a "login" keyword hit but NOT brand impersonation or typosquat
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.typosquatLev1");
            assertNoSignalWithId(signals, "url.ipAddress");
        }

        @Test
        @DisplayName("2. Official Amazon HTTPS URL produces no high-risk signals")
        void amazon_officialDomain_noHighRisk() {
            List<Signal> signals = detector.detect("Shop at https://www.amazon.in/dp/B09G9FPHY6");
            int totalPoints = signals.stream().mapToInt(Signal::points).sum();
            assertThat(totalPoints)
                    .as("Official Amazon URL should not accumulate high risk points")
                    .isLessThan(25);
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.ipAddress");
        }

        @Test
        @DisplayName("3. Official IRCTC URL produces no suspicious signals")
        void irctc_officialDomain_noSignals() {
            List<Signal> signals = detector.detect(
                    "Book your train ticket at https://www.irctc.co.in/nget/train-search");
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.typosquatLev1");
        }

        @Test
        @DisplayName("4. Income Tax official portal produces no suspicious signals")
        void incomeTax_officialDomain_noSignals() {
            List<Signal> signals = detector.detect(
                    "File ITR at https://www.incometax.gov.in/iec/foportal/");
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.typosquatLev1");
            assertNoSignalWithId(signals, "url.ipAddress");
        }

        @Test
        @DisplayName("5. Plain example.com URL with HTTPS — minimal risk")
        void example_httpsUrl_noMaliciousSignals() {
            List<Signal> signals = detector.detect("Visit https://example.com for details.");
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.ipAddress");
            assertNoSignalWithId(signals, "url.typosquatLev1");
            assertNoSignalWithId(signals, "url.typosquatLev2");
        }

        @Test
        @DisplayName("6. HDFC Bank official domain — no typosquat or impersonation")
        void hdfc_officialDomain_clean() {
            List<Signal> signals = detector.detect("Check https://www.hdfcbank.com/personal/pay");
            assertNoSignalWithId(signals, "url.brandImpersonation");
            assertNoSignalWithId(signals, "url.typosquatLev1");
        }
    }

    // ── Malicious URL tests ───────────────────────────────────────────────────

    @Nested
    @DisplayName("Malicious URLs — must trigger expected signals")
    class MaliciousUrlTests {

        @Test
        @DisplayName("7. Raw IPv4 host triggers url.ipAddress signal")
        void rawIpHost_triggersIpSignal() {
            List<Signal> signals = detector.detect(
                    "Click here to update your KYC: http://192.168.1.254/kyc/update");
            assertSignalPresent(signals, "url.ipAddress");
            assertThat(signalById(signals, "url.ipAddress").points()).isGreaterThanOrEqualTo(14);
        }

        @Test
        @DisplayName("8. URL shortener triggers url.shortener signal")
        void bitlyShortener_triggersShortenerSignal() {
            List<Signal> signals = detector.detect(
                    "Claim your prize now: https://bit.ly/3xAbCdE");
            assertSignalPresent(signals, "url.shortener");
            assertThat(signalById(signals, "url.shortener").points()).isGreaterThanOrEqualTo(8);
        }

        @Test
        @DisplayName("9. SBI brand name in subdomain but unofficial domain triggers impersonation")
        void sbiInSubdomain_triggersImpersonation() {
            List<Signal> signals = detector.detect(
                    "Verify your SBI account: https://sbi.kyc-update.xyz/login");
            assertSignalPresent(signals, "url.brandImpersonation");
            assertThat(signalById(signals, "url.brandImpersonation").points()).isGreaterThanOrEqualTo(20);
        }

        @Test
        @DisplayName("10. Levenshtein-1 typosquat of HDFC triggers url.typosquatLev1")
        void hdfcTyposquat_lev1_triggersHighRiskSignal() {
            // "hdfcbnk" is 1 edit from "hdfcbank"
            List<Signal> signals = detector.detect(
                    "Login to your account at https://hdfcbnk.com/netbanking");
            assertSignalPresent(signals, "url.typosquatLev1");
            assertThat(signalById(signals, "url.typosquatLev1").points()).isGreaterThanOrEqualTo(20);
        }

        @Test
        @DisplayName("11. Levenshtein-2 typosquat of Paytm triggers url.typosquatLev2")
        void paytmTyposquat_lev2_triggersMediumRiskSignal() {
            // "paytrn" is 2 edits from "paytm"
            List<Signal> signals = detector.detect(
                    "Add money via https://www.paytrn.com/wallet");
            assertSignalPresent(signals, "url.typosquatLev2");
            assertThat(signalById(signals, "url.typosquatLev2").points()).isGreaterThanOrEqualTo(10);
        }

        @Test
        @DisplayName("12. Suspicious TLD (.xyz) triggers url.suspiciousTld signal")
        void suspiciousTld_xyz_triggersSignal() {
            List<Signal> signals = detector.detect(
                    "Update your KYC: http://secure-bank.xyz/kyc");
            assertSignalPresent(signals, "url.suspiciousTld");
        }

        @Test
        @DisplayName("13. '@' in URL triggers url.atSymbol signal")
        void atSymbolInUrl_triggersSignal() {
            List<Signal> signals = detector.detect(
                    "Your bank link: http://www.legit-bank.com@phishing-site.com/login");
            assertSignalPresent(signals, "url.atSymbol");
            assertThat(signalById(signals, "url.atSymbol").points()).isGreaterThanOrEqualTo(15);
        }

        @Test
        @DisplayName("14. Excessive subdomains (4 labels) triggers url.excessiveSubdomains")
        void excessiveSubdomains_triggersSignal() {
            List<Signal> signals = detector.detect(
                    "Verify account: https://secure.kyc.update.evil-bank.com/login");
            assertSignalPresent(signals, "url.excessiveSubdomains");
        }

        @Test
        @DisplayName("15. Plain HTTP (no HTTPS) triggers url.noHttps signal")
        void plainHttp_triggersNoHttpsSignal() {
            List<Signal> signals = detector.detect(
                    "Submit details at http://genuine-site.com/form");
            assertSignalPresent(signals, "url.noHttps");
        }

        @Test
        @DisplayName("16. URL with 'verify' and 'kyc' keywords triggers url.keyword signal")
        void suspiciousKeywords_triggersKeywordSignal() {
            List<Signal> signals = detector.detect(
                    "https://not-a-bank.online/verify-kyc-account?token=abc123");
            assertSignalPresent(signals, "url.keyword");
            String explanation = signalById(signals, "url.keyword").explanation();
            assertThat(explanation).containsIgnoringCase("verify");
        }

        @Test
        @DisplayName("17. Non-standard port triggers url.portInUrl signal")
        void nonStandardPort_triggersPortSignal() {
            List<Signal> signals = detector.detect(
                    "Access your account: https://banking-portal.com:9999/login");
            assertSignalPresent(signals, "url.portInUrl");
            assertThat(signalById(signals, "url.portInUrl").points()).isGreaterThanOrEqualTo(10);
        }

        @Test
        @DisplayName("18. Very long URL triggers url.longUrl signal")
        void veryLongUrl_triggersLongUrlSignal() {
            String longUrl = "https://update-kyc-bank-secure-portal-verification.com/"
                    + "a".repeat(60) + "/confirm?token=xyz";
            List<Signal> signals = detector.detect("Visit " + longUrl);
            assertSignalPresent(signals, "url.longUrl");
        }

        @Test
        @DisplayName("19. Host with 4 hyphens triggers url.manyHyphens signal")
        void manyHyphensInHost_triggersSignal() {
            List<Signal> signals = detector.detect(
                    "https://secure-kyc-update-bank-portal.com/login");
            assertSignalPresent(signals, "url.manyHyphens");
        }

        @Test
        @DisplayName("20. Double scheme in URL triggers url.doubleScheme signal")
        void doubleScheme_triggersSignal() {
            List<Signal> signals = detector.detect(
                    "Navigate to https://redirect.com/go?url=http://phishing.xyz/steal");
            assertSignalPresent(signals, "url.doubleScheme");
            assertThat(signalById(signals, "url.doubleScheme").points()).isGreaterThanOrEqualTo(18);
        }

        @Test
        @DisplayName("21. ICICI brand in path with unofficial domain triggers impersonation")
        void iciciBankInPath_triggersImpersonation() {
            List<Signal> signals = detector.detect(
                    "Login here: https://secure-login.net/icicibank/account");
            assertSignalPresent(signals, "url.brandImpersonation");
        }
    }

    // ── Parameterised batch — signals summary ─────────────────────────────────

    @ParameterizedTest(name = "[{index}] {0} → expects signal '{2}'")
    @MethodSource("maliciousUrlSignalMatrix")
    @DisplayName("Batch — malicious URL → expected signal id")
    void batchMaliciousUrls(String description, String urlText, String expectedSignalId) {
        List<Signal> signals = detector.detect(urlText);
        assertSignalPresent(signals, expectedSignalId);
    }

    static Stream<Arguments> maliciousUrlSignalMatrix() {
        return Stream.of(
                Arguments.of("IP host", "http://10.0.0.1/login", "url.ipAddress"),
                Arguments.of("tinyurl shortener", "https://tinyurl.com/abc123", "url.shortener"),
                Arguments.of("Paytm in path (unofficial domain)", "https://payment-gateway.club/paytm/wallet", "url.brandImpersonation"),
                Arguments.of("PhonePe typosquat lev-1", "https://phonePee.com/send", "url.typosquatLev1"),
                Arguments.of("Suspicious .top TLD", "https://bank-kyc-verify.top/login", "url.suspiciousTld"),
                Arguments.of("@ in URL authority", "https://sbi.co.in@phish.ru/", "url.atSymbol"),
                Arguments.of("KYC keyword", "https://update-info.in/kyc/submit", "url.keyword"),
                Arguments.of("5-level subdomain nesting", "https://a.b.c.d.evil.com/", "url.excessiveSubdomains"),
                Arguments.of("Plain HTTP", "http://mybank-update.com/form", "url.noHttps"),
                Arguments.of("Double scheme redirect", "https://go.com?r=https://steal.xyz", "url.doubleScheme")
        );
    }

    // ── registrableDomain unit tests ──────────────────────────────────────────

    @Nested
    @DisplayName("UrlDetector.registrableDomain helper")
    class RegistrableDomainTests {

        @Test
        void twoLabelDomain() {
            assertThat(UrlDetector.registrableDomain("example.com")).isEqualTo("example.com");
        }

        @Test
        void threeLabelDomain() {
            assertThat(UrlDetector.registrableDomain("sub.example.com")).isEqualTo("example.com");
        }

        @Test
        void coInDomain() {
            assertThat(UrlDetector.registrableDomain("sbi.co.in")).isEqualTo("sbi.co.in");
        }

        @Test
        void subdomain_coIn() {
            assertThat(UrlDetector.registrableDomain("secure.sbi.co.in")).isEqualTo("sbi.co.in");
        }

        @Test
        void fourLevelSubdomain_coIn() {
            assertThat(UrlDetector.registrableDomain("kyc.update.evil.co.in")).isEqualTo("evil.co.in");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static void assertSignalPresent(List<Signal> signals, String id) {
        assertThat(signals)
                .as("Expected signal with id='%s' but got: %s", id, signalIds(signals))
                .anyMatch(s -> id.equals(s.id()));
    }

    private static void assertNoSignalWithId(List<Signal> signals, String id) {
        assertThat(signals)
                .as("Did NOT expect signal with id='%s'", id)
                .noneMatch(s -> id.equals(s.id()));
    }

    private static Signal signalById(List<Signal> signals, String id) {
        return signals.stream()
                .filter(s -> id.equals(s.id()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Signal not found: " + id));
    }

    private static List<String> signalIds(List<Signal> signals) {
        return signals.stream().map(Signal::id).toList();
    }
}
