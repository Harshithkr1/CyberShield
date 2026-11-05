package com.cybershield.service;

import com.cybershield.config.RulesConfig;
import com.cybershield.detector.*;
import com.cybershield.ml.TextClassifier;
import com.cybershield.ml.UrlClassifier;
import com.cybershield.ml.UrlFeatureExtractor;
import com.cybershield.model.AnalysisResult;
import com.cybershield.model.RiskLevel;
import com.cybershield.model.Signal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ScoringEngine & AnalyzerService — scoring, diminishing returns & combination attacks")
class ScoringEngineAndAnalyzerTest {

    private static AnalyzerService analyzerService;
    private static ScoringEngine scoringEngine;
    private static RulesConfig rulesConfig;

    @BeforeAll
    static void setUp() {
        rulesConfig = new RulesConfig();
        scoringEngine = new ScoringEngine(rulesConfig);

        // Instantiate all detectors with rulesConfig
        List<Detector> detectors = List.of(
                new UrlDetector(rulesConfig),
                new TextDetector(rulesConfig),
                new DigitalArrestDetector(rulesConfig),
                new MaliciousAppDetector(rulesConfig)
        );

        TextClassifier textClassifier = new TextClassifier();
        UrlClassifier urlClassifier = new UrlClassifier(new UrlFeatureExtractor());

        analyzerService = new AnalyzerService(detectors, scoringEngine, textClassifier, urlClassifier);
    }

    private void printResult(int index, String scenario, String text, AnalysisResult result) {
        System.out.println("================================================================================");
        System.out.printf("Message %d [%s]%n", index, scenario);
        System.out.println("--------------------------------------------------------------------------------");
        System.out.printf("Text:     \"%s\"%n", text);
        System.out.printf("Score:    %d / 100%n", result.score());
        System.out.printf("Level:    %s%n", result.level());
        System.out.printf("ScamType: %s%n", result.scamType());
        System.out.printf("Summary:  %s%n", result.summary());
        System.out.printf("URLs:     %s%n", result.urls());
        System.out.printf("Signals (%d):%n", result.signals().size());
        for (Signal s : result.signals()) {
            System.out.printf("  • [%-24s] (%2d pts) \"%s\" [%d..%d]%n",
                    s.id(), s.points(), s.matchedText(), s.start(), s.end());
        }
        System.out.println("================================================================================\n");
    }

    // ── 6 Core Message Tests with printed scores ──────────────────────────────

    @Test
    @DisplayName("Message 1: Safe, ordinary message (Score: 0, Level: LOW)")
    void testMessage1_SafeMessage() {
        String text = "Hi team, please find the attached notes from yesterday's retrospective meeting. See you all tomorrow!";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(1, "SAFE MESSAGE", text, result);

        assertThat(result.score()).isEqualTo(0);
        assertThat(result.level()).isEqualTo(RiskLevel.LOW);
        assertThat(result.scamType()).isEqualTo("SAFE");
        assertThat(result.signals()).isEmpty();
        assertThat(result.ml()).isNull();
    }

    @Test
    @DisplayName("Message 2: Weak signals only — caps & exclamation (Score: Low, Level: LOW)")
    void testMessage2_WeakSignalsOnly() {
        String text = "REMINDER PLEASE JOIN THE TOWN HALL MEETING RIGHT NOW ON TIME!!!";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(2, "WEAK SIGNALS / ALL-CAPS STYLING", text, result);

        // Diminishing returns ensures weak signals don't breach Low threshold
        assertThat(result.score()).isGreaterThan(0).isLessThan(25);
        assertThat(result.level()).isEqualTo(RiskLevel.LOW);
        assertThat(result.signals()).anyMatch(s -> s.id().equals("text.excessiveCaps"));
    }

    @Test
    @DisplayName("Message 3: KYC threat with URL shortener (Score: Medium, Level: MEDIUM)")
    void testMessage3_KycPhishingBait() {
        String text = "Dear customer, your kyc is incomplete. Urgent action required to avoid suspension: http://bit.ly/update-kyc";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(3, "MEDIUM RISK KYC SUSPENSION LURE", text, result);

        assertThat(result.score()).isGreaterThanOrEqualTo(25).isLessThan(50);
        assertThat(result.level()).isEqualTo(RiskLevel.MEDIUM);
        assertThat(result.urls()).contains("http://bit.ly/update-kyc");
        assertThat(result.signals()).anyMatch(s -> s.id().equals("text.kycThreat"));
    }

    @Test
    @DisplayName("Message 4: Combination bonus — OTP + Urgency + Suspicious URL forces at least HIGH")
    void testMessage4_CredentialPhishingCombination() {
        String text = "URGENT! Immediate action required. Please share your otp to prevent account closure: http://paytrn-secure.xyz/login";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(4, "CREDENTIAL PHISHING COMBINATION ATTACK", text, result);

        // Forces at least High via combination bonus (>= 65)
        assertThat(result.score()).isGreaterThanOrEqualTo(65);
        assertThat(result.level()).isIn(RiskLevel.HIGH, RiskLevel.CRITICAL);
        assertThat(result.scamType()).isEqualTo("CREDENTIAL_PHISHING");
        assertThat(result.summary()).contains("phishing");
    }

    @Test
    @DisplayName("Message 5: Rogue APK side-load + remote-access lures (Score: High, Level: HIGH)")
    void testMessage5_MaliciousAppSideload() {
        String text = "Enable unknown sources and download this apk to update your bank app: http://attacker.com/files/bank-update.apk. Grant accessibility permission.";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(5, "MALICIOUS APK AND REMOTE ACCESS LURE", text, result);

        assertThat(result.score()).isGreaterThanOrEqualTo(50);
        assertThat(result.level()).isIn(RiskLevel.HIGH, RiskLevel.CRITICAL);
        assertThat(result.scamType()).isEqualTo("MALICIOUS_APP");
        assertThat(result.signals()).anyMatch(s -> s.id().equals("maliciousApp.apkLink"));
    }

    @Test
    @DisplayName("Message 6: Combination bonus — Digital Arrest + Safe Account + Secrecy forces CRITICAL")
    void testMessage6_DigitalArrestCritical() {
        String text = "This is a CBI officer calling. You are under digital arrest for money laundering. Stay on video call, do not tell anyone, and immediately transfer to safe account for RBI verification.";
        AnalysisResult result = analyzerService.analyse(text, false);

        printResult(6, "DIGITAL ARREST COERCIVE EXTORTION", text, result);

        // Combination bonus forces Critical (>= 85)
        assertThat(result.score()).isGreaterThanOrEqualTo(85);
        assertThat(result.level()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.scamType()).isEqualTo("DIGITAL_ARREST");
        assertThat(result.summary()).contains("Critical threat detected");
    }

    // ── Additional Diminishing Returns & Deduplication Verification ───────────

    @Test
    @DisplayName("Diminishing returns prevents 10 weak signals from exceeding one strong signal")
    void diminishingReturns_manyWeakDoNotOutweighOneStrong() {
        // 1 strong signal of 20 points
        Signal strong = Signal.builder()
                .id("strong.sig")
                .category("TEST")
                .points(20)
                .explanation("Strong indicator")
                .matchedText("strong")
                .start(0)
                .end(6)
                .build();

        // 10 weak signals of 5 points each (non-overlapping)
        List<Signal> weakSignals = List.of(
                createDummySignal("w1", 5, 10, 15),
                createDummySignal("w2", 5, 20, 25),
                createDummySignal("w3", 5, 30, 35),
                createDummySignal("w4", 5, 40, 45),
                createDummySignal("w5", 5, 50, 55),
                createDummySignal("w6", 5, 60, 65),
                createDummySignal("w7", 5, 70, 75),
                createDummySignal("w8", 5, 80, 85),
                createDummySignal("w9", 5, 90, 95),
                createDummySignal("w10", 5, 100, 105)
        );

        int strongScore = scoringEngine.score(List.of(strong));
        int weakScore   = scoringEngine.score(weakSignals);

        System.out.printf("Single 20-pt signal score: %d, Ten 5-pt signals score: %d%n", strongScore, weakScore);

        assertThat(strongScore).isEqualTo(20);
        assertThat(weakScore).isLessThan(25); // remains in LOW risk!
    }

    @Test
    @DisplayName("Overlapping signals on identical text span are not double-counted")
    void overlappingSignals_deduplicatedToHighestPoints() {
        Signal kyc = Signal.builder()
                .id("text.kycThreat")
                .category("TEXT")
                .points(14)
                .explanation("KYC threat")
                .matchedText("complete your kyc")
                .start(0)
                .end(17)
                .build();

        Signal phishing = Signal.builder()
                .id("text.phishing")
                .category("TEXT")
                .points(12)
                .explanation("Phishing phrase")
                .matchedText("complete your kyc")
                .start(0)
                .end(17)
                .build();

        List<Signal> filtered = scoringEngine.filterOverlapping(List.of(phishing, kyc));
        assertThat(filtered).hasSize(1);
        assertThat(filtered.get(0).id()).isEqualTo("text.kycThreat");
        assertThat(filtered.get(0).points()).isEqualTo(14);
    }

    // ── ML Hybrid Tests ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Hybrid Test 1: Digital arrest sample stays Critical with ML on")
    void testDigitalArrest_WithMlOn_StaysCritical() {
        String text = "This is Officer R. K. Verma from Central Bureau of Investigation cyber cell. An arrest warrant is issued against your name for money laundering and a drug parcel seized at Mumbai airport. You are under digital arrest. Stay on video call, do not tell anyone, and transfer funds to safe account for RBI verification.";
        AnalysisResult result = analyzerService.analyse(text, true);

        assertThat(result.level()).isEqualTo(RiskLevel.CRITICAL);
        assertThat(result.score()).isGreaterThanOrEqualTo(75);
        assertThat(result.ml()).isNotNull();
        assertThat(result.ml().ruleScore()).isGreaterThanOrEqualTo(75);
        assertThat(result.ml().textProbability()).isGreaterThan(0.80);
    }

    @Test
    @DisplayName("Hybrid Test 2: Safe sample stays Low with ML on (capped at <= 49 if no signals)")
    void testSafeMessage_WithMlOn_StaysLow() {
        String text = "Hi Ananya, please find the meeting agenda and presentation slides for tomorrow's project review at 3 PM in the conference room. Let me know if you'd like to add any discussion points. Thanks!";
        AnalysisResult result = analyzerService.analyse(text, true);

        assertThat(result.level()).isEqualTo(RiskLevel.LOW);
        assertThat(result.score()).isLessThan(25);
        assertThat(result.score()).isLessThanOrEqualTo(49);
        assertThat(result.signals()).isEmpty();
        assertThat(result.ml()).isNotNull();
        assertThat(result.ml().ruleScore()).isEqualTo(0);
    }

    @Test
    @DisplayName("Hybrid Test 3: useMl=false gives exactly the old scores and ml is null")
    void testUseMlFalse_GivesExactRuleScores() {
        String text = "Dear SBI customer, your bank account KYC has expired. Your debit card and net banking will be blocked within 24 hours. Complete your kyc immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.";
        AnalysisResult resultNoMl = analyzerService.analyse(text, false);
        AnalysisResult resultMl   = analyzerService.analyse(text, true);

        assertThat(resultNoMl.ml()).isNull();
        assertThat(resultNoMl.score()).isEqualTo(resultMl.ml().ruleScore());
        assertThat(resultNoMl.score()).isEqualTo(37);
        assertThat(resultNoMl.level()).isEqualTo(RiskLevel.MEDIUM);
    }

    @Test
    @DisplayName("Evaluate all 5 UI samples in both modes (Rules-only vs Hybrid)")
    void evaluateAll5SamplesInBothModes() {
        java.util.Map<String, String> samples = new java.util.LinkedHashMap<>();
        samples.put("Sample 1: Fake Bank KYC SMS",
                "Dear SBI customer, your bank account KYC has expired. Your debit card and net banking will be blocked within 24 hours. Complete your kyc immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.");
        samples.put("Sample 2: Digital Arrest Call Script",
                "This is Officer R. K. Verma from Central Bureau of Investigation cyber cell. An arrest warrant is issued against your name for money laundering and a drug parcel seized at Mumbai airport. You are under digital arrest. Stay on video call, do not tell anyone, and transfer funds to safe account for RBI verification.");
        samples.put("Sample 3: Fake Courier Link",
                "Your FedEx courier parcel #FDX-99821 is on hold at customs clearance. Pay customs duty fee of Rs 49 to release package and reschedule your delivery: http://fedx-customs-clearance.top/track");
        samples.put("Sample 4: Malicious APK Install Message",
                "Urgent notice from Power Grid: Electricity connection will be disconnected tonight due to unpaid dues. Install our electricity bill app to clear bill: http://quick-power-bill.org/payment.apk. Enable unknown sources and grant accessibility permission.");
        samples.put("Sample 5: Safe Work Message",
                "Hi Ananya, please find the meeting agenda and presentation slides for tomorrow's project review at 3 PM in the conference room. Let me know if you'd like to add any discussion points. Thanks!");

        System.out.println("\n==================================================================================================================");
        System.out.println("                                5 SAMPLE SCENARIOS: RULES-ONLY VS HYBRID (ML ON)                                  ");
        System.out.println("==================================================================================================================");
        System.out.printf("%-40s | %-12s | %-10s | %-12s | %-10s | %-8s | %-10s%n",
                "Sample Scenario", "Rules Score", "Rules Lvl", "Hybrid Score", "Hybrid Lvl", "ML Score", "Formula");
        System.out.println("------------------------------------------------------------------------------------------------------------------");

        for (java.util.Map.Entry<String, String> entry : samples.entrySet()) {
            String name = entry.getKey();
            String text = entry.getValue();

            AnalysisResult rulesOnly = analyzerService.analyse(text, false);
            AnalysisResult hybrid    = analyzerService.analyse(text, true);

            int rScore = rulesOnly.score();
            RiskLevel rLvl = rulesOnly.level();
            int hScore = hybrid.score();
            RiskLevel hLvl = hybrid.level();
            int mlScore = hybrid.ml().mlScore();
            String formula = String.format("0.6x%d+0.4x%d", rScore, mlScore);

            System.out.printf("%-40s | %-12d | %-10s | %-12d | %-10s | %-8d | %-10s%n",
                    name, rScore, rLvl, hScore, hLvl, mlScore, formula);
        }
        System.out.println("==================================================================================================================\n");
    }

    private Signal createDummySignal(String id, int points, int start, int end) {
        return Signal.builder()
                .id(id)
                .category("TEXT")
                .points(points)
                .explanation("Test signal " + id)
                .matchedText("dummy")
                .start(start)
                .end(end)
                .build();
    }
}
