package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("MaliciousAppDetector — detection of rogue apps, APK links, and remote-access tools")
class MaliciousAppDetectorTest {

    private static MaliciousAppDetector detector;
    private static RulesConfig rulesConfig;

    @BeforeAll
    static void setUp() {
        rulesConfig = new RulesConfig();
        detector = new MaliciousAppDetector(rulesConfig);
    }

    @Test
    @DisplayName("1. Direct APK download link is detected via regex with exact offsets")
    void detectApkLink() {
        String text = "Click here to install update: http://attacker.com/files/bank-update.apk immediately.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("maliciousApp.apkLink");
            assertThat(s.category()).isEqualTo("MALICIOUS_APP");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getPhraseCategoryMaliciousApp());
            assertThat(s.start()).isGreaterThanOrEqualTo(0);
            assertThat(s.end()).isGreaterThan(s.start());
            assertThat(text.substring(s.start(), s.end())).isEqualTo(s.matchedText());
            assertThat(s.matchedText()).contains("bank-update.apk");
        });
    }

    @Test
    @DisplayName("2. Bare APK filename reference is detected")
    void detectApkFilename() {
        String text = "Please download and install payload.apk on your phone.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.apkLink")
                && s.matchedText().equals("payload.apk"));
    }

    @Test
    @DisplayName("3. 'Install from unknown sources' prompt is flagged")
    void detectUnknownSources() {
        String text = "Go to device settings and enable unknown sources to install our helper.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("4. AnyDesk remote-access tool prompt is detected")
    void detectAnyDesk() {
        String text = "Please download anydesk and share your anydesk id with our support agent.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("5. TeamViewer remote-access tool prompt is detected")
    void detectTeamViewer() {
        String text = "Install teamviewer so our executive can connect to your mobile.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("6. QuickSupport remote-access tool prompt is detected")
    void detectQuickSupport() {
        String text = "Please install quick support to enable remote debugging.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("7. RustDesk remote-access tool prompt is detected")
    void detectRustDesk() {
        String text = "Download rustdesk for immediate technical resolution.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("8. Accessibility permission request is flagged")
    void detectAccessibilityPermission() {
        String text = "Open settings and grant accessibility permission to activate the app.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("9. SMS permission request is flagged")
    void detectSmsPermission() {
        String text = "Application requires grant sms access to verify incoming OTPs.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("10. Screen share request is flagged")
    void detectScreenShare() {
        String text = "Please share your screen during this support call.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("11. Fake bank app lure is flagged")
    void detectFakeBankApp() {
        String text = "Download our custom bank app to access exclusive interest rates.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("12. Fake KYC app download lure is flagged")
    void detectKycApp() {
        String text = "Use this kyc app download to upload your documents immediately.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("13. Fake RTO challan app lure is flagged")
    void detectRtoChallanApp() {
        String text = "Pending traffic violation detected. Install rto challan app to settle.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("14. Fake PM Kisan app lure is flagged")
    void detectPmKisanApp() {
        String text = "Install pm kisan app to receive your government installment today.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("15. Fake electricity bill app lure is flagged")
    void detectElectricityBillApp() {
        String text = "Avoid power cut by downloading the electricity bill app now.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("maliciousApp.phrase"));
    }

    @Test
    @DisplayName("16. Safe app store recommendation produces no signals")
    void benignAppRecommendation_producesNoSignals() {
        String text = "You can download our official application directly from the Google Play Store.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).isEmpty();
    }
}

