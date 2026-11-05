package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("TextDetector — heuristic detection of generic scam and phishing language")
class TextDetectorTest {

    private static TextDetector detector;
    private static RulesConfig rulesConfig;

    @BeforeAll
    static void setUp() {
        rulesConfig = new RulesConfig();
        detector = new TextDetector(rulesConfig);
    }

    @Test
    @DisplayName("1. OTP solicitation is detected with exact offsets")
    void detectOtpSolicitation() {
        String text = "Dear customer, please share your otp to verify your transaction.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.otpSolicitation");
            assertThat(s.category()).isEqualTo("TEXT");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getTextOtpSolicitation());
            assertThat(s.start()).isGreaterThanOrEqualTo(0);
            assertThat(s.end()).isGreaterThan(s.start());
            assertThat(text.substring(s.start(), s.end())).isEqualToIgnoringCase(s.matchedText());
        });
    }

    @Test
    @DisplayName("2. Tolerant of SMS-style spelling ('plz share ur otp')")
    void detectSmsStyleOtpSolicitation() {
        String text = "URGENT plz share ur otp now to unlock";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.otpSolicitation");
            assertThat(s.start()).isGreaterThanOrEqualTo(0);
            assertThat(s.end()).isGreaterThan(s.start());
            assertThat(text.substring(s.start(), s.end())).isEqualToIgnoringCase(s.matchedText());
            assertThat(s.matchedText().toLowerCase()).contains("otp");
        });
    }

    @Test
    @DisplayName("3. Sensitive data: CVV request is detected")
    void detectCvvRequest() {
        String text = "Please enter your cvv to proceed with verification.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.sensitiveData"));
    }

    @Test
    @DisplayName("4. Sensitive data: PIN request is detected")
    void detectPinRequest() {
        String text = "Do not forget to enter your pin.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.sensitiveData"));
    }

    @Test
    @DisplayName("5. Sensitive data: Net banking password request is detected")
    void detectPasswordRequest() {
        String text = "Kindly share your net banking password for sync.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.sensitiveData"));
    }

    @Test
    @DisplayName("6. Sensitive data: Aadhaar card request is detected")
    void detectAadhaarRequest() {
        String text = "Send your aadhaar number immediately.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.sensitiveData"));
    }

    @Test
    @DisplayName("7. Sensitive data: PAN card request is detected")
    void detectPanRequest() {
        String text = "Please provide your pan card number for update.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.sensitiveData"));
    }

    @Test
    @DisplayName("8. Prize bait: lottery winner is detected")
    void detectPrizeBait() {
        String text = "Congratulations you have won a prize in our lucky draw!";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.prizeBait");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getTextPrizeBait());
        });
    }

    @Test
    @DisplayName("9. Refund bait: income tax refund is detected")
    void detectRefundBait() {
        String text = "Your tax refund of Rs 15000 is approved. Claim your refund now.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.prizeBait"));
    }

    @Test
    @DisplayName("10. KYC threat: incomplete KYC notification is detected")
    void detectKycThreat() {
        String text = "Your kyc is incomplete. Submit details today to avoid suspension.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.kycThreat");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getTextKycThreat());
        });
    }

    @Test
    @DisplayName("11. Utility threat: electricity disconnection is detected")
    void detectBillDisconnection() {
        String text = "Your electricity connection will be disconnected tonight due to unpaid bill.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.kycThreat"));
    }

    @Test
    @DisplayName("12. Customs fee / parcel on hold is detected")
    void detectCustomsParcelFee() {
        String text = "Your parcel held at customs. Pay customs duty to receive delivery.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("text.kycThreat"));
    }

    @Test
    @DisplayName("13. Urgency and deadline threats are detected")
    void detectUrgencyPhrases() {
        String text = "Immediate action required! Your account will be closed within 24 hours.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.urgency");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getPhraseCategoryUrgency());
        });
    }

    @Test
    @DisplayName("14. Pressure CTA: 'call immediately' or 'click now' detected")
    void detectPressureCta() {
        String text = "Click now or call immediately to prevent legal proceedings.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.pressureCta");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getTextPressureCta());
        });
    }

    @Test
    @DisplayName("15. Excessive CAPS detection flags aggressive messaging")
    void detectExcessiveCaps() {
        String text = "ATTENTION CUSTOMER YOUR ACCOUNT IS SUSPENDED IMMEDIATELY";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.excessiveCaps");
            assertThat(s.points()).isEqualTo(rulesConfig.getSignalWeights().getTextExcessiveCaps());
            assertThat(s.start()).isGreaterThanOrEqualTo(0);
            assertThat(s.end()).isGreaterThan(s.start());
        });
    }

    @Test
    @DisplayName("16. Excessive exclamation marks detection flags manufactured panic")
    void detectExcessiveExclamations() {
        String text = "Warning!!! Act fast or face arrest!!!";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anySatisfy(s -> {
            assertThat(s.id()).isEqualTo("text.excessiveExclamation");
            assertThat(s.start()).isGreaterThanOrEqualTo(0);
            assertThat(s.end()).isGreaterThan(s.start());
            assertThat(text.substring(s.start(), s.end())).contains("!");
        });
    }

    @Test
    @DisplayName("17. Safe, benign message produces no signals")
    void benignMessage_producesNoSignals() {
        String text = "Hi team, let's meet tomorrow at 10 AM to discuss the quarterly project roadmap.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).isEmpty();
    }
}

