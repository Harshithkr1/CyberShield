package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("DigitalArrestDetector — detection of law enforcement impersonation & extortion patterns")
class DigitalArrestDetectorTest {

    private static DigitalArrestDetector detector;
    private static RulesConfig rulesConfig;

    @BeforeAll
    static void setUp() {
        rulesConfig = new RulesConfig();
        detector = new DigitalArrestDetector(rulesConfig);
    }

    @Test
    @DisplayName("1. 'Digital arrest' phrase detection with exact explanation")
    void detectDigitalArrestDirect() {
        String text = "You are placed under digital arrest by authorities.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).isNotEmpty();
        Signal signal = signals.get(0);
        assertThat(signal.id()).isEqualTo("digitalArrest.phrase");
        assertThat(signal.category()).isEqualTo("DIGITAL_ARREST");
        assertThat(signal.points()).isEqualTo(rulesConfig.getSignalWeights().getPhraseCategoryDigitalArrest());
        assertThat(signal.explanation()).contains("A real agency never arrests over a video call and never asks for payment to a private account.");
        assertThat(signal.start()).isGreaterThanOrEqualTo(0);
        assertThat(signal.end()).isGreaterThan(signal.start());
        assertThat(text.substring(signal.start(), signal.end())).isEqualToIgnoringCase(signal.matchedText());
    }

    @Test
    @DisplayName("2. Impersonation of CBI officer")
    void detectCbiOfficer() {
        String text = "I am a CBI officer calling from headquarters.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("3. Impersonation of NCB (Narcotics Control Bureau)")
    void detectNcb() {
        String text = "Narcotics Control Bureau has seized a parcel addressed to you.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("4. Impersonation of ED (Enforcement Directorate)")
    void detectEd() {
        String text = "Notice from Enforcement Directorate regarding suspicious transactions.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("5. Impersonation of Cyber Cell / Police")
    void detectCyberCell() {
        String text = "Cyber cell has registered an FIR against your number.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("6. Drug parcel accusation")
    void detectDrugParcel() {
        String text = "A drug parcel in your name was intercepted by Mumbai customs.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("7. Money laundering allegation")
    void detectMoneyLaundering() {
        String text = "You are suspected of money laundering and hawala transactions.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("8. Aadhaar / SIM card misuse")
    void detectAadhaarMisuse() {
        String text = "Your aadhaar misuse has been flagged in multiple cyber fraud cases.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("9. Demand to stay on video call")
    void detectStayOnVideoCall() {
        String text = "Do not disconnect, stay on video call or you will be arrested.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("10. Secrecy demand: do not tell anyone")
    void detectDoNotTellAnyone() {
        String text = "This is a confidential national security matter, do not tell anyone.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("11. Safe account extortion demand")
    void detectSafeAccount() {
        String text = "You must transfer your funds to a safe account for government audit.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("12. RBI verification demand")
    void detectRbiVerification() {
        String text = "Deposit money for RBI verification to prove your innocence.";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).anyMatch(s -> s.id().equals("digitalArrest.phrase"));
    }

    @Test
    @DisplayName("13. Safe ordinary conversation produces no signals")
    void safeMessageProducesNoSignals() {
        String text = "Hello grandma, hope you are feeling better today. See you on Sunday!";
        List<Signal> signals = detector.detect(text);

        assertThat(signals).isEmpty();
    }
}

