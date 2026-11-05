package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import com.cybershield.util.PhraseScanner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Objects;

/**
 * Detects "digital arrest" scam patterns prevalent in India:
 * <ul>
 *   <li>Impersonation of law enforcement & agencies: CBI, police, customs, NCB, ED, TRAI, RBI, cyber cell, court</li>
 *   <li>False accusations: drug parcels, fake passports, money laundering, SIM or Aadhaar misuse</li>
 *   <li>Coercion tactics: "stay on video call", "do not tell anyone", "digital arrest"</li>
 *   <li>Financial extortion: demands to transfer funds to a "safe account" or for "RBI verification"</li>
 * </ul>
 *
 * <p>All phrases and scoring weights come from {@link RulesConfig}.
 * Explanation text includes: "A real agency never arrests over a video call and never asks for payment to a private account."
 * Never opens any network connection.</p>
 */
@Component
public class DigitalArrestDetector implements Detector {

    private static final String CATEGORY = "DIGITAL_ARREST";
    private static final String SIGNAL_ID = "digitalArrest.phrase";
    private static final String EXPLANATION_PREFIX =
            "Digital arrest scam pattern detected. A real agency never arrests over a video call and never asks for payment to a private account.";

    private final RulesConfig rulesConfig;

    public DigitalArrestDetector(RulesConfig rulesConfig) {
        this.rulesConfig = Objects.requireNonNull(rulesConfig, "rulesConfig cannot be null");
    }

    @Override
    public String name() {
        return "DigitalArrestDetector";
    }

    @Override
    public List<Signal> detect(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        int points = rulesConfig.getSignalWeights().getPhraseCategoryDigitalArrest();
        List<String> phrases = rulesConfig.getDigitalArrestPhrases();

        return PhraseScanner.scan(
                text,
                phrases,
                SIGNAL_ID,
                CATEGORY,
                points,
                EXPLANATION_PREFIX);
    }
}
