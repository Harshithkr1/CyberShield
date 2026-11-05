package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.config.SignalWeights;
import com.cybershield.model.Signal;
import com.cybershield.util.PhraseScanner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects generic phishing/scam language patterns in free text:
 * <ul>
 *   <li>Urgency and threats (deadline pressure, legal threats, account termination)</li>
 *   <li>Requests for sensitive data (OTP, PIN, CVV, password, Aadhaar, PAN)</li>
 *   <li>Prize or refund bait (fake lotteries, rewards, cashback)</li>
 *   <li>KYC threats, bill disconnections, customs fee, undelivered parcels</li>
 *   <li>Pressure call-to-actions to click or call immediately</li>
 *   <li>Excessive capital letters and exclamation marks</li>
 * </ul>
 *
 * <p>All phrases and scoring weights come from {@link RulesConfig}.
 * Matching is case-insensitive and tolerant of SMS-style spellings.
 * Never opens any network connection.</p>
 */
@Component
public class TextDetector implements Detector {

    private static final String CATEGORY = "TEXT";
    private static final Pattern CAPS_WORD_PATTERN = Pattern.compile("\\b[A-Z]{3,}\\b");

    private final RulesConfig rulesConfig;

    public TextDetector(RulesConfig rulesConfig) {
        this.rulesConfig = Objects.requireNonNull(rulesConfig, "rulesConfig cannot be null");
    }

    @Override
    public String name() {
        return "TextDetector";
    }

    @Override
    public List<Signal> detect(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        SignalWeights weights = rulesConfig.getSignalWeights();
        List<Signal> signals = new ArrayList<>();

        // 1. OTP solicitation
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getOtpSolicitationPhrases(),
                "text.otpSolicitation",
                CATEGORY,
                weights.getTextOtpSolicitation(),
                "Request for One-Time Password (OTP) detected. Legitimate entities never ask you to share your OTP."));

        // 2. Sensitive financial & identity data requests (PIN, CVV, password, Aadhaar, PAN)
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getSensitiveDataPhrases(),
                "text.sensitiveData",
                CATEGORY,
                weights.getTextSensitiveDataRequest(),
                "Request for sensitive financial or identity details (PIN, CVV, password, Aadhaar, PAN) detected."));

        // 3. Prize or refund bait
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getPrizeBaitPhrases(),
                "text.prizeBait",
                CATEGORY,
                weights.getTextPrizeBait(),
                "Prize, lottery, or refund bait detected. Scammers use false rewards to lure victims."));

        // 4. KYC threats, utility disconnection, customs fee, undelivered parcels
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getKycThreatPhrases(),
                "text.kycThreat",
                CATEGORY,
                weights.getTextKycThreat(),
                "Threat of account suspension, KYC expiration, utility disconnection, or parcel customs fee detected."));

        // 5. Urgency and threats
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getUrgencyPhrases(),
                "text.urgency",
                CATEGORY,
                weights.getPhraseCategoryUrgency(),
                "High-urgency language detected. Scammers create artificial pressure to force hasty decisions."));

        // 6. Generic phishing phrases
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getPhishingPhrases(),
                "text.phishing",
                CATEGORY,
                weights.getPhraseCategoryPhishing(),
                "Common phishing phrase detected."));

        // 7. Pressure CTA (click or call immediately)
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getPressureCtaPhrases(),
                "text.pressureCta",
                CATEGORY,
                weights.getTextPressureCta(),
                "Pressure call-to-action urging immediate clicking or calling detected."));

        // 8. Excessive CAPS (>= 4 words)
        int capsWordCount = PhraseScanner.countExcessiveCapsWords(text);
        if (capsWordCount >= 4) {
            int start = -1;
            int end = -1;
            Matcher m = CAPS_WORD_PATTERN.matcher(text);
            while (m.find()) {
                if (start == -1) start = m.start();
                end = m.end();
            }
            if (start == -1) {
                start = 0;
                end = text.length();
            }
            signals.add(Signal.builder()
                    .id("text.excessiveCaps")
                    .category(CATEGORY)
                    .points(weights.getTextExcessiveCaps())
                    .explanation("Excessive uppercase words detected (" + capsWordCount + " words); often used to induce panic or urgency.")
                    .matchedText(text.substring(start, end))
                    .start(start)
                    .end(end)
                    .build());
        }

        // 9. Excessive exclamation marks (>= 3)
        int exclamationCount = PhraseScanner.countExclamationMarks(text);
        if (exclamationCount >= 3) {
            int first = text.indexOf('!');
            int last = text.lastIndexOf('!');
            signals.add(Signal.builder()
                    .id("text.excessiveExclamation")
                    .category(CATEGORY)
                    .points(weights.getTextExcessiveExclamation())
                    .explanation("Excessive exclamation marks detected (" + exclamationCount + "); common tactic to manufacture false urgency.")
                    .matchedText(text.substring(first, last + 1))
                    .start(first)
                    .end(last + 1)
                    .build());
        }

        return List.copyOf(signals);
    }
}
