package com.cybershield.service;

import com.cybershield.config.RulesConfig;
import com.cybershield.config.ScoringThresholds;
import com.cybershield.model.RiskLevel;
import com.cybershield.model.Signal;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Converts a list of detected {@link Signal}s into a clamped 0–100 composite score
 * with diminishing returns, eliminates overlapping double-counted signals,
 * evaluates combination attack patterns, and derives risk levels, summaries, and scam types.
 *
 * <p>All thresholds and weight numbers are loaded dynamically from {@link RulesConfig}
 * (backed by {@code rules.json}). Never makes any network calls.</p>
 */
@Component
public class ScoringEngine {

    private final RulesConfig rulesConfig;

    private static final Set<String> AUTHORITY_TERMS = Set.of(
            "cbi", "police", "customs", "ncb", "ed", "trai", "rbi",
            "cyber cell", "court", "supreme court", "high court",
            "narcotics", "enforcement directorate"
    );

    private static final Set<String> PAYMENT_TERMS = Set.of(
            "safe account", "rbi verification", "transfer to safe", "move your money",
            "move money", "pay to avoid", "pay fine", "pay customs", "customs fee",
            "clearance fee", "deposit", "settle the case"
    );

    private static final Set<String> SECRECY_TERMS = Set.of(
            "do not tell anyone", "do not disconnect", "stay on video call",
            "stay on the call", "keep the video call on", "confidential",
            "skype", "google meet", "whatsapp video"
    );

    public ScoringEngine(RulesConfig rulesConfig) {
        this.rulesConfig = Objects.requireNonNull(rulesConfig, "rulesConfig cannot be null");
    }

    public RulesConfig getRulesConfig() {
        return rulesConfig;
    }

    /**
     * Filters out redundant and overlapping signals so that multiple detectors or sub-phrases
     * matching the same text slice do not double-count against the victim text.
     */
    public List<Signal> filterOverlapping(List<Signal> signals) {
        if (signals == null || signals.isEmpty()) {
            return List.of();
        }

        List<Signal> styleSignals = new ArrayList<>();
        List<Signal> spanSignals  = new ArrayList<>();

        for (Signal s : signals) {
            if (s.id().startsWith("text.excessive")) {
                styleSignals.add(s);
            } else if (s.start() >= 0 && s.end() > s.start()) {
                spanSignals.add(s);
            } else {
                styleSignals.add(s);
            }
        }

        // Sort span signals: highest points first, then longer span first
        spanSignals.sort((a, b) -> {
            int cmp = Integer.compare(b.points(), a.points());
            if (cmp != 0) return cmp;
            return Integer.compare(b.end() - b.start(), a.end() - a.start());
        });

        List<Signal> acceptedSpans = new ArrayList<>();
        for (Signal candidate : spanSignals) {
            boolean overlaps = false;
            for (Signal accepted : acceptedSpans) {
                if (isOverlapping(candidate, accepted)) {
                    overlaps = true;
                    break;
                }
            }
            if (!overlaps) {
                acceptedSpans.add(candidate);
            }
        }

        List<Signal> combined = new ArrayList<>();
        combined.addAll(acceptedSpans);
        combined.addAll(styleSignals);

        // Retain stable presentation order by text position
        combined.sort(Comparator.comparingInt(Signal::start));
        return List.copyOf(combined);
    }

    private boolean isOverlapping(Signal s1, Signal s2) {
        // Exact identical ID and range is a direct duplicate
        if (s1.id().equals(s2.id()) && s1.start() == s2.start() && s1.end() == s2.end()) {
            return true;
        }

        // Two distinct URL heuristics on the same URL are complementary
        if (s1.category().equals("URL") && s2.category().equals("URL")) {
            return false;
        }

        // Check character span overlap: max(start) < min(end)
        boolean hasSpanOverlap = Math.max(s1.start(), s2.start()) < Math.min(s1.end(), s2.end());
        if (!hasSpanOverlap) {
            return false;
        }

        // If a text phrase was matched inside a URL, drop the redundant text signal
        boolean s1IsText = s1.category().equals("TEXT");
        boolean s2IsText = s2.category().equals("TEXT");
        if ((s1.category().equals("URL") && s2IsText) || (s1IsText && s2.category().equals("URL"))) {
            return true;
        }

        // Both are text phrase signals whose character positions collide (e.g. subphrase matches)
        if (s1IsText && s2IsText) {
            return true;
        }

        // Both are digital arrest phrases overlapping each other
        if (s1.category().equals("DIGITAL_ARREST") && s2.category().equals("DIGITAL_ARREST")) {
            return true;
        }

        // Digital arrest phrase overlapping a generic phishing text phrase
        if ((s1.category().equals("DIGITAL_ARREST") && s2IsText) || (s1IsText && s2.category().equals("DIGITAL_ARREST"))) {
            return true;
        }

        return false;
    }

    /**
     * Compute composite 0–100 score from signals with diminishing returns
     * and combination bonuses.
     */
    public int score(List<Signal> signals) {
        if (signals == null || signals.isEmpty()) {
            return 0;
        }

        // Filter overlapping signals first if not already done
        List<Signal> distinct = filterOverlapping(signals);

        // Sort signals descending by points for diminishing returns
        List<Signal> sorted = new ArrayList<>(distinct);
        sorted.sort(Comparator.comparingInt(Signal::points).reversed());

        double dimFactor = rulesConfig.getSignalWeights().getDiminishingFactorPercent() / 100.0;
        if (dimFactor <= 0.0 || dimFactor > 1.0) {
            dimFactor = 0.80;
        }

        double accumulated = 0.0;
        for (int i = 0; i < sorted.size(); i++) {
            accumulated += sorted.get(i).points() * Math.pow(dimFactor, i);
        }

        int score = (int) Math.round(accumulated);

        // Combination 1: Authority impersonation + payment demand + secrecy forces Critical
        if (hasAuthorityImpersonation(distinct) && hasPaymentDemand(distinct) && hasSecrecy(distinct)) {
            int criticalMin = rulesConfig.getSignalWeights().getCriticalComboScore();
            score = Math.max(score, criticalMin);
        }

        // Combination 2: OTP request + urgency + suspicious link forces at least High
        if (hasOtpRequest(distinct) && hasUrgency(distinct) && hasSuspiciousLink(distinct)) {
            int highMin = rulesConfig.getSignalWeights().getHighComboScore();
            score = Math.max(score, highMin);
        }

        return Math.max(0, Math.min(score, 100));
    }

    /**
     * Derive RiskLevel from score using cutoffs defined in rules.json.
     */
    public RiskLevel level(int score) {
        ScoringThresholds t = rulesConfig.getScoringThresholds();
        if (score < t.medium())   return RiskLevel.LOW;
        if (score < t.high())     return RiskLevel.MEDIUM;
        if (score < t.critical()) return RiskLevel.HIGH;
        return RiskLevel.CRITICAL;
    }

    /**
     * Derive human-readable explanation summary.
     */
    public String summary(int score, List<Signal> signals, RiskLevel level) {
        if (signals == null || signals.isEmpty()) {
            return "No suspicious patterns detected. Always stay vigilant.";
        }

        if (hasAuthorityImpersonation(signals) && hasPaymentDemand(signals) && hasSecrecy(signals)) {
            return "Critical threat detected: Coercive law enforcement impersonation demanding secret money transfer. A real agency never arrests over a video call and never asks for payment to a private account.";
        }

        if (hasOtpRequest(signals) && hasUrgency(signals) && hasSuspiciousLink(signals)) {
            return "High risk phishing attack: Urgent pressure to share your One-Time Password (OTP) via a suspicious link.";
        }

        return switch (level) {
            case LOW      -> "A few minor patterns were noted. Treat with light caution.";
            case MEDIUM   -> "Several suspicious patterns found. Verify before acting.";
            case HIGH     -> "Multiple high-risk signals detected. Do not click links or share data.";
            case CRITICAL -> "Extremely high risk. This is very likely a scam. Stop all interaction.";
        };
    }

    /**
     * Infer the dominant scam type from the signals and combination analysis.
     */
    public String scamType(List<Signal> signals) {
        if (signals == null || signals.isEmpty()) {
            return "SAFE";
        }

        boolean hasDigitalArrest = signals.stream().anyMatch(s -> s.category().equals("DIGITAL_ARREST"));
        if (hasDigitalArrest && (hasSecrecy(signals) || hasPaymentDemand(signals) || hasAuthorityImpersonation(signals))) {
            return "DIGITAL_ARREST";
        }

        if (hasOtpRequest(signals) || signals.stream().anyMatch(s -> s.id().equals("text.sensitiveData"))) {
            return "CREDENTIAL_PHISHING";
        }

        boolean hasAppSignal = signals.stream()
                .anyMatch(s -> s.category().equals("MALICIOUS_APP") || s.id().startsWith("maliciousApp."));
        if (hasAppSignal) {
            return "MALICIOUS_APP";
        }

        boolean hasUrlSignal = signals.stream().anyMatch(s -> s.category().equals("URL"));
        if (hasUrlSignal) {
            return "PHISHING";
        }

        // Dominant category = category with highest total points
        return signals.stream()
                .collect(java.util.stream.Collectors.groupingBy(
                        Signal::category,
                        java.util.stream.Collectors.summingInt(Signal::points)
                ))
                .entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse("UNKNOWN");
    }

    // ── Combination pattern matchers ──────────────────────────────────────────

    private boolean hasAuthorityImpersonation(List<Signal> signals) {
        return signals.stream().anyMatch(s -> {
            if (s.category().equals("DIGITAL_ARREST")) return true;
            String text = s.matchedText().toLowerCase(Locale.ROOT);
            return AUTHORITY_TERMS.stream().anyMatch(text::contains);
        });
    }

    private boolean hasPaymentDemand(List<Signal> signals) {
        return signals.stream().anyMatch(s -> {
            String text = s.matchedText().toLowerCase(Locale.ROOT);
            return PAYMENT_TERMS.stream().anyMatch(text::contains);
        });
    }

    private boolean hasSecrecy(List<Signal> signals) {
        return signals.stream().anyMatch(s -> {
            String text = s.matchedText().toLowerCase(Locale.ROOT);
            return SECRECY_TERMS.stream().anyMatch(text::contains);
        });
    }

    private boolean hasOtpRequest(List<Signal> signals) {
        return signals.stream().anyMatch(s ->
                s.id().equals("text.otpSolicitation") || s.matchedText().toLowerCase(Locale.ROOT).contains("otp"));
    }

    private boolean hasUrgency(List<Signal> signals) {
        return signals.stream().anyMatch(s ->
                s.id().equals("text.urgency") || s.id().equals("text.pressureCta")
                        || s.matchedText().toLowerCase(Locale.ROOT).contains("urgent")
                        || s.matchedText().toLowerCase(Locale.ROOT).contains("immediate")
                        || s.matchedText().toLowerCase(Locale.ROOT).contains("hours"));
    }

    private boolean hasSuspiciousLink(List<Signal> signals) {
        return signals.stream().anyMatch(s ->
                s.category().equals("URL") || s.id().startsWith("url.") || s.id().equals("maliciousApp.apkLink"));
    }
}
