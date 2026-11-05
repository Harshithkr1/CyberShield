package com.cybershield.config;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Data transfer model for deserializing {@code rules.json} with Jackson.
 *
 * <p>Supports both flat top-level keys and nested structures (e.g. {@code scoring.thresholds},
 * {@code phrases.phishing}) for maximum configuration flexibility.
 * Unknown JSON keys are silently ignored to allow forward-compatible additions.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class RulesData {

    @JsonProperty("scoringThresholds")
    @JsonAlias({"thresholds"})
    private ScoringThresholds scoringThresholds;

    @JsonProperty("signalWeights")
    @JsonAlias({"weights"})
    private SignalWeights signalWeights;

    @JsonProperty("scoring")
    private ScoringContainer scoring;

    @JsonProperty("brands")
    private List<Brand> brands;

    @JsonProperty("urlShorteners")
    private List<String> urlShorteners;

    @JsonProperty("suspiciousTlds")
    private List<String> suspiciousTlds;

    @JsonProperty("freeHostingDomains")
    private List<String> freeHostingDomains;

    @JsonProperty("urlKeywords")
    private List<String> urlKeywords;

    @JsonProperty("phishingPhrases")
    private List<String> phishingPhrases;

    @JsonProperty("digitalArrestPhrases")
    private List<String> digitalArrestPhrases;

    @JsonProperty("maliciousAppPhrases")
    private List<String> maliciousAppPhrases;

    @JsonProperty("urgencyPhrases")
    @JsonAlias({"urgencyKeywords"})
    private List<String> urgencyPhrases;

    // ── New phrase categories for TextDetector ────────────────────────────────

    @JsonProperty("otpSolicitationPhrases")
    private List<String> otpSolicitationPhrases;

    @JsonProperty("sensitiveDataPhrases")
    private List<String> sensitiveDataPhrases;

    @JsonProperty("prizeBaitPhrases")
    private List<String> prizeBaitPhrases;

    @JsonProperty("kycThreatPhrases")
    private List<String> kycThreatPhrases;

    @JsonProperty("pressureCtaPhrases")
    private List<String> pressureCtaPhrases;

    @JsonProperty("mlScoring")
    private MlScoringConfig mlScoring;

    @JsonProperty("phrases")
    private PhrasesContainer phrases;

    public record MlScoringConfig(
            double ruleWeight,
            double mlWeight,
            int noSignalCap
    ) {
        public static final MlScoringConfig DEFAULT = new MlScoringConfig(0.6, 0.4, 49);
    }

    public MlScoringConfig getMlScoring() {
        return mlScoring != null ? mlScoring : MlScoringConfig.DEFAULT;
    }

    // ── Resolvers that reconcile flat and nested keys ─────────────────────────

    public ScoringThresholds resolveScoringThresholds() {
        if (scoringThresholds != null) return scoringThresholds;
        if (scoring != null && scoring.thresholds() != null) return scoring.thresholds();
        return null;
    }

    public SignalWeights resolveSignalWeights() {
        if (signalWeights != null) return signalWeights;
        if (scoring != null && scoring.weights() != null) return scoring.weights();
        return null;
    }

    public List<String> resolvePhishingPhrases() {
        if (phishingPhrases != null) return phishingPhrases;
        if (phrases != null && phrases.phishing() != null) return phrases.phishing();
        return null;
    }

    public List<String> resolveDigitalArrestPhrases() {
        if (digitalArrestPhrases != null) return digitalArrestPhrases;
        if (phrases != null && phrases.digitalArrest() != null) return phrases.digitalArrest();
        return null;
    }

    public List<String> resolveMaliciousAppPhrases() {
        if (maliciousAppPhrases != null) return maliciousAppPhrases;
        if (phrases != null && phrases.maliciousApp() != null) return phrases.maliciousApp();
        return null;
    }

    public List<String> resolveUrgencyPhrases() {
        if (urgencyPhrases != null) return urgencyPhrases;
        if (phrases != null && phrases.urgency() != null) return phrases.urgency();
        return null;
    }

    // ── Getters / Setters ─────────────────────────────────────────────────────

    public ScoringThresholds getScoringThresholds() { return scoringThresholds; }
    public void setScoringThresholds(ScoringThresholds v) { this.scoringThresholds = v; }

    public SignalWeights getSignalWeights() { return signalWeights; }
    public void setSignalWeights(SignalWeights v) { this.signalWeights = v; }

    public ScoringContainer getScoring() { return scoring; }
    public void setScoring(ScoringContainer v) { this.scoring = v; }

    public List<Brand> getBrands() { return brands; }
    public void setBrands(List<Brand> v) { this.brands = v; }

    public List<String> getUrlShorteners() { return urlShorteners; }
    public void setUrlShorteners(List<String> v) { this.urlShorteners = v; }

    public List<String> getSuspiciousTlds() { return suspiciousTlds; }
    public void setSuspiciousTlds(List<String> v) { this.suspiciousTlds = v; }

    public List<String> getFreeHostingDomains() { return freeHostingDomains; }
    public void setFreeHostingDomains(List<String> v) { this.freeHostingDomains = v; }

    public List<String> getUrlKeywords() { return urlKeywords; }
    public void setUrlKeywords(List<String> v) { this.urlKeywords = v; }

    public List<String> getPhishingPhrases() { return phishingPhrases; }
    public void setPhishingPhrases(List<String> v) { this.phishingPhrases = v; }

    public List<String> getDigitalArrestPhrases() { return digitalArrestPhrases; }
    public void setDigitalArrestPhrases(List<String> v) { this.digitalArrestPhrases = v; }

    public List<String> getMaliciousAppPhrases() { return maliciousAppPhrases; }
    public void setMaliciousAppPhrases(List<String> v) { this.maliciousAppPhrases = v; }

    public List<String> getUrgencyPhrases() { return urgencyPhrases; }
    public void setUrgencyPhrases(List<String> v) { this.urgencyPhrases = v; }

    public List<String> getOtpSolicitationPhrases() { return otpSolicitationPhrases; }
    public void setOtpSolicitationPhrases(List<String> v) { this.otpSolicitationPhrases = v; }

    public List<String> getSensitiveDataPhrases() { return sensitiveDataPhrases; }
    public void setSensitiveDataPhrases(List<String> v) { this.sensitiveDataPhrases = v; }

    public List<String> getPrizeBaitPhrases() { return prizeBaitPhrases; }
    public void setPrizeBaitPhrases(List<String> v) { this.prizeBaitPhrases = v; }

    public List<String> getKycThreatPhrases() { return kycThreatPhrases; }
    public void setKycThreatPhrases(List<String> v) { this.kycThreatPhrases = v; }

    public List<String> getPressureCtaPhrases() { return pressureCtaPhrases; }
    public void setPressureCtaPhrases(List<String> v) { this.pressureCtaPhrases = v; }

    public PhrasesContainer getPhrases() { return phrases; }
    public void setPhrases(PhrasesContainer v) { this.phrases = v; }

    // ── Nested container records for alternative JSON shapes ─────────────────

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ScoringContainer(
            @JsonProperty("thresholds") ScoringThresholds thresholds,
            @JsonProperty("weights") SignalWeights weights
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PhrasesContainer(
            @JsonProperty("phishing") List<String> phishing,
            @JsonProperty("digitalArrest") List<String> digitalArrest,
            @JsonProperty("maliciousApp") List<String> maliciousApp,
            @JsonProperty("urgency") List<String> urgency
    ) {}
}
