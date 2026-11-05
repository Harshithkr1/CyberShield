package com.cybershield.config;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
import com.fasterxml.jackson.annotation.JsonAnySetter;
import com.fasterxml.jackson.annotation.JsonCreator;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Scoring weights assigned to individual heuristic detection signals.
 */
public class SignalWeights {

    private final Map<String, Integer> weights = new LinkedHashMap<>();

    public SignalWeights() {
    }

    @JsonCreator
    public SignalWeights(Map<String, Integer> initialWeights) {
        if (initialWeights != null) {
            this.weights.putAll(initialWeights);
        }
    }

    @JsonAnySetter
    public void setWeight(String key, int value) {
        this.weights.put(key, value);
    }

    @JsonAnyGetter
    public Map<String, Integer> getWeights() {
        return Collections.unmodifiableMap(weights);
    }

    public int getWeight(String key, int defaultValue) {
        return weights.getOrDefault(key, defaultValue);
    }

    public boolean containsKey(String key) {
        return weights.containsKey(key);
    }

    public boolean isEmpty() {
        return weights.isEmpty();
    }

    public int size() {
        return weights.size();
    }

    // ── Typed getters for known detection heuristics ─────────────────────────

    public int getPhraseCategoryPhishing()      { return getWeight("phraseCategoryPhishing", 12); }
    public int getPhraseCategoryDigitalArrest() { return getWeight("phraseCategoryDigitalArrest", 20); }
    public int getPhraseCategoryMaliciousApp()  { return getWeight("phraseCategoryMaliciousApp", 15); }
    public int getPhraseCategoryUrgency()       { return getWeight("phraseCategoryUrgency", 8); }
    public int getUrlSuspiciousTld()            { return getWeight("urlSuspiciousTld", 10); }
    public int getUrlShortener()                { return getWeight("urlShortener", 8); }
    public int getUrlKeyword()                  { return getWeight("urlKeyword", 10); }
    public int getUrlTyposquatLevenshtein1()    { return getWeight("urlTyposquatLevenshtein1", 20); }
    public int getUrlTyposquatLevenshtein2()    { return getWeight("urlTyposquatLevenshtein2", 10); }
    public int getUrlExcessiveSubdomains()       { return getWeight("urlExcessiveSubdomains", 8); }
    public int getUrlFreeHosting()               { return getWeight("urlFreeHosting", 7); }
    public int getUrlIpAddress()                { return getWeight("urlIpAddress", 14); }
    public int getUrlPortInUrl()                { return getWeight("urlPortInUrl", 10); }
    public int getUrlAtSymbol()                 { return getWeight("urlAtSymbol", 15); }
    public int getUrlDoubleScheme()             { return getWeight("urlDoubleScheme", 18); }
    public int getTextExcessiveCaps()           { return getWeight("textExcessiveCaps", 5); }
    public int getTextOtpSolicitation()         { return getWeight("textOtpSolicitation", 18); }
    public int getTextSensitiveDataRequest()    { return getWeight("textSensitiveDataRequest", 16); }
    public int getTextPrizeBait()               { return getWeight("textPrizeBait", 12); }
    public int getTextKycThreat()               { return getWeight("textKycThreat", 14); }
    public int getTextPressureCta()             { return getWeight("textPressureCta", 10); }
    public int getTextExcessiveExclamation()    { return getWeight("textExcessiveExclamation", 5); }
    public int getCriticalComboScore()          { return getWeight("criticalComboScore", 85); }
    public int getHighComboScore()              { return getWeight("highComboScore", 65); }
    public int getDiminishingFactorPercent()    { return getWeight("diminishingFactorPercent", 80); }
}

