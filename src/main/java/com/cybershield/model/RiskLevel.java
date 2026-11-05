package com.cybershield.model;

/**
 * Risk level bands mapped to the composite score.
 *
 *   LOW      0 – 24
 *   MEDIUM  25 – 49
 *   HIGH    50 – 74
 *   CRITICAL 75 – 100
 */
public enum RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL;

    public static RiskLevel fromScore(int score) {
        if (score < 25)  return LOW;
        if (score < 50)  return MEDIUM;
        if (score < 75)  return HIGH;
        return CRITICAL;
    }
}
