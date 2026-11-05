package com.cybershield.config;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Cut-off values for classifying composite risk scores into {@code RiskLevel} bands.
 *
 * @param low      lower bound for LOW risk (typically 0)
 * @param medium   threshold where risk becomes MEDIUM (e.g. 25)
 * @param high     threshold where risk becomes HIGH (e.g. 50)
 * @param critical threshold where risk becomes CRITICAL (e.g. 75)
 */
public record ScoringThresholds(
        @JsonProperty("low") int low,
        @JsonProperty("medium") int medium,
        @JsonProperty("high") int high,
        @JsonProperty("critical") int critical
) {

    /**
     * Validates that thresholds are logically ordered and within [0, 100].
     *
     * @throws IllegalArgumentException if bounds are invalid
     */
    public void validate() {
        if (low < 0) {
            throw new IllegalArgumentException("Low threshold cannot be negative: " + low);
        }
        if (medium < low) {
            throw new IllegalArgumentException(
                    "Medium threshold (" + medium + ") cannot be less than low threshold (" + low + ")");
        }
        if (high < medium) {
            throw new IllegalArgumentException(
                    "High threshold (" + high + ") cannot be less than medium threshold (" + medium + ")");
        }
        if (critical < high) {
            throw new IllegalArgumentException(
                    "Critical threshold (" + critical + ") cannot be less than high threshold (" + high + ")");
        }
        if (critical > 100) {
            throw new IllegalArgumentException("Critical threshold cannot exceed 100: " + critical);
        }
    }
}

