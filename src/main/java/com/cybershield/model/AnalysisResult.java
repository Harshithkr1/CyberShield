package com.cybershield.model;

import java.util.List;

/**
 * The full analysis result returned by the REST API.
 */
public record AnalysisResult(
        int score,
        RiskLevel level,
        String summary,
        String scamType,
        List<Signal> signals,
        List<String> urls,
        MlResult ml
) {
    /**
     * Optional machine-learning sub-result (null when useMl=false).
     */
    public record MlResult(
            double textProbability,
            double urlProbability,
            List<String> topWords,
            int ruleScore,
            int mlScore
    ) {
        public MlResult(double textProbability, double urlProbability, List<String> topWords) {
            this(textProbability, urlProbability, topWords, 0, 0);
        }
    }
}
