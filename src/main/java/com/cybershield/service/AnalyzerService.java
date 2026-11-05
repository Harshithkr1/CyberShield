package com.cybershield.service;

import com.cybershield.config.RulesData;
import com.cybershield.detector.Detector;
import com.cybershield.ml.TextClassifier;
import com.cybershield.ml.UrlClassifier;
import com.cybershield.model.AnalysisResult;
import com.cybershield.model.RiskLevel;
import com.cybershield.model.Signal;
import com.cybershield.util.UrlExtractor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * Orchestrates the analysis pipeline:
 * <ol>
 *   <li>Run all registered {@link Detector}s.</li>
 *   <li>Collect and deduplicate overlapping signals.</li>
 *   <li>Extract URLs from the raw text.</li>
 *   <li>Score via {@link ScoringEngine}.</li>
 *   <li>Optionally combine with ML layer (when useMl is true).</li>
 *   <li>Attach summary, risk level, and scam type.</li>
 * </ol>
 */
@Service
public class AnalyzerService {

    private final List<Detector> detectors;
    private final ScoringEngine  scoringEngine;
    private final TextClassifier textClassifier;
    private final UrlClassifier  urlClassifier;

    public AnalyzerService(List<Detector> detectors, ScoringEngine scoringEngine) {
        this(detectors, scoringEngine, null, null);
    }

    @Autowired
    public AnalyzerService(List<Detector> detectors,
                           ScoringEngine scoringEngine,
                           @Autowired(required = false) TextClassifier textClassifier,
                           @Autowired(required = false) UrlClassifier urlClassifier) {
        this.detectors      = detectors;
        this.scoringEngine  = scoringEngine;
        this.textClassifier = textClassifier;
        this.urlClassifier  = urlClassifier;
    }

    /**
     * Run the full analysis pipeline on the submitted text.
     *
     * @param text  validated, non-empty input text
     * @param useMl whether to combine ML classification with the rule engine
     * @return complete {@link AnalysisResult}
     */
    public AnalysisResult analyse(String text, boolean useMl) {
        // 1. Collect signals from all registered detectors
        List<Signal> rawSignals = new ArrayList<>();
        if (text != null && !text.isBlank()) {
            for (Detector d : detectors) {
                rawSignals.addAll(d.detect(text));
            }
        }

        // 2. Filter overlapping signals to prevent double-counting
        List<Signal> signals = scoringEngine.filterOverlapping(rawSignals);

        // 3. Score and classify risk from rule engine
        int       ruleScore = scoringEngine.score(signals);
        RiskLevel ruleLevel = scoringEngine.level(ruleScore);

        // 4. Extract URLs (never fetched)
        List<String> urls = UrlExtractor.extract(text);

        // 5. ML & Hybrid Scoring
        int       finalScore = ruleScore;
        RiskLevel finalLevel = ruleLevel;
        AnalysisResult.MlResult ml = null;

        if (useMl) {
            double textProb = 0.0;
            List<String> topWords = List.of();
            if (textClassifier != null && text != null && !text.isBlank()) {
                TextClassifier.TextClassificationResult textResult = textClassifier.classify(text);
                textProb = textResult.probability();
                topWords = textResult.topWords();
            }

            double urlProb = 0.0;
            if (urlClassifier != null && !urls.isEmpty()) {
                for (String u : urls) {
                    double p = urlClassifier.classify(u);
                    if (p > urlProb) {
                        urlProb = p;
                    }
                }
            }

            // mlScore = max(textProbability, urlProbability) x 100
            double maxProb = Math.max(textProb, urlProb);
            int mlScore = (int) Math.round(maxProb * 100.0);

            // Load weights and safe message cap from rules.json via ScoringEngine
            RulesData.MlScoringConfig cfg = (scoringEngine.getRulesConfig() != null)
                    ? scoringEngine.getRulesConfig().getMlScoring()
                    : RulesData.MlScoringConfig.DEFAULT;

            // finalScore = round(0.6 x ruleScore + 0.4 x mlScore)
            finalScore = (int) Math.round(cfg.ruleWeight() * ruleScore + cfg.mlWeight() * mlScore);

            // ML must not push a clearly safe message (no rule signals) into High or Critical on its own
            if (signals.isEmpty()) {
                finalScore = Math.min(finalScore, cfg.noSignalCap());
            }

            // A Critical rule combination must never be lowered by ML.
            // If rules say Critical, the final level stays Critical.
            if (ruleLevel == RiskLevel.CRITICAL) {
                finalScore = Math.max(ruleScore, finalScore);
                finalLevel = RiskLevel.CRITICAL;
            } else {
                // Recompute the level from the final score using existing thresholds
                finalLevel = scoringEngine.level(finalScore);
            }

            ml = new AnalysisResult.MlResult(textProb, urlProb, topWords, ruleScore, mlScore);
        }

        // 6. Human-readable fields
        String summary  = scoringEngine.summary(finalScore, signals, finalLevel);
        String scamType = scoringEngine.scamType(signals);

        return new AnalysisResult(finalScore, finalLevel, summary, scamType, signals, urls, ml);
    }
}
