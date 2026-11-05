package com.cybershield.ml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.InputStream;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java TF-IDF + Logistic Regression text classifier replicating scikit-learn.
 *
 * <p>Pipeline reproduced:
 * <ol>
 *   <li>Lowercase input string (Unicode-safe)</li>
 *   <li>Tokenize using Unicode-aware word regex {@code \b\w+\b}</li>
 *   <li>Construct word unigrams and bigrams (joined by a single space)</li>
 *   <li>Filter terms to exported 5,000-feature vocabulary</li>
 *   <li>Compute TF * IDF with exported IDF array</li>
 *   <li>Apply L2 normalization</li>
 *   <li>Compute probability via sigmoid(w · x + b)</li>
 *   <li>Extract top 5 contributing terms (coefficient * tfidf, highest first)</li>
 * </ol>
 */
@Component
public class TextClassifier {

    private static final Pattern TOKEN_PATTERN = Pattern.compile("\\b\\w+\\b", Pattern.UNICODE_CHARACTER_CLASS);

    private final Map<String, Integer> vocabulary;
    private final double[] idf;
    private final double[] coefficients;
    private final double intercept;
    private final Map<Integer, String> indexToTerm;

    public record TextClassificationResult(double probability, List<String> topWords) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ModelData {
        public Map<String, Integer> vocabulary;
        public List<Double> idf;
        public List<Double> coefficients;
        public double intercept;
    }

    public TextClassifier() {
        this("/ml/text_model.json");
    }

    public TextClassifier(String resourcePath) {
        ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        ModelData data = null;

        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is != null) {
                data = mapper.readValue(is, ModelData.class);
            }
        } catch (Exception e) {
            // fallback to file path
        }

        if (data == null) {
            try {
                File file = new File("src/main/resources" + resourcePath);
                if (!file.exists()) {
                    file = new File("." + resourcePath);
                }
                data = mapper.readValue(file, ModelData.class);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load text classification model from " + resourcePath, e);
            }
        }

        this.vocabulary = Collections.unmodifiableMap(data.vocabulary);
        this.idf = data.idf.stream().mapToDouble(Double::doubleValue).toArray();
        this.coefficients = data.coefficients.stream().mapToDouble(Double::doubleValue).toArray();
        this.intercept = data.intercept;

        Map<Integer, String> rev = new HashMap<>(this.vocabulary.size());
        for (Map.Entry<String, Integer> entry : this.vocabulary.entrySet()) {
            rev.put(entry.getValue(), entry.getKey());
        }
        this.indexToTerm = Collections.unmodifiableMap(rev);
    }

    /**
     * Classifies text and returns scam probability and top contributing words.
     *
     * @param text input text message
     * @return {@link TextClassificationResult} containing probability in [0, 1] and top contributing terms
     */
    public TextClassificationResult classify(String text) {
        if (text == null || text.isBlank()) {
            double emptyProb = sigmoid(intercept);
            return new TextClassificationResult(emptyProb, List.of());
        }

        // 1. Lowercase
        String lower = text.toLowerCase(Locale.ROOT);

        // 2. Tokenize with Unicode-aware regex
        Matcher matcher = TOKEN_PATTERN.matcher(lower);
        List<String> tokens = new ArrayList<>();
        while (matcher.find()) {
            tokens.add(matcher.group());
        }

        if (tokens.isEmpty()) {
            double emptyProb = sigmoid(intercept);
            return new TextClassificationResult(emptyProb, List.of());
        }

        // 3. Build unigrams and bigrams
        List<String> ngrams = new ArrayList<>(tokens.size() * 2);
        ngrams.addAll(tokens);
        for (int i = 0; i < tokens.size() - 1; i++) {
            ngrams.add(tokens.get(i) + " " + tokens.get(i + 1));
        }

        // 4. Term counts filtered by vocabulary
        Map<Integer, Integer> termCounts = new HashMap<>();
        for (String term : ngrams) {
            Integer idx = vocabulary.get(term);
            if (idx != null) {
                termCounts.put(idx, termCounts.getOrDefault(idx, 0) + 1);
            }
        }

        if (termCounts.isEmpty()) {
            double emptyProb = sigmoid(intercept);
            return new TextClassificationResult(emptyProb, List.of());
        }

        // 5. Compute TF * IDF and sum of squares for L2 norm
        double sumSq = 0.0;
        Map<Integer, Double> tfidfMap = new HashMap<>();
        for (Map.Entry<Integer, Integer> entry : termCounts.entrySet()) {
            int idx = entry.getKey();
            int count = entry.getValue();
            double val = count * idf[idx];
            tfidfMap.put(idx, val);
            sumSq += val * val;
        }

        double l2Norm = Math.sqrt(sumSq);

        // 6. Dot product (normalized_tfidf · coefficients) + intercept
        double dot = 0.0;
        List<TermContribution> contributions = new ArrayList<>();

        for (Map.Entry<Integer, Double> entry : tfidfMap.entrySet()) {
            int idx = entry.getKey();
            double rawTfidf = entry.getValue();
            double xNorm = (l2Norm > 0.0) ? (rawTfidf / l2Norm) : 0.0;
            double coef = coefficients[idx];
            dot += xNorm * coef;

            // Track contribution to score increase: coefficient * normalized_tfidf
            double contribution = coef * xNorm;
            if (contribution > 0.0) {
                contributions.add(new TermContribution(indexToTerm.get(idx), contribution));
            }
        }

        double z = dot + intercept;
        double probability = sigmoid(z);

        // Sort contributions descending (highest first) and take top 5
        contributions.sort((a, b) -> Double.compare(b.contribution, a.contribution));
        List<String> topWords = new ArrayList<>();
        for (int i = 0; i < Math.min(5, contributions.size()); i++) {
            topWords.add(contributions.get(i).term);
        }

        return new TextClassificationResult(probability, Collections.unmodifiableList(topWords));
    }

    public double predictProbability(String text) {
        return classify(text).probability();
    }

    private static double sigmoid(double z) {
        return 1.0 / (1.0 + Math.exp(-z));
    }

    private record TermContribution(String term, double contribution) {}
}

