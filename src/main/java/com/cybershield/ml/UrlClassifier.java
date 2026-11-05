package com.cybershield.ml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

/**
 * Malicious URL classifier reproducing scikit-learn StandardScaler + LogisticRegression pipeline.
 *
 * <p>Loads model parameters from {@code src/main/resources/ml/url_model.json} once at startup.
 */
@Component
public class UrlClassifier {

    private final UrlFeatureExtractor featureExtractor;
    private final List<String> features;
    private final double[] means;
    private final double[] stds;
    private final double[] coefficients;
    private final double intercept;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ModelData {
        public List<String> features;
        public List<Double> means;
        public List<Double> stds;
        public List<Double> coefficients;
        public double intercept;
    }

    @Autowired
    public UrlClassifier(UrlFeatureExtractor featureExtractor) {
        this(featureExtractor, "/ml/url_model.json");
    }

    public UrlClassifier() {
        this(new UrlFeatureExtractor(), "/ml/url_model.json");
    }

    public UrlClassifier(UrlFeatureExtractor featureExtractor, String resourcePath) {
        this.featureExtractor = (featureExtractor != null) ? featureExtractor : new UrlFeatureExtractor();

        ObjectMapper mapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        ModelData data = null;

        try (InputStream is = getClass().getResourceAsStream(resourcePath)) {
            if (is != null) {
                data = mapper.readValue(is, ModelData.class);
            }
        } catch (Exception e) {
            // fallback
        }

        if (data == null) {
            try {
                File file = new File("src/main/resources" + resourcePath);
                if (!file.exists()) {
                    file = new File("." + resourcePath);
                }
                data = mapper.readValue(file, ModelData.class);
            } catch (Exception e) {
                throw new IllegalStateException("Failed to load URL classification model from " + resourcePath, e);
            }
        }

        this.features = Collections.unmodifiableList(data.features);
        this.means = data.means.stream().mapToDouble(Double::doubleValue).toArray();
        this.stds = data.stds.stream().mapToDouble(Double::doubleValue).toArray();
        this.coefficients = data.coefficients.stream().mapToDouble(Double::doubleValue).toArray();
        this.intercept = data.intercept;
    }

    /**
     * Classifies a URL and returns the predicted probability of it being malicious.
     *
     * @param url input URL
     * @return malicious probability in [0, 1]
     */
    public double classify(String url) {
        if (url == null || url.isBlank()) {
            return 0.0;
        }

        double[] raw = featureExtractor.extractFeatures(url);
        double[] scaled = featureExtractor.scaleFeatures(raw, means, stds);

        double z = intercept;
        for (int i = 0; i < scaled.length; i++) {
            z += scaled[i] * coefficients[i];
        }

        return sigmoid(z);
    }

    public double predictProbability(String url) {
        return classify(url);
    }

    public List<String> getFeatures() {
        return features;
    }

    private static double sigmoid(double z) {
        return 1.0 / (1.0 + Math.exp(-z));
    }
}

