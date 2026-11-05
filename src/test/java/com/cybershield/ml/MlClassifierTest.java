package com.cybershield.ml;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ML Classifiers Parity Test — Scikit-Learn (Python) vs Pure Java")
class MlClassifierTest {

    private static TextClassifier textClassifier;
    private static UrlClassifier urlClassifier;
    private static TestVectorsFile testVectors;

    @JsonIgnoreProperties(ignoreUnknown = true)
    record TestVectorsFile(
            String description,
            List<TextVector> texts,
            List<UrlVector> urls
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record TextVector(
            String text,
            double predicted_probability,
            int prediction,
            String label_name
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    record UrlVector(
            String url,
            double predicted_probability,
            int prediction,
            String label_name
    ) {}

    @BeforeAll
    static void setUp() throws Exception {
        textClassifier = new TextClassifier("/ml/text_model.json");
        urlClassifier = new UrlClassifier(new UrlFeatureExtractor(), "/ml/url_model.json");

        ObjectMapper mapper = new ObjectMapper();
        File f = new File("ml/test_vectors.json");
        if (!f.exists()) {
            f = new File("../ml/test_vectors.json");
        }
        testVectors = mapper.readValue(f, TestVectorsFile.class);
    }

    @Test
    @DisplayName("Assert Java TextClassifier matches Python predicted probability within 0.001 for all 10 texts")
    void testTextClassifierParity() {
        System.out.println("\n==========================================================================================================");
        System.out.println("                               TEXT CLASSIFIER PARITY COMPARISON TABLE                                    ");
        System.out.println("==========================================================================================================");
        System.out.printf("%-4s | %-7s | %-10s | %-10s | %-10s | %-6s | %s%n",
                "#", "Label", "Python", "Java", "Diff", "Status", "Snippet / Top Words");
        System.out.println("----------------------------------------------------------------------------------------------------------");

        assertThat(testVectors.texts()).hasSize(10);

        int index = 1;
        for (TextVector tv : testVectors.texts()) {
            TextClassifier.TextClassificationResult result = textClassifier.classify(tv.text());
            double javaProb = result.probability();
            double pyProb = tv.predicted_probability();
            double diff = Math.abs(javaProb - pyProb);

            boolean pass = diff <= 0.001;
            String status = pass ? "PASS" : "FAIL";
            String snippet = tv.text().length() > 40 ? tv.text().substring(0, 37) + "..." : tv.text();

            System.out.printf("%-4d | %-7s | %-10.4f | %-10.4f | %-10.6f | %-6s | \"%s\" (top: %s)%n",
                    index, tv.label_name(), pyProb, javaProb, diff, status, snippet, result.topWords());

            assertThat(diff)
                    .as("Text [%s] difference %.6f must be within 0.001 threshold", snippet, diff)
                    .isLessThanOrEqualTo(0.001);

            index++;
        }
        System.out.println("==========================================================================================================\n");
    }

    @Test
    @DisplayName("Assert Java UrlClassifier matches Python predicted probability within 0.001 for all 10 URLs")
    void testUrlClassifierParity() {
        System.out.println("\n==========================================================================================================");
        System.out.println("                                URL CLASSIFIER PARITY COMPARISON TABLE                                    ");
        System.out.println("==========================================================================================================");
        System.out.printf("%-4s | %-10s | %-10s | %-10s | %-10s | %-6s | %s%n",
                "#", "Label", "Python", "Java", "Diff", "Status", "URL");
        System.out.println("----------------------------------------------------------------------------------------------------------");

        assertThat(testVectors.urls()).hasSize(10);

        int index = 1;
        for (UrlVector uv : testVectors.urls()) {
            double javaProb = urlClassifier.classify(uv.url());
            double pyProb = uv.predicted_probability();
            double diff = Math.abs(javaProb - pyProb);

            boolean pass = diff <= 0.001;
            String status = pass ? "PASS" : "FAIL";

            System.out.printf("%-4d | %-10s | %-10.4f | %-10.4f | %-10.6f | %-6s | %s%n",
                    index, uv.label_name(), pyProb, javaProb, diff, status, uv.url());

            assertThat(diff)
                    .as("URL [%s] difference %.6f must be within 0.001 threshold", uv.url(), diff)
                    .isLessThanOrEqualTo(0.001);

            index++;
        }
        System.out.println("==========================================================================================================\n");
    }
}

