package com.cybershield;

import com.cybershield.controller.AnalyzeController;
import com.cybershield.model.AnalysisResult;
import com.cybershield.model.RiskLevel;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Robustness Tests — Edge cases, non-English text, malformed URLs, and boundaries")
class RobustnessTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper mapper;

    private AnalysisResult performAnalyze(String text, boolean useMl) throws Exception {
        var req = new AnalyzeController.AnalyzeRequest(text, useMl);
        var res = mvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andReturn();
        return mapper.readValue(res.getResponse().getContentAsString(), AnalysisResult.class);
    }

    @Test
    @DisplayName("Robustness: Very long input (exactly 5000 characters) returns sensible result")
    void testVeryLongInput() throws Exception {
        String base = "Urgent action required! Please update your KYC immediately: http://sbi-kyc-verify-portal.xyz ";
        StringBuilder sb = new StringBuilder();
        while (sb.length() + base.length() <= 5000) {
            sb.append(base);
        }
        while (sb.length() < 5000) {
            sb.append('A');
        }
        String text = sb.toString();
        assertThat(text).hasSize(5000);

        // Test with ML off
        AnalysisResult resNoMl = performAnalyze(text, false);
        assertThat(resNoMl).isNotNull();
        assertThat(resNoMl.score()).isBetween(0, 100);
        assertThat(resNoMl.level()).isNotNull();

        // Test with ML on
        AnalysisResult resMl = performAnalyze(text, true);
        assertThat(resMl).isNotNull();
        assertThat(resMl.score()).isBetween(0, 100);
        assertThat(resMl.ml()).isNotNull();
    }

    @Test
    @DisplayName("Robustness: Input with only URLs returns sensible result")
    void testInputWithOnlyUrls() throws Exception {
        String text = "http://sbi-kyc-verify-portal.xyz/login.php https://google.co.in http://185.220.101.5/police";

        AnalysisResult resNoMl = performAnalyze(text, false);
        assertThat(resNoMl.urls()).hasSize(3);
        assertThat(resNoMl.score()).isGreaterThan(0);

        AnalysisResult resMl = performAnalyze(text, true);
        assertThat(resMl.urls()).hasSize(3);
        assertThat(resMl.ml()).isNotNull();
        assertThat(resMl.ml().urlProbability()).isGreaterThan(0.9);
    }

    @Test
    @DisplayName("Robustness: Hindi non-English text with emojis")
    void testHindiTextWithEmoji() throws Exception {
        String hindi = "नमस्ते, यह एक महत्वपूर्ण सूचना है: आपका बैंक खाता केवाईसी समाप्त हो गया है। अपना डेबिट कार्ड चालू रखने के लिए http://sbi-kyc-portal.xyz पर जाएं 🚨⚠️";

        AnalysisResult resNoMl = performAnalyze(hindi, false);
        assertThat(resNoMl.urls()).contains("http://sbi-kyc-portal.xyz");
        assertThat(resNoMl.level()).isNotNull();

        AnalysisResult resMl = performAnalyze(hindi, true);
        assertThat(resMl.ml()).isNotNull();
        assertThat(resMl.ml().urlProbability()).isGreaterThan(0.9);
    }

    @Test
    @DisplayName("Robustness: Kannada non-English text with emojis")
    void testKannadaTextWithEmoji() throws Exception {
        String kannada = "ನಮಸ್ಕಾರ, ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಖಾತೆಯ ಕೆವೈಸಿ ಅವಧಿ ಮುಗಿದಿದೆ. ತಕ್ಷಣ ನವೀಕರಿಸಿ: http://bank-kyc-update.xyz ⚠️🔐";

        AnalysisResult resNoMl = performAnalyze(kannada, false);
        assertThat(resNoMl.urls()).contains("http://bank-kyc-update.xyz");
        assertThat(resNoMl.level()).isNotNull();

        AnalysisResult resMl = performAnalyze(kannada, true);
        assertThat(resMl.ml()).isNotNull();
        assertThat(resMl.ml().urlProbability()).isGreaterThan(0.9);
    }

    @ParameterizedTest(name = "Robustness with malformed URL: {0}")
    @ValueSource(strings = {
            "Check this link: http:// and tell me if it works",
            "Broken: https://.. please look",
            "Malformed: http://:::::/path",
            "Extra slashes: http:///invalid/test",
            "Unusual protocol: ftp://files.bank-secure.top/apk",
            "Invalid IP digits: http://999.999.999.999/scam",
            "Special characters: http://user:pass@host:8080/query?a=1&b=2#ref",
            "Encoded path: http://sbi-verify.top/%20%3Cscript%3E/index.html"
    })
    void testMalformedUrlsDoNotCrash(String text) throws Exception {
        AnalysisResult resNoMl = performAnalyze(text, false);
        assertThat(resNoMl).isNotNull();
        assertThat(resNoMl.score()).isBetween(0, 100);

        AnalysisResult resMl = performAnalyze(text, true);
        assertThat(resMl).isNotNull();
        assertThat(resMl.score()).isBetween(0, 100);
    }

    @Test
    @DisplayName("Security headers verification")
    void testSecurityHeaders() throws Exception {
        mvc.perform(post("/api/analyze")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"text\": \"hello\", \"useMl\": false}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("default-src 'self'")))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"))
                .andExpect(header().string("X-Frame-Options", "DENY"));
    }
}

