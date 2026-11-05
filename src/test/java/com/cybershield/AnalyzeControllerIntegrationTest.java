package com.cybershield;

import com.cybershield.controller.AnalyzeController;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for POST /api/analyze.
 * Uses the full Spring context and MockMvc for HTTP-layer coverage.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AnalyzeControllerIntegrationTest {

        @Autowired
        MockMvc mvc;
        @Autowired
        ObjectMapper mapper;

        // ── Happy path ────────────────────────────────────────────────────────────

        @Test
        @DisplayName("Valid text returns 200 with required fields")
        void validRequest_returns200() throws Exception {
                var body = new AnalyzeController.AnalyzeRequest("Check this link: http://example.com", false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").isNumber())
                                .andExpect(jsonPath("$.level").isString())
                                .andExpect(jsonPath("$.summary").isString())
                                .andExpect(jsonPath("$.scamType").isString())
                                .andExpect(jsonPath("$.signals").isArray())
                                .andExpect(jsonPath("$.urls").isArray());
        }

        @Test
        @DisplayName("useMl=true returns ml field as object")
        void useMlTrue_returnsMlField() throws Exception {
                var body = new AnalyzeController.AnalyzeRequest("Some suspicious message", true);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.ml").isMap());
        }

        @Test
        @DisplayName("useMl=false returns ml field as null")
        void useMlFalse_returnsMlNull() throws Exception {
                var body = new AnalyzeController.AnalyzeRequest("Hello world", false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.ml").doesNotExist());
        }

        // ── Validation errors ─────────────────────────────────────────────────────

        @Test
        @DisplayName("Blank text returns 400 with error message")
        void blankText_returns400() throws Exception {
                String body = """
                                {"text": "  ", "useMl": false}
                                """;

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").isString());
        }

        @Test
        @DisplayName("Missing text returns 400")
        void missingText_returns400() throws Exception {
                String body = """
                                {"useMl": false}
                                """;

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest());
        }

        @Test
        @DisplayName("Text exceeding 5000 chars returns 400")
        void tooLongText_returns400() throws Exception {
                String longText = "a".repeat(5001);
                String body = mapper.writeValueAsString(
                                new AnalyzeController.AnalyzeRequest(longText, false));

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isBadRequest())
                                .andExpect(jsonPath("$.error").isString());
        }

        @Test
        @DisplayName("Text of exactly 5000 chars is accepted")
        void exactlyMaxLength_returns200() throws Exception {
                String maxText = "a".repeat(5000);
                String body = mapper.writeValueAsString(
                                new AnalyzeController.AnalyzeRequest(maxText, false));

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(body))
                                .andExpect(status().isOk());
        }

        // ── Five Sample Scenarios (UI Samples) ─────────────────────────────────────────

        @Test
        @DisplayName("Sample 1: Fake Bank KYC SMS scores Medium or higher through MockMvc")
        void sample1_bankKycSms_scoresMediumOrHigher() throws Exception {
                String text = "Dear SBI customer, your bank account KYC has expired. Your debit card and net banking will be blocked within 24 hours. Complete your kyc immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.";
                var body = new AnalyzeController.AnalyzeRequest(text, false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").isNumber())
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.greaterThanOrEqualTo(25)))
                                .andExpect(jsonPath("$.level").value(org.hamcrest.Matchers.isOneOf("MEDIUM", "HIGH", "CRITICAL")))
                                .andExpect(jsonPath("$.scamType").value("PHISHING"))
                                .andExpect(jsonPath("$.signals").isArray())
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(org.hamcrest.Matchers.greaterThan(0))))
                                .andExpect(jsonPath("$.urls").isArray())
                                .andExpect(jsonPath("$.urls[0]").value("http://sbi-kyc-verify-portal.xyz"));
        }

        @Test
        @DisplayName("Sample 2: Digital Arrest Call Script must score Critical through MockMvc")
        void sample2_digitalArrest_mustScoreCritical() throws Exception {
                String text = "This is Officer R. K. Verma from Central Bureau of Investigation cyber cell. An arrest warrant is issued against your name for money laundering and a drug parcel seized at Mumbai airport. You are under digital arrest. Stay on video call, do not tell anyone, and transfer funds to safe account for RBI verification.";
                var body = new AnalyzeController.AnalyzeRequest(text, false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").isNumber())
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.greaterThanOrEqualTo(75)))
                                .andExpect(jsonPath("$.level").value("CRITICAL"))
                                .andExpect(jsonPath("$.scamType").value("DIGITAL_ARREST"))
                                .andExpect(jsonPath("$.summary").value(org.hamcrest.Matchers.containsString("Critical threat detected")))
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(org.hamcrest.Matchers.greaterThan(0))));
        }

        @Test
        @DisplayName("Sample 3: Fake Courier Link scores Medium or higher through MockMvc")
        void sample3_fakeCourierLink_scoresMediumOrHigher() throws Exception {
                String text = "Your FedEx courier parcel #FDX-99821 is on hold at customs clearance. Pay customs duty fee of Rs 49 to release package and reschedule your delivery: http://fedx-customs-clearance.top/track";
                var body = new AnalyzeController.AnalyzeRequest(text, false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").isNumber())
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.greaterThanOrEqualTo(25)))
                                .andExpect(jsonPath("$.level").value(org.hamcrest.Matchers.isOneOf("MEDIUM", "HIGH", "CRITICAL")))
                                .andExpect(jsonPath("$.scamType").value("PHISHING"))
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(org.hamcrest.Matchers.greaterThan(0))))
                                .andExpect(jsonPath("$.urls[0]").value("http://fedx-customs-clearance.top/track"));
        }

        @Test
        @DisplayName("Sample 4: Malicious APK Install Message scores High or higher through MockMvc")
        void sample4_maliciousApk_scoresHighOrHigher() throws Exception {
                String text = "Urgent notice from Power Grid: Electricity connection will be disconnected tonight due to unpaid dues. Install our electricity bill app to clear bill: http://quick-power-bill.org/payment.apk. Enable unknown sources and grant accessibility permission.";
                var body = new AnalyzeController.AnalyzeRequest(text, false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").isNumber())
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.greaterThanOrEqualTo(50)))
                                .andExpect(jsonPath("$.level").value(org.hamcrest.Matchers.isOneOf("HIGH", "CRITICAL")))
                                .andExpect(jsonPath("$.scamType").value("MALICIOUS_APP"))
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(org.hamcrest.Matchers.greaterThan(0))))
                                .andExpect(jsonPath("$.urls[0]").value("http://quick-power-bill.org/payment.apk"));
        }

        @Test
        @DisplayName("Sample 5: Safe Message must score Low through MockMvc")
        void sample5_safeMessage_mustScoreLow() throws Exception {
                String text = "Hi Ananya, please find the meeting agenda and presentation slides for tomorrow's project review at 3 PM in the conference room. Let me know if you'd like to add any discussion points. Thanks!";
                var body = new AnalyzeController.AnalyzeRequest(text, false);

                mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.score").value(0))
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.lessThan(25)))
                                .andExpect(jsonPath("$.level").value("LOW"))
                                .andExpect(jsonPath("$.scamType").value("SAFE"))
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(0)))
                                .andExpect(jsonPath("$.urls", org.hamcrest.Matchers.hasSize(0)));
        }

        // ── ML Layer Integration Tests ──────────────────────────────────────────

        @Test
        @DisplayName("ML on: Digital arrest sample stays Critical with ML on")
        void digitalArrest_withMlOn_staysCritical() throws Exception {
                String text = "This is Officer R. K. Verma from Central Bureau of Investigation cyber cell. An arrest warrant is issued against your name for money laundering and a drug parcel seized at Mumbai airport. You are under digital arrest. Stay on video call, do not tell anyone, and transfer funds to safe account for RBI verification.";
                var body = new AnalyzeController.AnalyzeRequest(text, true);

                var mvcResult = mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.level").value("CRITICAL"))
                                .andExpect(jsonPath("$.score").value(org.hamcrest.Matchers.greaterThanOrEqualTo(75)))
                                .andExpect(jsonPath("$.ml").isMap())
                                .andExpect(jsonPath("$.ml.topWords").isArray())
                                .andReturn();

                var result = mapper.readValue(mvcResult.getResponse().getContentAsString(), com.cybershield.model.AnalysisResult.class);
                org.assertj.core.api.Assertions.assertThat(result.level()).isEqualTo(com.cybershield.model.RiskLevel.CRITICAL);
                org.assertj.core.api.Assertions.assertThat(result.ml().textProbability()).isGreaterThan(0.8);
                org.assertj.core.api.Assertions.assertThat(result.ml().ruleScore()).isGreaterThanOrEqualTo(75);
        }

        @Test
        @DisplayName("ML on: Safe message must stay Low and not be pushed into High/Critical")
        void safeMessage_withMlOn_staysLow() throws Exception {
                String text = "Hi Ananya, please find the meeting agenda and presentation slides for tomorrow's project review at 3 PM in the conference room. Let me know if you'd like to add any discussion points. Thanks!";
                var body = new AnalyzeController.AnalyzeRequest(text, true);

                var mvcResult = mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(body)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.level").value("LOW"))
                                .andExpect(jsonPath("$.signals", org.hamcrest.Matchers.hasSize(0)))
                                .andExpect(jsonPath("$.ml").isMap())
                                .andReturn();

                var result = mapper.readValue(mvcResult.getResponse().getContentAsString(), com.cybershield.model.AnalysisResult.class);
                org.assertj.core.api.Assertions.assertThat(result.level()).isEqualTo(com.cybershield.model.RiskLevel.LOW);
                org.assertj.core.api.Assertions.assertThat(result.score()).isLessThan(25);
                org.assertj.core.api.Assertions.assertThat(result.score()).isLessThanOrEqualTo(49);
                org.assertj.core.api.Assertions.assertThat(result.ml().ruleScore()).isEqualTo(0);
                org.assertj.core.api.Assertions.assertThat(result.ml().textProbability()).isLessThan(0.2);
        }

        @Test
        @DisplayName("ML off: useMl=false gives exactly the old scores and ml is null")
        void useMlFalse_givesExactlyOldScoresAndNullMl() throws Exception {
                String text = "Dear SBI customer, your bank account KYC has expired. Your debit card and net banking will be blocked within 24 hours. Complete your kyc immediately at http://sbi-kyc-verify-portal.xyz to avoid disruption.";
                var bodyFalse = new AnalyzeController.AnalyzeRequest(text, false);

                var mvcResult = mvc.perform(post("/api/analyze")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(mapper.writeValueAsString(bodyFalse)))
                                .andExpect(status().isOk())
                                .andExpect(jsonPath("$.ml").doesNotExist())
                                .andExpect(jsonPath("$.level").value("MEDIUM"))
                                .andReturn();

                var result = mapper.readValue(mvcResult.getResponse().getContentAsString(), com.cybershield.model.AnalysisResult.class);
                org.assertj.core.api.Assertions.assertThat(result.ml()).isNull();
                org.assertj.core.api.Assertions.assertThat(result.score()).isEqualTo(37);
        }
}
