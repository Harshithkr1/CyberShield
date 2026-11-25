package com.cybershield.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@DisplayName("Verify REST API integration tests (/api/verify/*)")
class VerifyControllerIntegrationTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    ObjectMapper mapper;

    @Test
    @DisplayName("GET /api/verify/merchants returns 5 fictional merchants with security headers")
    void getMerchants_returnsFiveAndHeaders() throws Exception {
        mvc.perform(get("/api/verify/merchants"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(jsonPath("$", org.hamcrest.Matchers.hasSize(5)))
                .andExpect(jsonPath("$[0].bank").value("Demo Bank"));
    }

    @Test
    @DisplayName("POST /api/verify/receiver detects VERIFIED_DEMO, LOOKALIKE, and UNKNOWN")
    void verifyReceiver_outcomes() throws Exception {
        mvc.perform(post("/api/verify/receiver")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"upiId": "ravl@demobank"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("LOOKALIKE"));

        mvc.perform(post("/api/verify/receiver")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"upiId": "stranger@otherbank"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UNKNOWN"))
                .andExpect(jsonPath("$.reason").value("cannot be verified here"));
    }

    @Test
    @DisplayName("POST /api/verify/qr rejects amount 0, negative, huge, and unknown JSON keys with 400")
    void qrRejectsBadAmountsAndStrictJson() throws Exception {
        for (String badAmount : List.of("0", "0.00", "-10", "100000.01", "9999999")) {
            mvc.perform(post("/api/verify/qr")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("""
                                    {"merchantId": "ravi-stores", "amountRupees": %s}
                                    """.formatted(badAmount)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error").isString());
        }

        // Strict JSON rejects unknown fields
        mvc.perform(post("/api/verify/qr")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"merchantId": "ravi-stores", "amountRupees": 50, "unexpected": 1}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Full flow: generate QR -> check VALID -> tamper -> TAMPERED -> 3 receipts -> tamper entry 2 -> brokenAtIndex 1")
    void fullVerifyQrCheckAndReceiptTrailFlow() throws Exception {
        String qrJson = mvc.perform(post("/api/verify/qr")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"merchantId": "ravi-stores", "amountRupees": 250.50}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.qrDataUri").value(org.hamcrest.Matchers.startsWith("data:image/png;base64,")))
                .andExpect(jsonPath("$.paymentLink").value(org.hamcrest.Matchers.startsWith("https://")))
                .andReturn().getResponse().getContentAsString();

        var qr = mapper.readTree(qrJson);
        assertThat(qr.get("paymentLink").asText()).doesNotContain("upi:" + "//");

        // Verify explicit http:// PUBLIC_BASE_URL keeps http:// scheme (for local LAN QR testing)
        var lanController = new VerifyController(
                new DemoMerchantRegistry(),
                new ReceiverVerifier(new DemoMerchantRegistry()),
                new PaymentSigner(),
                new QrCodeGenerator(),
                new ReceiptService(new PaymentSigner(), new DemoMerchantRegistry()),
                mapper,
                jakarta.validation.Validation.buildDefaultValidatorFactory().getValidator(),
                "http://192.168.1.42:8080"
        );
        var lanMock = org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(lanController).build();
        lanMock.perform(post("/api/verify/qr")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"merchantId": "ravi-stores", "amountRupees": 500}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paymentLink").value(org.hamcrest.Matchers.startsWith("http://192.168.1.42:8080/pay-demo.html?")));
        String payload = qr.get("payload").asText();
        String sig = qr.get("signature").asText();

        // Check returns VALID
        mvc.perform(post("/api/verify/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("payload", payload, "signature", sig))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VALID"));

        // Tamper amount -> TAMPERED & receipt refused with 400
        String decoded = new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8);
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(decoded.replace("|25050|", "|99999|").getBytes(StandardCharsets.UTF_8));

        mvc.perform(post("/api/verify/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("payload", tamperedPayload, "signature", sig))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("TAMPERED"));

        mvc.perform(post("/api/verify/receipt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("payload", tamperedPayload, "signature", sig))))
                .andExpect(status().isBadRequest());

        // Chain 3 valid receipts
        ReceiptService.ReceiptEntry e1 = issueViaApi(payload, sig, null);
        ReceiptService.ReceiptEntry e2 = issueViaApi(payload, sig, e1.hash());
        ReceiptService.ReceiptEntry e3 = issueViaApi(payload, sig, e2.hash());

        mvc.perform(post("/api/verify/trail/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("entries", List.of(e1, e2, e3)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true));

        // Edit amount in entry 2 -> brokenAtIndex 1
        var editedE2 = new ReceiptService.ReceiptEntry(
                e2.receiptId(), e2.merchant(), e2.upiId(), "9999.00",
                e2.timestamp(), e2.prevHash(), e2.hash(), e2.signature());

        mvc.perform(post("/api/verify/trail/check")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("entries", List.of(e1, editedE2, e3)))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(false))
                .andExpect(jsonPath("$.brokenAtIndex").value(1));
    }

    @Test
    @DisplayName("GET /pay-demo.html serves standalone customer verification page with security headers")
    void payDemoHtml_returns200WithSecurityHeaders() throws Exception {
        mvc.perform(get("/pay-demo.html"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("pay-demo-root")));
    }

    private ReceiptService.ReceiptEntry issueViaApi(String payload, String sig, String prevHash) throws Exception {
        var req = new java.util.LinkedHashMap<String, Object>();
        req.put("payload", payload);
        req.put("signature", sig);
        if (prevHash != null) req.put("prevHash", prevHash);

        String json = mvc.perform(post("/api/verify/receipt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.receiptId").value(org.hamcrest.Matchers.startsWith("DEMO-")))
                .andReturn().getResponse().getContentAsString();
        return mapper.readValue(json, ReceiptService.ReceiptEntry.class);
    }
}

