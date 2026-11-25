package com.cybershield.pay;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "cybershield.pay.cors-allowed-origin=https://example.github.io")
@AutoConfigureMockMvc
class PayControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("GET /api/pay/health returns {status:'ok'} with configured CORS header")
    void healthEndpointReturnsOk() throws Exception {
        mockMvc.perform(get("/api/pay/health").header("Origin", "https://example.github.io"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "https://example.github.io"))
                .andExpect(jsonPath("$.status").value("ok"));
    }

    @Test
    @DisplayName("POST /api/pay/order rejects amount <= 0 and missing VPA/ref with 400")
    void orderRejectsInvalidInputs() throws Exception {
        mockMvc.perform(post("/api/pay/order")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"receiverVpa\":\"demo-shop@csbank\",\"payeeName\":\"Shop\",\"amount\":0,\"ref\":\"R1\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").exists());

        mockMvc.perform(post("/api/pay/order")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"receiverVpa\":\"\",\"payeeName\":\"Shop\",\"amount\":10,\"ref\":\"R1\"}"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/api/pay/order")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"receiverVpa\":\"demo-shop@csbank\",\"payeeName\":\"Shop\",\"amount\":10,\"ref\":\"\"}"))
                .andExpect(status().isBadRequest());
    }
}
