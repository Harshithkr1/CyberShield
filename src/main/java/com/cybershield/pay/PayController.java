package com.cybershield.pay;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Signed Demo Bank payment order endpoints under {@code /api/pay/*}.
 */
@RestController
@RequestMapping("/api/pay")
public class PayController {

    public record VerifyTokenRequest(String token) {}

    private final PayOrderService payOrderService;

    public PayController(PayOrderService payOrderService) {
        this.payOrderService = payOrderService;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @PostMapping("/order")
    public ResponseEntity<?> createOrder(@RequestBody(required = false) PayOrderService.CreateOrderRequest req) {
        try {
            return ResponseEntity.ok(payOrderService.createOrder(req));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/verify")
    public PayOrderService.VerifyResponse verifyOrder(@RequestBody(required = false) VerifyTokenRequest req) {
        return payOrderService.verifyToken(req == null ? null : req.token());
    }
}

