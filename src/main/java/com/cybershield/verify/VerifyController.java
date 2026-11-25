package com.cybershield.verify;

import com.cybershield.verify.ReceiptService.ReceiptEntry;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Valid;
import jakarta.validation.Validator;
import jakarta.validation.constraints.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Stateless REST API for the Verify module ({@code /api/verify/*}).
 * Never stores, logs, or transmits user data; enforces strict JSON validation.
 */
@RestController
@RequestMapping("/api/verify")
public class VerifyController {

    private final DemoMerchantRegistry merchantRegistry;
    private final ReceiverVerifier receiverVerifier;
    private final PaymentSigner paymentSigner;
    private final QrCodeGenerator qrCodeGenerator;
    private final ReceiptService receiptService;
    private final ObjectMapper strictMapper;
    private final Validator validator;
    private final String publicBaseUrl;

    @Autowired
    public VerifyController(
            DemoMerchantRegistry merchantRegistry,
            ReceiverVerifier receiverVerifier,
            PaymentSigner paymentSigner,
            QrCodeGenerator qrCodeGenerator,
            ReceiptService receiptService,
            ObjectMapper objectMapper,
            Validator validator,
            @Value("${PUBLIC_BASE_URL:}") String publicBaseUrl) {
        this.merchantRegistry = merchantRegistry;
        this.receiverVerifier = receiverVerifier;
        this.paymentSigner = paymentSigner;
        this.qrCodeGenerator = qrCodeGenerator;
        this.receiptService = receiptService;
        this.strictMapper = objectMapper.copy()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        this.validator = validator;
        this.publicBaseUrl = publicBaseUrl;
    }

    // ── Request / Response DTOs (strict JSON parsing) ─────────────────────────

    public record ReceiverVerifyRequest(
            @NotBlank(message = "upiId must not be blank")
            @Size(min = 3, max = 120, message = "upiId must be between 3 and 120 characters")
            String upiId,
            @Size(max = 120, message = "name must be at most 120 characters")
            String name
    ) {}

    public record QrRequest(
            @NotBlank(message = "merchantId must not be blank")
            @Size(max = 64, message = "merchantId must be at most 64 characters")
            String merchantId,
            @NotNull(message = "amountRupees is required")
            @DecimalMin(value = "0.01", message = "amountRupees must be at least 0.01")
            @DecimalMax(value = "100000.00", message = "amountRupees must be at most 100000.00")
            @Digits(integer = 6, fraction = 2, message = "amountRupees must have at most 2 decimal places")
            BigDecimal amountRupees,
            @Size(max = 64, message = "orderId must be at most 64 characters")
            @Pattern(regexp = "^[A-Za-z0-9_-]*$", message = "orderId may only contain letters, digits, '-' or '_'")
            String orderId
    ) {}

    public record QrResponse(
            String paymentLink,
            String qrDataUri,
            String payload,
            String signature,
            DemoMerchant merchant,
            long amountPaise,
            String amountRupees,
            String orderId,
            long expiresAtEpochSec
    ) {}

    public record CheckTokenRequest(
            @NotBlank(message = "payload must not be blank")
            @Size(max = 2048, message = "payload exceeds maximum size")
            String payload,
            @NotBlank(message = "signature must not be blank")
            @Size(max = 512, message = "signature exceeds maximum size")
            String signature
    ) {}

    public record ReceiptRequest(
            @NotBlank(message = "payload must not be blank")
            @Size(max = 2048, message = "payload exceeds maximum size")
            String payload,
            @NotBlank(message = "signature must not be blank")
            @Size(max = 512, message = "signature exceeds maximum size")
            String signature,
            @Size(max = 128, message = "prevHash must be at most 128 characters")
            String prevHash
    ) {}

    public record TrailCheckRequest(
            @NotEmpty(message = "entries must not be empty")
            @Size(max = 100, message = "entries must contain at most 100 receipts")
            List<@Valid ReceiptEntry> entries
    ) {}

    // ── Endpoints ─────────────────────────────────────────────────────────────

    @GetMapping("/merchants")
    public ResponseEntity<List<DemoMerchant>> getMerchants() {
        return ResponseEntity.ok(merchantRegistry.findAll());
    }

    @PostMapping("/receiver")
    public ResponseEntity<ReceiverVerifier.VerificationResult> verifyReceiver(
            @RequestBody(required = false) String rawBody) {
        ReceiverVerifyRequest request = parseStrict(rawBody, ReceiverVerifyRequest.class);
        return ResponseEntity.ok(receiverVerifier.verify(request.upiId(), request.name()));
    }

    @PostMapping("/qr")
    public ResponseEntity<QrResponse> generateQr(
            @RequestBody(required = false) String rawBody,
            HttpServletRequest httpRequest) {
        QrRequest request = parseStrict(rawBody, QrRequest.class);
        DemoMerchant merchant = merchantRegistry.findById(request.merchantId())
                .orElseThrow(() -> new IllegalArgumentException("Unknown merchantId"));

        BigDecimal scaled = request.amountRupees().setScale(2, RoundingMode.UNNECESSARY);
        long amountPaise = scaled.movePointRight(2).longValueExact();
        String orderId = (request.orderId() == null || request.orderId().isBlank())
                ? "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT)
                : request.orderId().trim();

        PaymentSigner.SignedPayment signed = paymentSigner.sign(
                merchant.id(), merchant.upiId(), amountPaise, orderId);

        String baseUrl = resolvePublicBaseUrl(httpRequest);
        String paymentLink = baseUrl + "/pay-demo.html?p=" + signed.payload() + "&s=" + signed.signature();
        String qrDataUri = qrCodeGenerator.toPngDataUri(paymentLink);

        return ResponseEntity.ok(new QrResponse(
                paymentLink,
                qrDataUri,
                signed.payload(),
                signed.signature(),
                merchant,
                amountPaise,
                scaled.toPlainString(),
                orderId,
                signed.expiresAtEpochSec()
        ));
    }

    @PostMapping("/check")
    public ResponseEntity<PaymentSigner.CheckResult> checkToken(
            @RequestBody(required = false) String rawBody) {
        CheckTokenRequest request = parseStrict(rawBody, CheckTokenRequest.class);
        return ResponseEntity.ok(paymentSigner.check(request.payload(), request.signature()));
    }

    @PostMapping("/receipt")
    public ResponseEntity<ReceiptService.ReceiptEntry> issueReceipt(
            @RequestBody(required = false) String rawBody) {
        ReceiptRequest request = parseStrict(rawBody, ReceiptRequest.class);
        ReceiptService.ReceiptEntry entry = receiptService.issueReceipt(
                request.payload(), request.signature(), request.prevHash());
        return ResponseEntity.ok(entry);
    }

    @PostMapping("/trail/check")
    public ResponseEntity<ReceiptService.TrailCheckResult> checkTrail(
            @RequestBody(required = false) String rawBody) {
        TrailCheckRequest request = parseStrict(rawBody, TrailCheckRequest.class);
        return ResponseEntity.ok(receiptService.checkTrail(request.entries()));
    }

    private <T> T parseStrict(String rawBody, Class<T> clazz) {
        if (rawBody == null || rawBody.isBlank()) {
            throw new IllegalArgumentException("Request body must not be empty");
        }
        if (rawBody.length() > 65536) {
            throw new IllegalArgumentException("Request body exceeds maximum allowed size");
        }
        T dto;
        try {
            dto = strictMapper.readValue(rawBody, clazz);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("Malformed or unexpected JSON payload");
        }
        Set<ConstraintViolation<T>> violations = validator.validate(dto);
        if (!violations.isEmpty()) {
            ConstraintViolation<T> first = violations.iterator().next();
            throw new IllegalArgumentException(first.getPropertyPath() + ": " + first.getMessage());
        }
        return dto;
    }

    // ── Host resolution (HTTPS DemoPay links or explicit PUBLIC_BASE_URL) ───

    private String resolvePublicBaseUrl(HttpServletRequest req) {
        String configured = publicBaseUrl;
        if (configured == null || configured.isBlank()) {
            configured = System.getenv("PUBLIC_BASE_URL");
        }
        if (configured != null && !configured.isBlank()) {
            String trimmed = configured.trim().replaceAll("/+$", "");
            if (trimmed.matches("(?i)^https?://.+")) {
                return trimmed;
            }
            if (!trimmed.isBlank()) {
                return "https://" + trimmed;
            }
        }
        String forwardedHost = req.getHeader("X-Forwarded-Host");
        if (forwardedHost != null && !forwardedHost.isBlank()) {
            return "https://" + forwardedHost.split(",")[0].trim();
        }
        String hostHeader = req.getHeader("Host");
        if (hostHeader != null && !hostHeader.isBlank()) {
            return "https://" + hostHeader.trim();
        }
        int port = req.getServerPort();
        String host = (port == 80 || port == 443)
                ? req.getServerName()
                : req.getServerName() + ":" + port;
        return "https://" + host;
    }

    // ── Error handlers (strict 400s, zero stack-trace leakage) ────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .findFirst()
                .orElse("Invalid request");
        return ResponseEntity.badRequest().body(Map.of("error", message));
    }

    @ExceptionHandler(ReceiptService.InvalidPaymentTokenException.class)
    public ResponseEntity<Map<String, Object>> handleInvalidToken(ReceiptService.InvalidPaymentTokenException ex) {
        PaymentSigner.CheckResult cr = ex.getCheckResult();
        return ResponseEntity.badRequest().body(Map.of(
                "error", ex.getMessage(),
                "status", cr.status().name(),
                "reasons", cr.reasons()
        ));
    }

    @ExceptionHandler({HttpMessageNotReadableException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, String>> handleBadRequest(Exception ex) {
        String msg = ex instanceof IllegalArgumentException
                ? ex.getMessage()
                : "Malformed or unexpected JSON payload";
        return ResponseEntity.badRequest().body(Map.of("error", msg));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGeneric(Exception ex) {
        return ResponseEntity.internalServerError()
                .body(Map.of("error", "An unexpected error occurred while processing the request"));
    }
}
