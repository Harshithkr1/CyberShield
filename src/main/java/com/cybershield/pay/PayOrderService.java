package com.cybershield.pay;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues and verifies HMAC-SHA256 signed Demo Bank merchant orders ({@code CS1.<payload>.<sig>}).
 */
@Service
public class PayOrderService {

    private static final Logger log = LoggerFactory.getLogger(PayOrderService.class);

    public static final String TOKEN_PREFIX = "CS1";
    public static final long ORDER_TTL_MILLIS = 300_000L; // 300 seconds
    private static final int QR_SIZE_PX = 300;
    private static final Base64.Encoder B64U_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64U_DEC = Base64.getUrlDecoder();

    public record CreateOrderRequest(
            String receiverVpa,
            String payeeName,
            BigDecimal amount,
            String note,
            String ref
    ) {}

    public record OrderPayload(
            String pa,
            String pn,
            String am,
            String tr,
            String tn,
            long ts
    ) {}

    public record OrderResponse(
            OrderPayload payload,
            String canonical,
            String signatureHex,
            long expiresAt,
            String qrPngBase64
    ) {}

    public record ChangedField(
            String field,
            String original,
            String received
    ) {}

    public record VerifyResponse(
            boolean valid,
            String reason,
            List<ChangedField> changedFields,
            OrderPayload payload
    ) {}

    private record StoredOrder(OrderPayload payload, long expiresAt) {}

    private final byte[] secretKey;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    // In-memory order store for field-level tamper comparison; cleared on Render free-tier cold starts.
    private final Map<String, StoredOrder> orderStore = new ConcurrentHashMap<>();

    @Autowired
    public PayOrderService(
            @Value("${cybershield.pay.signing-secret:}") String configuredSecret,
            ObjectMapper objectMapper
    ) {
        this(resolveSigningKey(configuredSecret), Clock.systemUTC(), objectMapper);
    }

    public PayOrderService(byte[] keyBytes, Clock clock, ObjectMapper objectMapper) {
        if (keyBytes == null || keyBytes.length < 16) {
            throw new IllegalArgumentException("Signing key must be at least 16 bytes");
        }
        this.secretKey = keyBytes.clone();
        this.clock = clock != null ? clock : Clock.systemUTC();
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    private static byte[] resolveSigningKey(String configuredSecret) {
        String envSecret = System.getenv("UPI_SIGNING_SECRET");
        String effective = (envSecret != null && !envSecret.isBlank()) ? envSecret : configuredSecret;
        if (effective != null && !effective.isBlank()) {
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest(effective.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        log.warn("DEV ONLY: ephemeral signing key (not persisted)");
        return random;
    }

    public OrderResponse createOrder(CreateOrderRequest req) {
        if (req == null) {
            throw new IllegalArgumentException("Request body must not be null");
        }
        String pa = cleanRequired(req.receiverVpa(), "receiverVpa must not be empty");
        String tr = cleanRequired(req.ref(), "ref must not be missing");
        if (req.amount() == null || req.amount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("amount must be greater than 0");
        }
        String pn = cleanOptional(req.payeeName());
        String tn = cleanOptional(req.note());
        rejectPipe(pa, "receiverVpa");
        rejectPipe(pn, "payeeName");
        rejectPipe(tr, "ref");
        rejectPipe(tn, "note");

        String am = req.amount().setScale(2, RoundingMode.HALF_UP).toPlainString();
        long ts = clock.millis();
        long expiresAt = ts + ORDER_TTL_MILLIS;

        OrderPayload payload = new OrderPayload(pa, pn, am, tr, tn, ts);
        String canonical = buildCanonical(payload);
        byte[] signatureBytes = hmacSha256(canonical);
        String signatureHex = HexFormat.of().formatHex(signatureBytes);

        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize order payload", e);
        }

        String token = TOKEN_PREFIX + "."
                + B64U_ENC.encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8)) + "."
                + B64U_ENC.encodeToString(signatureBytes);

        evictExpired(ts);
        orderStore.put(storeKey(tr, ts), new StoredOrder(payload, expiresAt));

        String qrPngBase64 = renderQrPngBase64(token);
        return new OrderResponse(payload, canonical, signatureHex, expiresAt, qrPngBase64);
    }

    public VerifyResponse verifyToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return unknownOrder(null);
        }
        String[] parts = rawToken.trim().split("\\.", -1);
        if (parts.length != 3 || !TOKEN_PREFIX.equals(parts[0])) {
            return unknownOrder(null);
        }

        OrderPayload payload;
        try {
            byte[] decodedJson = B64U_DEC.decode(parts[1]);
            payload = objectMapper.readValue(decodedJson, OrderPayload.class);
        } catch (Exception e) {
            return unknownOrder(null);
        }

        if (payload == null || payload.tr() == null || payload.ts() <= 0) {
            return unknownOrder(null);
        }

        byte[] providedSig;
        try {
            providedSig = B64U_DEC.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return unknownOrder(null);
        }

        byte[] expectedSig = hmacSha256(buildCanonical(payload));
        boolean sigMatches = providedSig.length == expectedSig.length
                && MessageDigest.isEqual(providedSig, expectedSig);

        StoredOrder stored = orderStore.get(storeKey(payload.tr(), payload.ts()));
        if (!sigMatches) {
            if (stored == null) {
                return unknownOrder(null);
            }
            List<ChangedField> diffs = diffPayloads(stored.payload(), payload);
            return new VerifyResponse(false, "signature mismatch", diffs, payload);
        }

        long now = clock.millis();
        long expiresAt = payload.ts() + ORDER_TTL_MILLIS;
        if (now > expiresAt) {
            return new VerifyResponse(false, "expired", List.of(), payload);
        }

        return new VerifyResponse(true, "valid", List.of(), payload);
    }

    private static VerifyResponse unknownOrder(OrderPayload payload) {
        return new VerifyResponse(false, "unsigned or unknown order", List.of(), payload);
    }

    private static List<ChangedField> diffPayloads(OrderPayload original, OrderPayload received) {
        List<ChangedField> changes = new ArrayList<>();
        compareField(changes, "pa", original.pa(), received.pa());
        compareField(changes, "pn", original.pn(), received.pn());
        compareField(changes, "am", original.am(), received.am());
        compareField(changes, "tr", original.tr(), received.tr());
        compareField(changes, "tn", original.tn(), received.tn());
        compareField(changes, "ts", String.valueOf(original.ts()), String.valueOf(received.ts()));
        return List.copyOf(changes);
    }

    private static void compareField(List<ChangedField> changes, String name, String orig, String recv) {
        String a = orig == null ? "" : orig;
        String b = recv == null ? "" : recv;
        if (!a.equals(b)) {
            changes.add(new ChangedField(name, a, b));
        }
    }

    private static String buildCanonical(OrderPayload p) {
        return String.join("|",
                nvl(p.pa()),
                nvl(p.pn()),
                nvl(p.am()),
                nvl(p.tr()),
                nvl(p.tn()),
                String.valueOf(p.ts())
        );
    }

    private byte[] hmacSha256(String canonical) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
            return mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256 failure", e);
        }
    }

    private String renderQrPngBase64(String content) {
        try {
            BitMatrix matrix = new QRCodeWriter().encode(
                    content,
                    BarcodeFormat.QR_CODE,
                    QR_SIZE_PX,
                    QR_SIZE_PX,
                    Map.of(EncodeHintType.MARGIN, 1)
            );
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", baos);
            return Base64.getEncoder().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate order QR PNG", e);
        }
    }

    private void evictExpired(long nowMillis) {
        orderStore.entrySet().removeIf(entry -> nowMillis > entry.getValue().expiresAt());
    }

    private static String storeKey(String ref, long ts) {
        return nvl(ref) + "|" + ts;
    }

    private static String cleanRequired(String val, String message) {
        if (val == null || val.trim().isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return val.trim();
    }

    private static String cleanOptional(String val) {
        return val == null ? "" : val.trim();
    }

    private static void rejectPipe(String val, String fieldName) {
        if (val.indexOf('|') >= 0) {
            throw new IllegalArgumentException(fieldName + " must not contain '|'");
        }
    }

    private static String nvl(String s) {
        return s == null ? "" : s;
    }
}

