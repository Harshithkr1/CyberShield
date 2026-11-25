package com.cybershield.verify;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Signs and verifies DemoPay payment tokens with HMAC-SHA256.
 *
 * <p>Reads key material from {@code SIGNING_SECRET} environment variable, or
 * generates 32 random bytes at startup if absent. Never hard-codes or logs keys.</p>
 */
@Component
public class PaymentSigner {

    public static final String VERSION = "v1";
    public static final String CURRENCY = "INR";
    public static final long EXPIRY_SECONDS = 600L; // 10 minutes
    public static final long MIN_PAISE = 1L;          // Rs.0.01
    public static final long MAX_PAISE = 10_000_000L; // Rs.100,000.00

    public enum Status {
        VALID,
        TAMPERED,
        EXPIRED,
        MALFORMED
    }

    public record SignedPayment(
            String canonical,
            String payload,
            String signature,
            long expiresAtEpochSec
    ) {}

    public record CheckResult(
            Status status,
            String merchantId,
            String upiId,
            Long amountPaise,
            String amountRupees,
            String currency,
            String orderId,
            Long expiresAtEpochSec,
            List<String> reasons
    ) {}

    private final byte[] secretKey;
    private final Clock clock;

    @Autowired
    public PaymentSigner() {
        this(resolveStartupKey(), Clock.systemUTC());
    }

    public PaymentSigner(byte[] keyBytes, Clock clock) {
        if (keyBytes == null || keyBytes.length < 16) {
            throw new IllegalArgumentException("Signing key must be at least 16 bytes");
        }
        this.secretKey = keyBytes.clone();
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    private static byte[] resolveStartupKey() {
        String envSecret = System.getenv("SIGNING_SECRET");
        if (envSecret != null && !envSecret.isBlank()) {
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest(envSecret.getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
        }
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        return random;
    }

    public SignedPayment sign(String merchantId, String upiId, long amountPaise, String orderId) {
        validateField(merchantId, "merchantId");
        validateField(upiId, "upiId");
        validateField(orderId, "orderId");
        if (amountPaise < MIN_PAISE || amountPaise > MAX_PAISE) {
            throw new IllegalArgumentException("amountPaise must be between " + MIN_PAISE + " and " + MAX_PAISE);
        }

        long expiresAt = clock.instant().getEpochSecond() + EXPIRY_SECONDS;
        return signWithExpiry(merchantId.trim(), upiId.trim(), amountPaise, orderId.trim(), expiresAt);
    }

    public SignedPayment signWithExpiry(String merchantId, String upiId, long amountPaise, String orderId, long expiresAtEpochSec) {
        String canonical = String.join("|",
                VERSION,
                merchantId,
                upiId,
                String.valueOf(amountPaise),
                CURRENCY,
                orderId,
                String.valueOf(expiresAtEpochSec)
        );
        String payload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(canonical.getBytes(StandardCharsets.UTF_8));
        String signature = hmacBase64Url(canonical);
        return new SignedPayment(canonical, payload, signature, expiresAtEpochSec);
    }

    public CheckResult check(String payloadB64, String signatureB64) {
        if (payloadB64 == null || payloadB64.isBlank() || signatureB64 == null || signatureB64.isBlank()) {
            return malformed("Missing payload or signature.");
        }

        String canonical;
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(payloadB64.trim());
            canonical = new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return malformed("Payload is not valid Base64url.");
        }

        byte[] providedSig;
        try {
            providedSig = Base64.getUrlDecoder().decode(signatureB64.trim());
        } catch (IllegalArgumentException e) {
            return malformed("Signature is not valid Base64url.");
        }

        if (providedSig.length != 32) {
            return malformed("Signature length is invalid.");
        }

        String[] parts = canonical.split("\\|", -1);
        if (parts.length != 7) {
            return malformed("Canonical payload does not contain 7 pipe-separated fields.");
        }

        String ver = parts[0];
        String merchantId = parts[1];
        String upiId = parts[2];
        String amountStr = parts[3];
        String currency = parts[4];
        String orderId = parts[5];
        String expStr = parts[6];

        List<String> structuralErrors = new ArrayList<>();
        if (!VERSION.equals(ver)) structuralErrors.add("Unsupported token version.");
        if (!CURRENCY.equals(currency)) structuralErrors.add("Invalid currency (must be INR).");
        if (merchantId.isBlank() || upiId.isBlank() || orderId.isBlank()) {
            structuralErrors.add("Merchant, UPI ID, or orderId is blank.");
        }

        long amountPaise;
        try {
            amountPaise = Long.parseLong(amountStr);
            if (amountPaise < MIN_PAISE || amountPaise > MAX_PAISE) {
                structuralErrors.add("Amount out of allowed range.");
            }
        } catch (NumberFormatException e) {
            structuralErrors.add("Invalid amountPaise value.");
            amountPaise = 0L;
        }

        long expiresAt;
        try {
            expiresAt = Long.parseLong(expStr);
        } catch (NumberFormatException e) {
            structuralErrors.add("Invalid expiry timestamp.");
            expiresAt = 0L;
        }

        if (!structuralErrors.isEmpty()) {
            return new CheckResult(Status.MALFORMED, null, null, null, null, null, null, null,
                    List.copyOf(structuralErrors));
        }

        byte[] expectedSig = hmacBytes(canonical.getBytes(StandardCharsets.UTF_8));
        String formattedRupees = String.format(java.util.Locale.ROOT, "%.2f", amountPaise / 100.0);

        if (!MessageDigest.isEqual(expectedSig, providedSig)) {
            return new CheckResult(Status.TAMPERED, merchantId, upiId, amountPaise, formattedRupees,
                    currency, orderId, expiresAt,
                    List.of("HMAC-SHA256 signature mismatch: payload or signature was altered."));
        }

        long now = clock.instant().getEpochSecond();
        if (now > expiresAt) {
            return new CheckResult(Status.EXPIRED, merchantId, upiId, amountPaise, formattedRupees,
                    currency, orderId, expiresAt,
                    List.of("Payment link expired after the 10-minute validity window."));
        }

        return new CheckResult(Status.VALID, merchantId, upiId, amountPaise, formattedRupees,
                currency, orderId, expiresAt,
                List.of("Signature verified and token is within its 10-minute validity window."));
    }

    public String hmacBase64Url(String data) {
        byte[] sig = hmacBytes(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
    }

    public boolean verifyHmacBase64Url(String data, String signatureB64) {
        if (data == null || signatureB64 == null || signatureB64.isBlank()) return false;
        try {
            byte[] provided = Base64.getUrlDecoder().decode(signatureB64.trim());
            if (provided.length != 32) return false;
            byte[] expected = hmacBytes(data.getBytes(StandardCharsets.UTF_8));
            return MessageDigest.isEqual(expected, provided);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public String sha256Hex(String input) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private byte[] hmacBytes(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secretKey, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HMAC-SHA256 failure", e);
        }
    }

    private static void validateField(String value, String name) {
        if (value == null || value.isBlank() || value.indexOf('|') >= 0
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            throw new IllegalArgumentException(name + " contains invalid characters or is blank");
        }
    }

    private static CheckResult malformed(String reason) {
        return new CheckResult(Status.MALFORMED, null, null, null, null, null, null, null, List.of(reason));
    }
}

