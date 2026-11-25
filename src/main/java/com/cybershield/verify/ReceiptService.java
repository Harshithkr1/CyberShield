package com.cybershield.verify;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

/**
 * Issues and verifies stateless hash-chained Demo Bank receipts.
 * Each receipt's hash is SHA-256(prevHash + "|" + canonical receipt fields)
 * and signed via HMAC-SHA256 by {@link PaymentSigner}.
 */
@Component
public class ReceiptService {

    public static final String GENESIS_HASH = "GENESIS";

    @JsonIgnoreProperties(ignoreUnknown = false)
    public record ReceiptEntry(
            @NotBlank @Size(max = 64) String receiptId,
            @NotBlank @Size(max = 120) String merchant,
            @NotBlank @Size(max = 120) String upiId,
            @NotBlank @Size(max = 32) String amount,
            @NotBlank @Size(max = 64) String timestamp,
            @NotBlank @Size(max = 128) String prevHash,
            @NotBlank @Size(max = 128) String hash,
            @NotBlank @Size(max = 128) String signature
    ) {}

    public record TrailCheckResult(
            boolean valid,
            Integer brokenAtIndex,
            String reason
    ) {}

    public static class InvalidPaymentTokenException extends RuntimeException {
        private final PaymentSigner.CheckResult checkResult;

        public InvalidPaymentTokenException(PaymentSigner.CheckResult checkResult) {
            super(checkResult.reasons().isEmpty() ? checkResult.status().name() : checkResult.reasons().get(0));
            this.checkResult = checkResult;
        }

        public PaymentSigner.CheckResult getCheckResult() {
            return checkResult;
        }
    }

    private final PaymentSigner signer;
    private final DemoMerchantRegistry registry;
    private final Clock clock;

    @Autowired
    public ReceiptService(PaymentSigner signer, DemoMerchantRegistry registry) {
        this(signer, registry, Clock.systemUTC());
    }

    public ReceiptService(PaymentSigner signer, DemoMerchantRegistry registry, Clock clock) {
        this.signer = signer;
        this.registry = registry;
        this.clock = clock != null ? clock : Clock.systemUTC();
    }

    public ReceiptEntry issueReceipt(String payload, String signature, String prevHash) {
        PaymentSigner.CheckResult check = signer.check(payload, signature);
        if (check.status() != PaymentSigner.Status.VALID) {
            throw new InvalidPaymentTokenException(check);
        }

        String merchantName = registry.findById(check.merchantId())
                .map(DemoMerchant::name)
                .orElse(check.merchantId());

        String receiptId = "DEMO-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase(Locale.ROOT);
        String amount = check.amountRupees();
        String timestamp = Instant.now(clock).toString();
        String normalizedPrev = (prevHash == null || prevHash.isBlank()) ? GENESIS_HASH : prevHash.trim();

        String hashInput = normalizedPrev + "|" + canonicalFields(receiptId, merchantName, check.upiId(), amount, timestamp);
        String hash = signer.sha256Hex(hashInput);
        String receiptSig = signer.hmacBase64Url(hash);

        return new ReceiptEntry(receiptId, merchantName, check.upiId(), amount, timestamp, normalizedPrev, hash, receiptSig);
    }

    public TrailCheckResult checkTrail(List<ReceiptEntry> entries) {
        if (entries == null || entries.isEmpty()) {
            return new TrailCheckResult(false, 0, "Trail must contain at least one receipt entry.");
        }

        for (int i = 0; i < entries.size(); i++) {
            ReceiptEntry entry = entries.get(i);
            if (entry == null) {
                return new TrailCheckResult(false, i, "Receipt entry is null.");
            }

            if (i > 0) {
                String expectedPrev = entries.get(i - 1).hash();
                if (!expectedPrev.equals(entry.prevHash())) {
                    return new TrailCheckResult(
                            false,
                            i,
                            "Chain link broken: prevHash does not match entry " + (i - 1) + " hash."
                    );
                }
            }

            String hashInput = entry.prevHash() + "|" + canonicalFields(
                    entry.receiptId(), entry.merchant(), entry.upiId(), entry.amount(), entry.timestamp());
            String expectedHash = signer.sha256Hex(hashInput);

            if (!expectedHash.equalsIgnoreCase(entry.hash())) {
                return new TrailCheckResult(
                        false,
                        i,
                        "Hash mismatch at entry " + i + ": receipt fields were modified."
                );
            }

            if (!signer.verifyHmacBase64Url(entry.hash(), entry.signature())) {
                return new TrailCheckResult(
                        false,
                        i,
                        "HMAC signature invalid at entry " + i + "."
                );
            }
        }

        return new TrailCheckResult(true, null, "All " + entries.size() + " chained receipt(s) verified.");
    }

    private static String canonicalFields(String receiptId, String merchant, String upiId, String amount, String timestamp) {
        return String.join("|", receiptId, merchant, upiId, amount, timestamp);
    }
}

