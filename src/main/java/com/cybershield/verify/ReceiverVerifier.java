package com.cybershield.verify;

import com.cybershield.util.Levenshtein;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;

/**
 * Verifies a receiver UPI ID (and optional expected name) against the
 * fictional Demo Bank merchant registry using exact lookup and Levenshtein
 * lookalike detection within distance 2 on the same handle.
 */
@Component
public class ReceiverVerifier {

    public enum Status {
        VERIFIED_DEMO,
        NAME_MISMATCH,
        LOOKALIKE,
        UNKNOWN
    }

    public record VerificationResult(
            Status status,
            DemoMerchant merchant,
            DemoMerchant closestMatch,
            String reason
    ) {}

    private final DemoMerchantRegistry registry;

    public ReceiverVerifier(DemoMerchantRegistry registry) {
        this.registry = registry;
    }

    public VerificationResult verify(String rawUpiId, String optionalName) {
        if (rawUpiId == null || rawUpiId.isBlank()) {
            return new VerificationResult(Status.UNKNOWN, null, null, "cannot be verified here");
        }

        String normalizedUpi = rawUpiId.trim().toLowerCase(Locale.ROOT);
        Optional<DemoMerchant> exact = registry.findByUpiId(normalizedUpi);

        if (exact.isPresent()) {
            DemoMerchant merchant = exact.get();
            if (optionalName != null && !optionalName.isBlank()) {
                String expectedNorm = normalizeName(merchant.name());
                String inputNorm = normalizeName(optionalName);
                if (!expectedNorm.equals(inputNorm)) {
                    return new VerificationResult(
                            Status.NAME_MISMATCH,
                            merchant,
                            null,
                            "Registered name is '" + merchant.name() + "', which differs from the entered name."
                    );
                }
            }
            return new VerificationResult(
                    Status.VERIFIED_DEMO,
                    merchant,
                    null,
                    "Matched fictional Demo Bank merchant: " + merchant.name() + "."
            );
        }

        // Check lookalikes: within Levenshtein distance 2 of a registered ID sharing the same handle
        int atIdx = normalizedUpi.indexOf('@');
        if (atIdx > 0 && atIdx == normalizedUpi.lastIndexOf('@') && atIdx < normalizedUpi.length() - 1) {
            String inputLocal = normalizedUpi.substring(0, atIdx);
            String inputHandle = normalizedUpi.substring(atIdx + 1);

            DemoMerchant bestMatch = null;
            int bestDist = Integer.MAX_VALUE;

            for (DemoMerchant candidate : registry.findAll()) {
                String candUpi = candidate.upiId().toLowerCase(Locale.ROOT);
                int candAt = candUpi.indexOf('@');
                if (candAt <= 0) continue;

                String candLocal = candUpi.substring(0, candAt);
                String candHandle = candUpi.substring(candAt + 1);

                if (inputHandle.equals(candHandle)) {
                    int dist = Levenshtein.distanceIgnoreCase(inputLocal, candLocal);
                    if (dist > 0 && dist <= 2 && dist < bestDist) {
                        bestDist = dist;
                        bestMatch = candidate;
                    }
                }
            }

            if (bestMatch != null) {
                return new VerificationResult(
                        Status.LOOKALIKE,
                        null,
                        bestMatch,
                        "Lookalike ID detected (edit distance " + bestDist + " from registered ID " + bestMatch.upiId() + ")."
                );
            }
        }

        return new VerificationResult(Status.UNKNOWN, null, null, "cannot be verified here");
    }

    private static String normalizeName(String name) {
        return name.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }
}

