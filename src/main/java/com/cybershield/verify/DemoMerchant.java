package com.cybershield.verify;

/**
 * Fictional Demo Bank merchant registered for the Verify simulator.
 */
public record DemoMerchant(
        String id,
        String name,
        String upiId,
        String bank,
        String category
) {}

