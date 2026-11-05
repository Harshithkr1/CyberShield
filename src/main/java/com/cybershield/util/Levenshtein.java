package com.cybershield.util;

/**
 * Classic Levenshtein (edit-distance) implementation.
 *
 * <p>Used by the URL detector to spot typosquatting – e.g. "paypa1.com" vs
 * "paypal.com".  Operates on lower-cased strings for case-insensitive
 * comparisons.</p>
 */
public final class Levenshtein {

    private Levenshtein() {}

    /**
     * Compute the minimum edit distance between two strings.
     *
     * @param a first string (not null)
     * @param b second string (not null)
     * @return edit distance (0 = identical)
     */
    public static int distance(String a, String b) {
        int m = a.length();
        int n = b.length();

        // Use a rolling two-row array to keep memory O(n).
        int[] prev = new int[n + 1];
        int[] curr = new int[n + 1];

        for (int j = 0; j <= n; j++) prev[j] = j;

        for (int i = 1; i <= m; i++) {
            curr[0] = i;
            for (int j = 1; j <= n; j++) {
                if (a.charAt(i - 1) == b.charAt(j - 1)) {
                    curr[j] = prev[j - 1];
                } else {
                    curr[j] = 1 + Math.min(prev[j - 1], Math.min(prev[j], curr[j - 1]));
                }
            }
            int[] tmp = prev; prev = curr; curr = tmp;
        }

        return prev[n];
    }

    /**
     * Convenience: case-insensitive distance.
     */
    public static int distanceIgnoreCase(String a, String b) {
        return distance(a.toLowerCase(), b.toLowerCase());
    }
}
