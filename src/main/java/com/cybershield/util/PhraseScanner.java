package com.cybershield.util;

import com.cybershield.model.Signal;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Stateless utility that scans text for phrase matches (case-insensitive,
 * multi-word, SMS-spelling-tolerant) and returns {@link Signal} objects with
 * accurate {@code start} / {@code end} character offsets in the original text.
 *
 * <h2>SMS-style tolerance</h2>
 * Phrase tokens are matched with common SMS abbreviations and Indian spelling variants:
 * <ul>
 *   <li>{@code your / ur}</li>
 *   <li>{@code you / u}</li>
 *   <li>{@code are / r}</li>
 *   <li>{@code please / plz / pls}</li>
 *   <li>{@code thanks / thx}</li>
 *   <li>{@code okay / ok}</li>
 *   <li>{@code aadhaar / aadhar}</li>
 * </ul>
 *
 * <p>Words are bounded by {@code \b} and punctuation-tolerant separators to avoid
 * false positives (e.g. matching "trai" inside "train" or "ed" inside "credited").</p>
 *
 * <p>This class never opens any network connection.</p>
 */
public final class PhraseScanner {

    private PhraseScanner() {}

    private static final ConcurrentHashMap<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

    private static final Map<String, String> SMS_SYNONYMS = Map.ofEntries(
            Map.entry("your", "(?:your|ur)"),
            Map.entry("ur", "(?:your|ur)"),
            Map.entry("you", "(?:you|u)"),
            Map.entry("u", "(?:you|u)"),
            Map.entry("are", "(?:are|r)"),
            Map.entry("r", "(?:are|r)"),
            Map.entry("please", "(?:please|plz|pls)"),
            Map.entry("plz", "(?:please|plz|pls)"),
            Map.entry("pls", "(?:please|plz|pls)"),
            Map.entry("thanks", "(?:thanks|thx)"),
            Map.entry("thx", "(?:thanks|thx)"),
            Map.entry("okay", "(?:okay|ok)"),
            Map.entry("ok", "(?:okay|ok)"),
            Map.entry("aadhaar", "(?:aadhaar|aadhar)"),
            Map.entry("aadhar", "(?:aadhaar|aadhar)")
    );

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Scan {@code text} for every phrase in {@code phrases}.
     * Returns one {@link Signal} per matched phrase (first occurrence).
     *
     * @param text         the raw input text
     * @param phrases      list of phrases to search for (from {@code rules.json})
     * @param signalId     the {@code Signal.id} to assign each match
     * @param category     the {@code Signal.category} to assign
     * @param points       points per matched phrase
     * @param explanation  explanation template; the literal phrase is appended in quotes
     * @param limitSignals if {@code > 0}, stop after this many distinct phrases match
     * @return immutable list of signals, one per matched phrase (may be empty, never null)
     */
    public static List<Signal> scan(
            String text,
            List<String> phrases,
            String signalId,
            String category,
            int points,
            String explanation,
            int limitSignals) {

        if (text == null || text.isBlank() || phrases == null || phrases.isEmpty()) {
            return List.of();
        }

        List<Signal> signals = new ArrayList<>();

        for (String phrase : phrases) {
            if (phrase == null || phrase.isBlank()) continue;
            if (limitSignals > 0 && signals.size() >= limitSignals) break;

            Pattern pattern = compilePhrasePattern(phrase);
            Matcher matcher = pattern.matcher(text);
            if (matcher.find()) {
                int start = matcher.start();
                int end = matcher.end();
                String matched = text.substring(start, end);

                signals.add(Signal.builder()
                        .id(signalId)
                        .category(category)
                        .points(points)
                        .explanation(explanation + " Detected: \"" + phrase + "\".")
                        .matchedText(matched)
                        .start(start)
                        .end(end)
                        .build());
            }
        }

        return List.copyOf(signals);
    }

    /**
     * Convenience overload with no limit on matches.
     */
    public static List<Signal> scan(
            String text, List<String> phrases,
            String signalId, String category,
            int points, String explanation) {
        return scan(text, phrases, signalId, category, points, explanation, 0);
    }

    /**
     * Compiles a regex {@link Pattern} for the given phrase, handling word boundaries,
     * punctuation variation, and SMS abbreviations. Results are cached.
     */
    public static Pattern compilePhrasePattern(String phrase) {
        return PATTERN_CACHE.computeIfAbsent(phrase, PhraseScanner::buildPattern);
    }

    private static Pattern buildPattern(String phrase) {
        String trimmed = phrase.trim();
        if (trimmed.startsWith(".")) {
            // Extension or dotted prefix, e.g. ".apk"
            return Pattern.compile("(?<![a-zA-Z0-9])\\." + Pattern.quote(trimmed.substring(1)) + "\\b",
                    Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        }

        String[] tokens = trimmed.split("[^a-zA-Z0-9]+");
        List<String> regexTokens = new ArrayList<>();
        for (String token : tokens) {
            if (token.isBlank()) continue;
            String lower = token.toLowerCase(Locale.ROOT);
            String tokenRegex = SMS_SYNONYMS.getOrDefault(lower, Pattern.quote(token));
            regexTokens.add(tokenRegex);
        }

        if (regexTokens.isEmpty()) {
            return Pattern.compile(Pattern.quote(phrase), Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
        }

        String joined = String.join("[\\s\\p{Punct}]+", regexTokens);
        return Pattern.compile("\\b" + joined + "\\b", Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    }

    /**
     * Count fully-uppercase words (length &gt; 2) in {@code text}.
     * Used to detect aggressive/alarming all-caps messages.
     */
    public static int countExcessiveCapsWords(String text) {
        if (text == null || text.isBlank()) return 0;
        int count = 0;
        for (String word : text.split("\\s+")) {
            String clean = word.replaceAll("^[^A-Za-z]+|[^A-Za-z]+$", "");
            if (clean.length() > 2 && clean.equals(clean.toUpperCase(Locale.ROOT))
                    && clean.chars().anyMatch(Character::isLetter)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Count occurrences of {@code '!'} in {@code text}.
     */
    public static int countExclamationMarks(String text) {
        if (text == null) return 0;
        int c = 0;
        for (char ch : text.toCharArray()) if (ch == '!') c++;
        return c;
    }

    /**
     * Normalise a phrase or text for case-insensitive, SMS-tolerant matching.
     */
    public static String normalise(String s) {
        if (s == null) return "";
        String lower = s.toLowerCase(Locale.ROOT);
        String spaced = lower.replaceAll("[\\s\\-_/.,;:!?]+", " ").trim();
        s = spaced.replaceAll("(?<![a-z])ur(?![a-z])", "your");
        s = s.replaceAll("(?<![a-z])u(?![a-z])", "you");
        s = s.replaceAll("(?<![a-z])r(?![a-z])", "are");
        s = s.replaceAll("(?<![a-z])plz(?![a-z])", "please");
        s = s.replaceAll("(?<![a-z])pls(?![a-z])", "please");
        s = s.replaceAll("(?<![a-z])thx(?![a-z])", "thanks");
        s = s.replaceAll("(?<![a-z])ok(?![a-z])", "okay");
        return s;
    }
}
