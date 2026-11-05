package com.cybershield.model;

/**
 * A single detection signal produced by a Detector.
 * Immutable record – construct via builder or all-args constructor.
 */
public record Signal(
        String id,
        String category,
        int points,
        String explanation,
        String matchedText,
        int start,
        int end
) {
    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private String id;
        private String category;
        private int points;
        private String explanation;
        private String matchedText;
        private int start;
        private int end;

        public Builder id(String id)                  { this.id = id; return this; }
        public Builder category(String category)      { this.category = category; return this; }
        public Builder points(int points)             { this.points = points; return this; }
        public Builder explanation(String explanation){ this.explanation = explanation; return this; }
        public Builder matchedText(String matchedText){ this.matchedText = matchedText; return this; }
        public Builder start(int start)               { this.start = start; return this; }
        public Builder end(int end)                   { this.end = end; return this; }

        public Signal build() {
            return new Signal(id, category, points, explanation, matchedText, start, end);
        }
    }
}
