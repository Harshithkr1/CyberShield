package com.cybershield.detector;

import com.cybershield.config.RulesConfig;
import com.cybershield.model.Signal;
import com.cybershield.util.PhraseScanner;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects references to malicious or suspicious mobile applications:
 * <ul>
 *   <li>Direct .apk links or Android package download references</li>
 *   <li>Prompts to "install from unknown sources" or sideload apps</li>
 *   <li>Remote-access tools pushed for scams (AnyDesk, TeamViewer, QuickSupport, RustDesk)</li>
 *   <li>High-risk permission requests (Accessibility, SMS, screen-share)</li>
 *   <li>Rogue app lures (fake bank, KYC, RTO challan, PM Kisan, electricity apps)</li>
 * </ul>
 *
 * <p>All phrases and scoring weights come from {@link RulesConfig}.
 * Never opens any network connection.</p>
 */
@Component
public class MaliciousAppDetector implements Detector {

    private static final String CATEGORY = "MALICIOUS_APP";
    private static final String PHRASE_SIGNAL_ID = "maliciousApp.phrase";
    private static final String APK_SIGNAL_ID = "maliciousApp.apkLink";
    private static final Pattern APK_LINK_PATTERN =
            Pattern.compile("(?i)(?:https?://\\S+?|\\b[\\w.-]+?)\\.apk\\b");

    private final RulesConfig rulesConfig;

    public MaliciousAppDetector(RulesConfig rulesConfig) {
        this.rulesConfig = Objects.requireNonNull(rulesConfig, "rulesConfig cannot be null");
    }

    @Override
    public String name() {
        return "MaliciousAppDetector";
    }

    @Override
    public List<Signal> detect(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }

        int points = rulesConfig.getSignalWeights().getPhraseCategoryMaliciousApp();
        List<Signal> signals = new ArrayList<>();

        // 1. Match phrases from rulesConfig
        signals.addAll(PhraseScanner.scan(
                text,
                rulesConfig.getMaliciousAppPhrases(),
                PHRASE_SIGNAL_ID,
                CATEGORY,
                points,
                "Suspicious mobile app installation or remote-access tool reference detected."));

        // 2. Detect direct .apk URLs and filenames
        Matcher apkMatcher = APK_LINK_PATTERN.matcher(text);
        while (apkMatcher.find()) {
            int start = apkMatcher.start();
            int end = apkMatcher.end();
            String matched = text.substring(start, end);

            boolean alreadyCovered = signals.stream()
                    .anyMatch(s -> s.id().equals(APK_SIGNAL_ID) && s.start() == start && s.end() == end);

            if (!alreadyCovered) {
                signals.add(Signal.builder()
                        .id(APK_SIGNAL_ID)
                        .category(CATEGORY)
                        .points(points)
                        .explanation("Direct link or file reference to an Android application package (.apk) detected. Installing APK files outside official app stores poses severe security risks.")
                        .matchedText(matched)
                        .start(start)
                        .end(end)
                        .build());
            }
        }

        return List.copyOf(signals);
    }
}
