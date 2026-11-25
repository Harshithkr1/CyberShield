package com.cybershield;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Validates src/main/resources/static/data/scenarios.json from the classpath.
 */
class ScenariosDataTest {

    private static final List<String> LANGS = List.of("en", "kn", "hi");
    private static final Set<String> ALLOWED_CHANNELS = Set.of("sms", "whatsapp", "call", "payment", "qr", "app");

    private static JsonNode scenariosRoot;

    @BeforeAll
    static void loadScenarios() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream is = ScenariosDataTest.class.getResourceAsStream("/static/data/scenarios.json")) {
            assertThat(is)
                    .as("scenarios.json must exist on classpath at /static/data/scenarios.json")
                    .isNotNull();
            scenariosRoot = mapper.readTree(is);
        }
        assertThat(scenariosRoot.isArray())
                .as("scenarios.json root must be a JSON array")
                .isTrue();
    }

    @Test
    @DisplayName("Contains exactly 9 scenarios with unique IDs and valid channels")
    void hasNineUniqueIdsAndValidChannels() {
        assertThat(scenariosRoot.size()).isEqualTo(9);

        Set<String> ids = new HashSet<>();
        for (JsonNode scenario : scenariosRoot) {
            String id = scenario.path("id").asText("");
            assertThat(id).as("scenario id must not be blank").isNotBlank();
            assertThat(ids.add(id)).as("duplicate scenario id: " + id).isTrue();

            assertThat(scenario.path("scamType").asText("")).isNotBlank();
            String channel = scenario.path("channel").asText("");
            assertThat(ALLOWED_CHANNELS)
                    .as("Invalid channel '%s' in scenario %s", channel, id)
                    .contains(channel);
        }

        assertThat(ids).containsExactlyInAnyOrder(
                "collect-request", "refund-call", "qr-receive",
                "kyc-sms", "wrong-transfer", "fake-care",
                "lottery-fee", "cloned-app", "digital-arrest");
    }

    @Test
    @DisplayName("Every en, kn, and hi field is present and non-empty across all scenarios")
    void allTranslationsPresentAndNonEmpty() {
        for (JsonNode scenario : scenariosRoot) {
            String id = scenario.path("id").asText();

            assertMultilingualNode(scenario.get("message"), id + ".message");
            assertMultilingualNode(scenario.get("rule"), id + ".rule");

            JsonNode redFlags = scenario.get("redFlags");
            assertThat(redFlags).as(id + ".redFlags missing").isNotNull();
            for (String lang : LANGS) {
                JsonNode flags = redFlags.get(lang);
                assertThat(flags).as(id + ".redFlags." + lang + " missing").isNotNull();
                assertThat(flags.isArray() && flags.size() > 0)
                        .as(id + ".redFlags." + lang + " must be a non-empty array")
                        .isTrue();
                for (JsonNode f : flags) {
                    assertThat(f.asText("")).as(id + ".redFlags." + lang + " item blank").isNotBlank();
                }
            }

            JsonNode options = scenario.get("options");
            assertThat(options != null && options.isArray()).isTrue();
            for (JsonNode opt : options) {
                String optId = opt.path("id").asText();
                assertThat(optId).as(id + " option id missing").isNotBlank();
                assertMultilingualNode(opt.get("label"), id + ".options." + optId + ".label");
                assertMultilingualNode(opt.get("feedback"), id + ".options." + optId + ".feedback");

                if (opt.has("consequence") && !opt.get("consequence").isNull()) {
                    JsonNode cons = opt.get("consequence");
                    assertThat(cons.has("amountBefore")).isTrue();
                    assertThat(cons.has("amountAfter")).isTrue();
                    assertThat(cons.get("amountAfter").asInt())
                            .as("consequence amountAfter must be less than amountBefore on " + id + "." + optId)
                            .isLessThan(cons.get("amountBefore").asInt());
                    assertMultilingualNode(cons.get("note"), id + ".options." + optId + ".consequence.note");
                }
            }
        }
    }

    @Test
    @DisplayName("Every scenario has 3-4 options with exactly one correct option and consequence only on wrong options")
    void optionsCountAndSingleCorrectOption() {
        for (JsonNode scenario : scenariosRoot) {
            String id = scenario.path("id").asText();
            JsonNode options = scenario.get("options");
            assertThat(options.size())
                    .as("Scenario %s must have 3 or 4 options", id)
                    .isBetween(3, 4);

            int correctCount = 0;
            Set<String> optIds = new HashSet<>();
            for (JsonNode opt : options) {
                String optId = opt.path("id").asText();
                assertThat(optIds.add(optId)).as("Duplicate option id in " + id).isTrue();
                assertThat(opt.has("correct") && opt.get("correct").isBoolean())
                        .as("Option %s.%s missing boolean correct flag", id, optId)
                        .isTrue();

                boolean isCorrect = opt.get("correct").asBoolean();
                if (isCorrect) {
                    correctCount++;
                    assertThat(opt.has("consequence"))
                            .as("Correct option %s.%s must not have a consequence", id, optId)
                            .isFalse();
                }
            }
            assertThat(correctCount)
                    .as("Scenario %s must have exactly 1 correct option", id)
                    .isEqualTo(1);
        }
    }

    @Test
    @DisplayName("Every redFlag is an exact substring of its message in the same language")
    void redFlagsAreExactSubstringsOfMessage() {
        for (JsonNode scenario : scenariosRoot) {
            String id = scenario.path("id").asText();
            for (String lang : LANGS) {
                String message = scenario.path("message").path(lang).asText("");
                JsonNode flags = scenario.path("redFlags").path(lang);
                for (JsonNode flagNode : flags) {
                    String flag = flagNode.asText("");
                    assertThat(message)
                            .as("Scenario '%s' [%s] redFlag '%s' is not an exact substring of message '%s'",
                                    id, lang, flag, message)
                            .contains(flag);
                }
            }
        }
    }

    @Test
    @DisplayName("Safety guard: no real UPI deep links and kyc-sms consequence matches spec")
    void safetyGuardsAndSpecifiedConsequence() {
        String rawJson = scenariosRoot.toString().toLowerCase();
        assertThat(rawJson).doesNotContain("upi:" + "//");

        for (JsonNode scenario : scenariosRoot) {
            if ("kyc-sms".equals(scenario.path("id").asText())) {
                for (JsonNode opt : scenario.get("options")) {
                    if ("open-link".equals(opt.path("id").asText())) {
                        JsonNode cons = opt.get("consequence");
                        assertThat(cons).isNotNull();
                        assertThat(cons.get("amountBefore").asInt()).isEqualTo(12480);
                        assertThat(cons.get("amountAfter").asInt()).isEqualTo(6480);
                    }
                }
            }
        }
    }

    @Test
    @DisplayName("i18n en, kn, hi files load cleanly with matching non-empty keys")
    void i18nFilesLoadWithCompleteKeys() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode enRoot = readJson(mapper, "/static/i18n/en.json");
        Set<String> enKeys = new HashSet<>();
        collectLeafKeys("", enRoot, enKeys);
        assertThat(enKeys).isNotEmpty();

        for (String lang : LANGS) {
            JsonNode root = readJson(mapper, "/static/i18n/" + lang + ".json");
            Set<String> keys = new HashSet<>();
            collectLeafKeys("", root, keys);
            assertThat(keys)
                    .as("i18n/" + lang + ".json must contain every key from en.json")
                    .containsAll(enKeys);
        }
    }

    private static JsonNode readJson(ObjectMapper mapper, String path) throws Exception {
        try (InputStream is = ScenariosDataTest.class.getResourceAsStream(path)) {
            assertThat(is).as(path + " must exist on classpath").isNotNull();
            return mapper.readTree(is);
        }
    }

    private static void collectLeafKeys(String prefix, JsonNode node, Set<String> out) {
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String nextPrefix = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
                collectLeafKeys(nextPrefix, entry.getValue(), out);
            }
        } else {
            assertThat(node.asText("")).as("i18n key must not be blank: " + prefix).isNotBlank();
            out.add(prefix);
        }
    }

    private static void assertMultilingualNode(JsonNode node, String path) {
        assertThat(node).as(path + " missing").isNotNull();
        for (String lang : LANGS) {
            assertThat(node.has(lang)).as(path + "." + lang + " missing").isTrue();
            assertThat(node.get(lang).asText("")).as(path + "." + lang + " must not be blank").isNotBlank();
        }
    }
}

