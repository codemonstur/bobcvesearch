package bobcvesearch.util;

import bobthebuildtool.pojos.buildfile.Project;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

import static bobthebuildtool.services.Constants.YAML_PARSER;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.readString;
import static java.util.Collections.emptySet;

public enum Suppressions {;

    public record SuppressionsFile(Set<SuppressRule> rules) {}
    public record SuppressRule(String cve, String osvId, String gav) {}

    public static class SuppressionMatcher {
        private final Set<String> rules;

        public SuppressionMatcher(final Set<SuppressRule> set) {
            this.rules = new HashSet<>();
            for (final var rule : set) {
                if (isNullOrEmpty(rule.gav)) continue;
                if (!isNullOrEmpty(rule.cve)) rules.add(rule.gav + "-" + rule.cve);
                if (!isNullOrEmpty(rule.osvId)) rules.add(rule.gav + "-" + rule.osvId);
            }
        }

        public boolean isOsvIdSuppressed(final String id, final String gav) {
            return rules.contains(gav + "-" + id);
        }
        public boolean isCveSuppressed(final String cve, final String gav) {
            return rules.contains(gav + "-" + cve);
        }
    }

    public static SuppressionMatcher loadSuppresionMatcher(final Project project, final Path path) throws IOException {
        final var suppresionsFile = project.parentDir.resolve(path);
        if (!isRegularFile(suppresionsFile)) return new SuppressionMatcher(emptySet());

        return new SuppressionMatcher(YAML_PARSER.loadAs(readString(suppresionsFile), SuppressionsFile.class).rules());
    }

}
