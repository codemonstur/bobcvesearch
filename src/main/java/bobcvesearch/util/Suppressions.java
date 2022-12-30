package bobcvesearch.util;

import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.services.Constants;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.readString;

public enum Suppressions {;

    public record SuppressionsFile(Set<SuppressRule> rules) {
        public boolean suppresses(final String cve, final String gav) {
            return rules.contains(new SuppressRule(cve, gav));
        }
    }
    public record SuppressRule(String cve, String gav) {}

    public static SuppressionsFile loadSuppresionsFile(final Project project, final Path path) throws IOException {
        final var suppresionsFile = project.parentDir.resolve(path);
        if (!isRegularFile(suppresionsFile)) return new SuppressionsFile(Set.of());

        return Constants.YAML_PARSER.loadAs(readString(suppresionsFile), SuppressionsFile.class);
    }

}
