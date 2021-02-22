package bobcvesearch.core;

import bobthebuildtool.pojos.buildfile.Dependency;
import com.google.gson.reflect.TypeToken;

import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static bobthebuildtool.services.Constants.JSON_PARSER;
import static bobthebuildtool.services.Functions.isNullOrEmpty;

public enum GavToCPE {;

    public static String toCoordinate(final Dependency dependency, final String defaultValue) {
        if (dependency == null) return defaultValue;
        if (!isNullOrEmpty(dependency.repository)) return dependency.repository;
        if (!isNullOrEmpty(dependency.github)) return dependency.github;
        return defaultValue;
    }

    private static final Type MAP_TYPE = new TypeToken<Map<String, List<String>>>(){}.getType();

    public static Map<String, List<String>> loadCoordinateToCpe() throws IOException {
        return loadCoordinateToCpe("/gav-to-cpe.json");
    }
    public static Map<String, List<String>> loadCoordinateToCpe(final String resource) throws IOException {
        try (final var reader = new InputStreamReader(GavToCPE.class.getResourceAsStream(resource))) {
            return JSON_PARSER.fromJson(reader, MAP_TYPE);
        }
    }

    public static List<String> toCPEs(final Dependency dependency) {
        if (!isNullOrEmpty(dependency.github)) {
            return githubToCPEs(dependency.github);
        }
        if (!isNullOrEmpty(dependency.repository)) {
            return gavToCPEs(dependency.repository);
        }
        return Collections.emptyList();
    }
    private static List<String> gavToCPEs(final String gav) {
        final String[] parts = gav.split(":");
        final String groupId = parts[0];
        final String artifactId = parts[1];
        final String version = parts[2];

        return List.of(
            "cpe:2.3:a:" + groupId + ":" + artifactId + ":*",
            "cpe:2.3:a:" + groupId + ":" + artifactId + ":" + version + ":*",
            "cpe:2.3:a:*:" + groupId + ":*",
            "cpe:2.3:a:*:" + groupId + ":" + version + ":*",
            "cpe:2.3:a:*:" + artifactId + ":*",
            "cpe:2.3:a:*:" + artifactId + ":" + version + ":*"
        );
    }
    private static List<String> githubToCPEs(final String github) {
        final String[] parts = github.split(":");
        final String repo = parts[0];
        final String version = parts[1];

        return List.of(
                "cpe:2.3:a:" + repo + ":*",
                "cpe:2.3:a:" + repo + ":" + version + ":*",
                "cpe:2.3:a:*:" + repo + ":*",
                "cpe:2.3:a:*:" + repo + ":" + version + ":*"
        );
    }
}
