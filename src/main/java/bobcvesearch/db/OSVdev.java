package bobcvesearch.db;

import bobthebuildtool.pojos.buildfile.Dependency;
import com.google.gson.annotations.SerializedName;
import fr.cryptohash.SHA256;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import static bobcvesearch.util.ExtendedHttpCaller.newHttpCall;
import static bobthebuildtool.services.Constants.JSON_PARSER;
import static bobthebuildtool.services.Functions.encodeHex;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.*;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.util.Collections.binarySearch;
import static java.util.Collections.emptyList;
import static java.util.concurrent.TimeUnit.DAYS;

// OSV.dev is a nice project started by Google. They have a simple HTTP API that I can query with
// a maven GAV and it gives me a list of vulnerabilities back. Perfect. This works.
public enum OSVdev {;

    public record OsvdevRequestBody(String version, @SerializedName("package") PPackage pPackage) {}
    public record OsvdevResponseBody(List<Vulnerability> vulns) {}

    public record Vulnerability(String schema_version, String id, String summary, String details, List<String> aliases,
                                String modified, String published, Map<String, Object> database_specific,
                                List<Reference> references, List<Software> affected, List<Severity> severity) {}
    public record Reference(String type, String url) {}
    public record Software(@SerializedName("package") PPackage ppackage, Map<String, Object> database_specific, List<String> versions) {}
    public record PPackage(String name, String ecosystem, String purl) {}
    public record Severity(String type, String score) {}

    public static List<Vulnerability> listVulnerabilities(final Dependency dependency, final long cacheAge) throws IOException {
        if (isNullOrEmpty(dependency.repository)) return emptyList();

        final var gav = dependency.repository.split(":");
        final var list = callOsvdev(toOsdevRequest(gav[0], gav[1], gav[2]), cacheAge).vulns();
        return list != null ? list : emptyList();
    }

    private static OsvdevRequestBody toOsdevRequest(final String groupId, final String artifactId, final String version) {
        return new OsvdevRequestBody(version, new OSVdev.PPackage(groupId + ":" + artifactId, "Maven", null));
    }

    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.27","package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"}}'
    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.15.3","package":{"name":"org.jsoup:jsoup","ecosystem":"Maven"}}'
    private static OsvdevResponseBody callOsvdev(final OsvdevRequestBody request, final long cacheAge) throws IOException {
        final var json = JSON_PARSER.toJson(request);
        final var key = encodeHex(hashSHA256(json, UTF_8));
        final var file = CACHE_DIR.resolve("osvdev_" + key + ".json");

        final var cached = loadCachedResponse(file, cacheAge, null);
        if (cached != null) return cached;

        return writeResponseToCache(file, newHttpCall()
            .scheme("https").hostname("api.osv.dev")
            .post("/v1/query")
            .body(json)
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyAsString());
    }

    private static final Path CACHE_DIR = Paths.get(System.getProperty("user.home"), ".bob", "plugins", "bobcvesearch", "cache");
    private static OsvdevResponseBody writeResponseToCache(final Path cacheFile, final String response) throws IOException {
        ensureExistenceCacheDirectory();
        Files.writeString(cacheFile, response, CREATE, WRITE, TRUNCATE_EXISTING);
        return JSON_PARSER.fromJson(response, OsvdevResponseBody.class);
    }
    private static OsvdevResponseBody loadCachedResponse(final Path cacheFile, final long cacheAge, final OsvdevResponseBody defaultValue) throws IOException {
        ensureExistenceCacheDirectory();
        if (!isAcceptable(cacheFile, cacheAge)) return defaultValue;
        return JSON_PARSER.fromJson(Files.readString(cacheFile), OsvdevResponseBody.class);
    }
    private static void ensureExistenceCacheDirectory() throws IOException {
        if (!Files.exists(CACHE_DIR)) Files.createDirectories(CACHE_DIR);
    }

    private static boolean isAcceptable(final Path file, final long cacheAge) {
        final var maxAge = System.currentTimeMillis() - cacheAge;
        return Files.exists(file) && file.toFile().lastModified() > maxAge;
    }
    private static byte[] hashSHA256(final String data, final Charset charset) {
        return new SHA256().digest(data.getBytes(charset));
    }

}
