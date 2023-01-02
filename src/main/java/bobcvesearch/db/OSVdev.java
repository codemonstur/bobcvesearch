package bobcvesearch.db;

import bobthebuildtool.pojos.buildfile.Dependency;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static bobcvesearch.util.ExtendedHttpCaller.newHttpCall;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static java.util.Collections.emptyList;

// OSV.dev is a nice project started by Google. They have a simple HTTP API that I can query with
// a maven GAV and it gives me a list of vulnerabilities back. Perfect. This works.
public enum OSVdev {;

    public record OsvdevRequestBody(String version, @SerializedName("package") PPackage pPackage) {}
    public record OsvdevResponseBody(List<Vulnerability> vulns) {}

    public record Vulnerability(String schema_version, String id, String summary, String details, List<String> aliases,
                                String modified, String published, Map<String, Object> database_specific,
                                List<Reference> references, List<Software> affected, Severity severity) {}
    public record Reference(String type, String url) {}
    public record Software(@SerializedName("package") PPackage ppackage, Map<String, Object> database_specific, List<String> versions) {}
    public record PPackage(String name, String ecosystem, String purl) {}
    public record Severity(String type, String score) {}

    public static List<Vulnerability> listVulnerabilities(final Dependency dependency) throws IOException {
        if (isNullOrEmpty(dependency.repository)) return emptyList();

        final var gav = dependency.repository.split(":");
        final var list = callOsvdev(gav[0], gav[1], gav[2]).vulns();
        return list != null ? list : emptyList();
    }

    private static OsvdevResponseBody callOsvdev(final String groupId, final String artifactId, final String version) throws IOException {
        return callOsvdev(toOsdevRequest(groupId, artifactId, version));
    }

    private static OsvdevRequestBody toOsdevRequest(final String groupId, final String artifactId, final String version) {
        return new OsvdevRequestBody(version, new OSVdev.PPackage(groupId + ":" + artifactId, "Maven", null));
    }

    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.27","package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"}}'
    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.15.3","package":{"name":"org.jsoup:jsoup","ecosystem":"Maven"}}'
    private static OsvdevResponseBody callOsvdev(final OsvdevRequestBody request) throws IOException {
        return newHttpCall()
            .scheme("https").hostname("api.osv.dev")
            .post("/v1/query")
            .bodyJson(request)
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyInto(OsvdevResponseBody.class);
    }

}
