package bobcvesearch.db;

import bobcvesearch.util.HttpNotFound;

import java.io.IOException;
import java.util.List;

import static bobcvesearch.util.ExtendedHttpCaller.newHttpCall;
import static bobthebuildtool.services.Functions.encodeUrl;

// This class provides some basic functionality to query the NIST NVD database.
// You can get basic info on a given CVE.
// The code isn't connected to anything because I don't know what to do with it.
// There is no easy way to connect a CVE to a given version of a library. So I
// don't know if the CVE applies to a
public enum NistNvd {;

    record NistNvdResponse(int resultsPerPage, int startIndex, int totalResults, String format, String version,
                           String timestamp, List<Vulnerability> vulnerabilities) {}
    record Vulnerability(Cve cve) {}
    // Omitted Configurations, and References fields
    record Cve(String id, String sourceIdentifier, String published, String lastModified, String vulnStatus,
               List<Text> descriptions, Metrics metrics, List<Weakness> weaknesses) {}
    record Text(String lang, String value) {}
    record Metrics(List<CvssMetricV31> cvssMetricV31, List<CvssMetricV2> cvssMetricV2) {}
    record CvssMetricV31(String source, String type, CvssDataV31 cvssData, double exploitabilityScore,
                         double impactScore) {}
    record CvssDataV31(String version, String vectorString, String attackVector, String attackComplexity,
                       String privilegesRequired, String userInteraction, String scope, String confidentialityImpact,
                       String integrityImpact, String availabilityImpact, double baseScore, String baseSeverity) {}
    record CvssMetricV2(String source, String type, CvssDataV2 cvssData, String baseSeverity,
                        double exploitabilityScore, double impactScore, boolean acInsufInfo,
                        boolean obtainAllPrivilege, boolean obtainUserPrivilege,
                        boolean obtainOtherPrivilege, boolean userInteractionRequired) {}
    record CvssDataV2(String version, String vectorString, String accessVector, String accessComplexity,
                      String authentication,
                      String confidentialityImpact, String integrityImpact, String availabilityImpact,
                      double baseScore) {}
    record Weakness(String source, String type, List<Text> description) {}

    private static Vulnerability getCVE(final String cve) throws IOException {
        final var response = newHttpCall()
            .scheme("https").hostname("services.nvd.nist.gov")
            .get("/rest/json/cves/2.0?cveId=" + encodeUrl(cve))
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyInto(NistNvdResponse.class);
        if (response.totalResults == 0) throw new HttpNotFound(cve + " not found");

        return response.vulnerabilities().get(0);
    }

}
