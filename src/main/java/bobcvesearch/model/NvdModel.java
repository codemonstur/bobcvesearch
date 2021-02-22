package bobcvesearch.model;

import java.util.ArrayList;
import java.util.List;

import static bobthebuildtool.services.Functions.isNullOrEmpty;

public final class NvdModel {
    String CVE_data_type; String CVE_data_format; String CVE_data_version; String CVE_data_numberOfCVEs;
    String CVE_data_timestamp; public List<CveItem> CVE_Items;

    public final class CveItem {
        Cve cve; Configurations configurations; Impact impact; String publishedDate; String lastModifiedDate;

        public String getID() {
            return cve.CVE_data_meta.ID;
        }

        public List<String> getCPEs() {
            final var list = new ArrayList<String>();

            if (configurations != null && configurations.nodes != null) {
                for (final var node : configurations.nodes) {
                    if (node.cpe_match == null) continue;
                    for (final var cpe : node.cpe_match) {
                        if (isNullOrEmpty(cpe.cpe23Uri)) continue;
                        list.add(cpe.cpe23Uri);
                    }
                }
            }
            return list;
        }

        public String getDescription() {
            final var builder = new StringBuilder();

            if (cve != null && cve.description != null && cve.description.description_data != null) {
                for (final var description : cve.description.description_data) {
                    if (description.value == null) continue;
                    builder.append(description.value).append("\n\n");
                }
            }

            return builder.toString();
        }

        public String getCvssV2() {
            return impact != null
                && impact.baseMetricV2 != null
                && impact.baseMetricV2.cvssV2 != null
                && impact.baseMetricV2.cvssV2.baseScore != null
                 ? impact.baseMetricV2.cvssV2.baseScore.toString() : "";
        }

        public String getCvssV3() {
            return impact != null
                && impact.baseMetricV3 != null
                && impact.baseMetricV3.cvssV3 != null
                && impact.baseMetricV3.cvssV3.baseScore != null
                 ? impact.baseMetricV3.cvssV3.baseScore.toString() : "";
        }
    }

    public static class Cve { String data_type; String data_format; String data_version; CveMetaData CVE_data_meta;
        ProblemTypeWrapper problemtype; References references; DescriptionWrapper description; }
    public static class CveMetaData { String ID; String ASSIGNER; }
    public static class ProblemTypeWrapper { List<ProblemType> problemtype_data; }
    public static class ProblemType { List<Description> description; }
    public static class References { List<ReferenceData> reference_data; }
    public static class ReferenceData { String url; String name; String refsource; List<String> tags; }
    public static class DescriptionWrapper { List<Description> description_data; }
    public static class Description { String lang; String value; }

    public static class Configurations { String CVE_data_version; List<Nodes> nodes; }
    public static class Nodes { String operator; List<CpeMatch> cpe_match; }
    public static class CpeMatch { Boolean vulnerable; String cpe23Uri; String versionEndIncluding; }

    public static class Impact { BaseMetricV2 baseMetricV2; BaseMetricV3 baseMetricV3; }
    public static class BaseMetricV2 { CvssV2 cvssV2; String severity; Double exploitabilityScore; Double impactScore;
        Boolean acInsufInfo; Boolean obtainAllPrivilege; Boolean obtainUserPrivilege; Boolean obtainOtherPrivilege;
        Boolean userInteractionRequired; }
    public static class CvssV2 { String version; String vectorString; String accessVector; String accessComplexity;
        String authentication; String confidentialityImpact; String integrityImpact; String availabilityImpact;
        Double baseScore; }
    public static class BaseMetricV3 { CvssV3 cvssV3; Double exploitabilityScore; Double impactScore; }
    public static class CvssV3 { String version; String vectorString; String attackVector; String attackComplexity;
        String privilegesRequired; String userInteraction; String scope; String confidentialityImpact;
        String integrityImpact; String availabilityImpact; Double baseScore; String baseSeverity; }

}
