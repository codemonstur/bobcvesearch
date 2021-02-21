package bobcvesearch.model;

import bobthebuildtool.pojos.buildfile.Dependency;

public final class Finding { Dependency dependency; float confidence; String cve; String cvssV2; String cvssV3;
    public Finding(Dependency dependency, float confidence, String cve, String cvssV2, String cvssV3) {
        this.dependency = dependency;
        this.confidence = confidence;
        this.cve = cve;
        this.cvssV2 = cvssV2;
        this.cvssV3 = cvssV3;
    }
}
