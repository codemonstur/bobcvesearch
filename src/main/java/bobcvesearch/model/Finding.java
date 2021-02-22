package bobcvesearch.model;

public final class Finding { public String coordinate; public String cve; public float confidence; String cvssV2; String cvssV3;
    public Finding(String coordinate, String cve, float confidence, String cvssV2, String cvssV3) {
        this.coordinate = coordinate;
        this.confidence = confidence;
        this.cve = cve;
        this.cvssV2 = cvssV2;
        this.cvssV3 = cvssV3;
    }

    @Override
    public int hashCode() {
        return coordinate.hashCode() ^ cve.hashCode();
    }

    @Override
    public boolean equals(final Object o) {
        if (o == null) return false;
        if (o instanceof Finding) {
            final Finding that = (Finding) o;
            return coordinate.equals(that.coordinate) && cve.equals(that.cve);
        }
        return false;
    }

}
