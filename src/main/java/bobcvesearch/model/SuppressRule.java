package bobcvesearch.model;

public final class SuppressRule { String cve; String gav;
    public SuppressRule(String cve, String gav) {
        this.cve = cve;
        this.gav = gav;
    }
}
