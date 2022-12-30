package bobcvesearch.util;

public final class ProjectHasVulnerabilities extends Exception {
    public ProjectHasVulnerabilities(final int size) {
        super("Found " + size + " vulnerabilities in your project dependencies");
    }
}
