package bobcvesearch.error;

public final class ProjectHasVulnerabilities extends Exception {
    public ProjectHasVulnerabilities(int size) {
        super("Found " + size + " vulnerabilities in your project dependencies");
    }
}
