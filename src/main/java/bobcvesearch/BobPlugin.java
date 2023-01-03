package bobcvesearch;

import bobcvesearch.db.OSVdev;
import bobcvesearch.util.ProjectHasVulnerabilities;
import bobcvesearch.util.Suppressions.SuppressionsFile;
import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.pojos.error.DependencyResolutionFailed;
import bobthebuildtool.pojos.error.VersionTooOld;
import bobthebuildtool.services.Log;
import jcli.annotations.CliOption;
import jcli.errors.InvalidCommandLine;
import us.springett.cvss.Cvss;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.function.Consumer;

import static bobcvesearch.util.DependencyResolution.listProjectDependencies;
import static bobcvesearch.db.OSVdev.listVulnerabilities;
import static bobcvesearch.util.Suppressions.loadSuppresionsFile;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static bobthebuildtool.services.Update.requireBobVersion;
import static jcli.CliParserBuilder.newCliParser;

public enum BobPlugin {;

    public static void installPlugin(final Project project) throws VersionTooOld {
        requireBobVersion("11");
        project.addCommand("check-cve", "Checks OSV.dev for known vulnerabilities of dependencies", BobPlugin::checkCVE);
    }

    public static class CliCheckCve {
        @CliOption(name = 's', longName = "suppressions", defaultValue = "src/conf/suppressions.yml", description = "The suppressions file to use")
        public Path suppressions;
        @CliOption(name = 'f', longName = "failIfResults", description = "Fails the build if findings")
        public boolean failOnFind;
        @CliOption(name = 'd', longName = "days", defaultValue = "7", description = "The number of days before a new update is attempted")
        public long numDays;
    }

    private static final String FINDING = """
            Published  : %s
            Dependency : %s
            CVE        : %s
            CVSS Score : %s
            Description: %s
             
            """;

    private static int checkCVE(final Project project, final Map<String, String> environment, final String[] args)
            throws DependencyResolutionFailed, InvalidCommandLine, IOException, ProjectHasVulnerabilities {
        final var cli = newCliParser(CliCheckCve::new).name("check-cve").parse(args);

        final Consumer<String> logger = cli.failOnFind ? Log::logError : Log::logWarning;
        final SuppressionsFile sups = loadSuppresionsFile(project, cli.suppressions);

        int found = 0;
        for (final var lib : listProjectDependencies(project)) {
            try {
                for (final var vuln : listVulnerabilities(lib)) {
                    found++;
                    for (final var cve : vuln.aliases()) {
                        if (sups.suppresses(cve, lib.repository)) continue;
                        logger.accept(String.format(FINDING, vuln.published(), lib.repository, toCVE(cve), toCvssScore(vuln), vuln.summary()));
                    }
                    if (vuln.aliases().isEmpty()) {
                        logger.accept(String.format(FINDING, vuln.published(), lib.repository, "NO-CVE-LISTED", toCvssScore(vuln), vuln.summary()));
                    }
                }
            } catch (final Exception e) {
                throw new IllegalArgumentException("Failed to list vulnerabilities for " + lib.repository, e);
            }
        }

        if (found > 0) {
            if (cli.failOnFind) throw new ProjectHasVulnerabilities(found);
            logger.accept("Found " + found + " total vulnerabilities in project dependencies");
        }
        return 0;
    }

    private static final DateTimeFormatter YYYY_MM_DD_HH_MM_SS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static String toHumanDate(final String iso8601) {
        final var instant = Instant.parse(iso8601);
        final var datetime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
        return YYYY_MM_DD_HH_MM_SS.format(datetime);
    }

    private static String toCVE(final String cve) {
        return cve + " (https://nvd.nist.gov/vuln/detail/" + cve + ")";
    }

    private static String toCvssScore(final OSVdev.Vulnerability vuln) {
        if (isNullOrEmpty(vuln.severity())) return "NO SCORE GIVEN";
        final var cvss = vuln.severity().get(0).score();
        final var base = Cvss.fromVector(cvss).calculateScore().getBaseScore();
        return cvss + " (" + base + ")";
    }

}
