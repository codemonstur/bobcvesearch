package bobcvesearch;

import bobcvesearch.db.OSVdev.Vulnerability;
import bobcvesearch.util.ProjectHasVulnerabilities;
import bobthebuildtool.pojos.buildfile.Dependency;
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

import static bobcvesearch.db.OSVdev.listVulnerabilities;
import static bobcvesearch.util.DependencyResolution.listProjectDependencies;
import static bobcvesearch.util.Suppressions.loadSuppresionMatcher;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static bobthebuildtool.services.Update.requireBobVersion;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;
import static java.util.concurrent.TimeUnit.*;
import static jcli.CliParserBuilder.newCliParser;

public enum BobPlugin {;

    public static void installPlugin(final Project project) throws VersionTooOld {
        requireBobVersion("11");
        project.addCommand("check-cve", "Checks OSV.dev for known vulnerabilities of dependencies", BobPlugin::checkCVE);
    }

    public static class CliCheckCve {
        @CliOption(name = 's', longName = "suppressions", defaultValue = "src/conf/suppressions.yml", description = "The suppressions file to use")
        public Path suppressions;
        @CliOption(name = 'f', longName = "failIfResults", description = "Fails the build if vulnerabilities were found")
        public boolean failOnFind;
        @CliOption(longName = "fields", defaultValue = "published,dependency,cve,cve_score,summary", description = "Which fields should be printed in order. Choose from [id, published, modified, dependency, cve, cve_score, summary, details]")
        public String fields;
        @CliOption(longName = "cache-timeout", defaultValue = "1d", description = "The maximum age of a cached result. Format is a number followed by unit. ie '1m' or '5h'")
        public String cacheTimeout;
    }

    public interface FindingLayout {
        String report(Dependency dependency, Vulnerability vulnerability, String cve);
    }

    private static final Map<String, FindingLayout> FINDING_REPORT_FIELDS = ofEntries(
        entry("id", (dependency, vulnerability, cve) -> "ID         : " + vulnerability.id()),
        entry("published", (dependency, vulnerability, cve) -> "Published  : " + toHumanDate(vulnerability.published())),
        entry("modified", (dependency, vulnerability, cve) -> "Modified   : " + toHumanDate(vulnerability.modified())),
        entry("dependency", (dependency, vulnerability, cve) -> "Dependency : " + dependency.repository),
        entry("cve", (dependency, vulnerability, cve) -> "CVE        : " + (isNullOrEmpty(cve) ? "NO-CVE-LISTED" : toCVE(cve))),
        entry("cve_score", (dependency, vulnerability, cve) -> "CVSS Score : " + toCvssScore(vulnerability)),
        entry("summary", (dependency, vulnerability, cve) -> "Summary    : " + vulnerability.summary()),
        entry("details", (dependency, vulnerability, cve) -> "Details    : " + vulnerability.details())
    );

    private static int checkCVE(final Project project, final Map<String, String> environment, final String[] args)
            throws DependencyResolutionFailed, InvalidCommandLine, IOException, ProjectHasVulnerabilities {
        final var cli = newCliParser(CliCheckCve::new).name("check-cve").parse(args);

        final Consumer<String> logger = cli.failOnFind ? Log::logError : Log::logWarning;
        final var matcher = loadSuppresionMatcher(project, cli.suppressions);
        final var fields = cli.fields.split(",");

        int found = 0;
        for (final var lib : listProjectDependencies(project)) {
            try {
                for (final var vuln : listVulnerabilities(lib, toMillis(cli.cacheTimeout))) {
                    found++;

                    if (matcher.isOsvIdSuppressed(vuln.id(), lib.repository)) continue;

                    for (final var cve : vuln.aliases()) {
                        if (matcher.isCveSuppressed(cve, lib.repository)) continue;
                        logger.accept(toFinding(lib, vuln, cve, fields));
                    }
                    if (vuln.aliases().isEmpty()) {
                        logger.accept(toFinding(lib, vuln, null, fields));
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

    private static String toFinding(final Dependency lib, final Vulnerability vuln, final String cve, final String[] fields) {
        final var finding = new StringBuilder();
        for (final var field : fields) {
            finding.append(FINDING_REPORT_FIELDS.get(field).report(lib, vuln, cve)).append("\n");
        }
        return finding.append(" ").toString();
    }

    private static long toMillis(final String cacheTimeout) {
        final var unit = switch (cacheTimeout.charAt(cacheTimeout.length()-1)) {
            case 's' -> SECONDS; case 'm' -> MINUTES; case 'h' -> HOURS; case 'd' -> DAYS;
            default -> throw new IllegalArgumentException("Invalid duration value " + cacheTimeout);
        };
        final long value = Long.parseLong(cacheTimeout.substring(0, cacheTimeout.length()-1));
        return unit.toMillis(value);
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

    private static String toCvssScore(final Vulnerability vuln) {
        if (isNullOrEmpty(vuln.severity())) return "NO SCORE GIVEN";
        final var cvss = vuln.severity().get(0).score();
        final var base = Cvss.fromVector(cvss).calculateScore().getBaseScore();
        return cvss + " (" + base + ")";
    }

}
