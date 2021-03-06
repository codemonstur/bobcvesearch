package bobcvesearch;

import bobcvesearch.error.ProjectHasVulnerabilities;
import bobcvesearch.model.CliCveSearch;
import bobcvesearch.model.Finding;
import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.pojos.error.DependencyResolutionFailed;
import bobthebuildtool.pojos.error.VersionTooOld;
import bobthebuildtool.services.Log;
import jcli.errors.InvalidCommandLine;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static bobcvesearch.core.VulnerabilitySearch.findVulnerabilities;
import static bobthebuildtool.services.Update.requireBobVersion;
import static jcli.CliParserBuilder.newCliParser;

public enum BobPlugin {;

    public static final String DB_LOCATION = ".bob/security/cve";

    public static final List<String> NVD_DB_NAMES = List.of("modified", "recent", "2021", "2020",
            "2019", "2018", "2017", "2016", "2015", "2014", "2013", "2012", "2011", "2010", "2009",
            "2008", "2007", "2006", "2005", "2004", "2003", "2002");

    public static void installPlugin(final Project project) throws VersionTooOld {
        requireBobVersion("0.3.0");
        project.addCommand("check-cve", "Checks if any dependency has a known vulnerability", BobPlugin::checkCVE);
    }

    private static int checkCVE(final Project project, final Map<String, String> environment, final String[] args)
            throws DependencyResolutionFailed, InvalidCommandLine, IOException, ProjectHasVulnerabilities {
        final var cli = newCliParser(CliCveSearch::new).name("check-cve").parse(args);

        final var list = findVulnerabilities(project, cli, NVD_DB_NAMES);
        if (!list.isEmpty()) {
            printVulnerabilities(list, cli.failOnFind);
            if (cli.failOnFind) throw new ProjectHasVulnerabilities(list.size());
        }

        return 0;
    }

    private static void printVulnerabilities(final List<Finding> list, final boolean failOnFind) {
        final Consumer<String> logger = failOnFind ? Log::logError : Log::logWarning;
        for (final var finding : list) {
            logger.accept("Dependency " + finding.coordinate + " matchs CVE " + finding.cve + " with probability " + finding.confidence);
        }
    }

}
