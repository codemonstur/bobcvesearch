package bobcvesearch.model;

import jcli.annotations.CliOption;

import java.nio.file.Path;

public final class CliCveSearch {

    @CliOption(name = 's', longName = "suppressions", defaultValue = "src/conf/suppressions.yml", description = "The suppressions file to use")
    public Path suppressions;
    @CliOption(name = 'f', longName = "failIfResults", description = "Fails the build if findings")
    public boolean failOnFind;
    @CliOption(name = 'd', longName = "days", defaultValue = "7", description = "The number of days before a new update is attempted")
    public long numDays;

}
