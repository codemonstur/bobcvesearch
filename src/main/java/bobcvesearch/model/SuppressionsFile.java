package bobcvesearch.model;

import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.services.Constants;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;

import static java.nio.file.Files.isRegularFile;
import static java.nio.file.Files.readString;

public final class SuppressionsFile {
    public Set<SuppressRule> rules;

    public static SuppressionsFile loadSuppresionsFile(final Project project, final Path path) throws IOException {
        final var suppresionsFile = project.parentDir.resolve(path);
        if (!isRegularFile(suppresionsFile)) return new SuppressionsFile();
        return Constants.YAML_PARSER.loadAs(readString(suppresionsFile), SuppressionsFile.class);
    }

}
