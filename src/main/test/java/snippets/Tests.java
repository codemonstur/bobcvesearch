package snippets;

import java.io.IOException;

import static bobcvesearch.core.NistVulnerabilityDatabase.downloadMetaData;

public class Tests {

    private static final String META_DATA =
        "lastModifiedDate:2021-02-21T12:00:43-05:00\n" +
        "size:2756650\n" +
        "zipSize:219069\n" +
        "gzSize:218925\n" +
        "sha256:85E230E00FEE1C09DB42C31764556B6EE5B59249C6BEEF121EFCCA394B7A9737";

    public static void main(final String... args) throws IOException {
        downloadMetaData("modified");
        //long l = Instant.from(ISO_INSTANT.parse("2021-02-21T12:00:43-05:00")).toEpochMilli();
        //System.out.println(l);
    }

}
