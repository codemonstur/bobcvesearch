package bobcvesearch.db;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;

import java.io.IOException;
import java.util.List;

public enum Github {;

    // This code attempts the find github advisories by scraping the search page
    // https://github.com/advisories?query=jhy%2Fjsoup
    //
    // The scraping works, and advisory data is extracted. Unfortunately the data
    // doesn't conform to the list of advisories that can be found on the project
    // page of the searched for project:
    // https://github.com/jhy/jsoup/security/advisories
    //
    // Currently (2023-01-06), the search page finds 3 advisories and the project
    // page has only 2. It looks like the search returns advisories that are closed
    // or otherwise dealt with.

    public static List<GithubAdvisory> listAdvisories() throws IOException {
        final var document = Jsoup.connect("https://github.com/advisories?query=jhy%2Fjsoup").get();
        return document.select("body a").stream()
            .filter(link -> isAdvisory(link))
            .map(link -> toGithubFinding(link.parent()))
            .toList();
    }

    private static boolean isAdvisory(final Element link) {
        return link.attr("href").startsWith("/advisories/");
    }

    record GithubAdvisory(String link, String title, String severity, String cve, String datetime) {}

    private static GithubAdvisory toGithubFinding(final Element advisory) {
        final Element link = advisory.selectFirst("a");
        final Element severity = advisory.selectFirst("span");
        final Element cve = advisory.selectFirst("div > div > span");
        final Element time = advisory.selectFirst("relative-time");

        return new GithubAdvisory(link.attr("href"), link.text(), severity.text(), cve.text(), time.attr("datetime"));
    }

}
