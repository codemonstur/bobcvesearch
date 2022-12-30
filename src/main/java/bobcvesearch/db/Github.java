package bobcvesearch.db;

// I would like to be able to list the active security advisories for a given project.
// The thinking is that your bob project should not depend on software with any active
// advisories still open.
//
// No luck yet. Tried scraping the main website. Keep getting a 406 when I try to call
// /<username>/<project>/security/counts. Tried looking for an API call that might give
// me this info. No luck
public enum Github {;

// This calls the /security/counts endpoint. Returns a 406 Not Acceptable.
//        String s = newHttpCall()
//            .scheme("https").hostname("github.com")
//            .post("/x-stream/xstream/security/counts")
//            .header("Accept", "application/json")
//            .body(new MultipartForm()
//                .add("_method", "GET".getBytes(US_ASCII))
//                .add("items[item-0][type]", "advisories".getBytes(US_ASCII)))
//            .execute()
//            .verifySuccess()
//            .fetchBodyAsString();
//        System.out.println(s);

// This attempts to scrape the main page, fails because JavaScript builds the page with
// the above call.
//        Document document = Jsoup.connect("https://").get();
//        Element element = document.selectFirst("li[data-item-id=\"advisories\"]");
//        System.out.println(element);

}
