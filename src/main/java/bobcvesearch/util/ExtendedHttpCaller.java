package bobcvesearch.util;

import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.HttpCallResponse;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static java.net.http.HttpResponse.BodyHandlers.ofString;

public enum ExtendedHttpCaller {;

    private static final HttpClient HTTP_CLIENT = HttpClient.newHttpClient();
    private static final Gson GSON = new Gson();

    public static CustomHttpCallRequest newHttpCall() {
        return new CustomHttpCallRequest();
    }

    public static class CustomHttpCallRequest extends HttpCallRequest<CustomHttpCallRequest> {
        public CustomHttpCallRequest() {
            super(HTTP_CLIENT);
        }
        public CustomHttpCallRequest body(final String body) {
            return body(HttpRequest.BodyPublishers.ofString(body));
        }
        public CustomHttpCallRequest bodyJson(final Object object) {
            return body(HttpRequest.BodyPublishers.ofString(GSON.toJson(object)));
        }
        @Override public CustomHttpCallResponse execute() throws IOException {
            return new CustomHttpCallResponse(send(ofString()));
        }
    }
    public static class CustomHttpCallResponse extends HttpCallResponse<CustomHttpCallResponse> {
        public CustomHttpCallResponse(final HttpResponse<String> response) {
            super(response);
        }
        public <T> T fetchBodyInto(final Class<T> clazz) throws IOException {
            return GSON.fromJson(fetchBodyAsString(), clazz);
        }
    }
}
