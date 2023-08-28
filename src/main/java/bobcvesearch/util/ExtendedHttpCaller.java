package bobcvesearch.util;

import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.HttpCallResponse;
import httpclient.Serializers;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import static bobthebuildtool.services.Constants.HTTP_CLIENT;
import static bobthebuildtool.services.Constants.JSON_PARSER;
import static java.net.http.HttpResponse.BodyHandlers.ofString;
import static java.nio.charset.StandardCharsets.UTF_8;

public enum ExtendedHttpCaller {;

    public static HttpCallRequest newHttpCall() {
        return new HttpCallRequest(HTTP_CLIENT, SERIALIZERS);
    }

    private static final Serializers SERIALIZERS = new Serializers.Builder()
        .json(new Serializers.Serializer() {
            public <U> U fromData(final byte[] data, final Class<U> clazz) {
                return JSON_PARSER.fromJson(new String(data, UTF_8), clazz);
            }
        })
        .build();

}
