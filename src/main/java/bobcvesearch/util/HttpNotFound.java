package bobcvesearch.util;

import java.io.IOException;

public final class HttpNotFound extends IOException {
    public HttpNotFound(final String message) {
        super(message);
    }
}