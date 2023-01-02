package tools;

import bobcvesearch.db.OSVdev;

import java.io.IOException;

public class Requests {

    public static void main(final String... args) throws IOException {
        OSVdev.callOsvdev("com.google.protobuf", "protobuf-java", "3.19.4");
        OSVdev.callOsvdev("org.yaml", "snakeyaml", "1.27");
    }

}
