package tools;

import us.springett.cvss.Cvss;
import us.springett.cvss.Score;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class Requests {

    public static void main(final String... args) throws IOException {
//        OSVdev.callOsvdev("com.google.protobuf", "protobuf-java", "3.19.4");
//        OSVdev.callOsvdev("org.yaml", "snakeyaml", "1.27");
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        Instant parse = Instant.parse("2022-12-12T15:30:33Z");
        LocalDateTime cet = LocalDateTime.ofInstant(parse, ZoneId.systemDefault());
        System.out.println(formatter.format(cet));
    }

}
