package security.jpa.global.security.constants;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ApplicationConstants {

    private static String jwtSecretKey;

    @Value("${jwt.secret-key}")
    public void setJwtSecretKey(String jwtSecretKey) {
        ApplicationConstants.jwtSecretKey = jwtSecretKey;
    }

    public static String getJwtSecretKey() {
        return jwtSecretKey;
    }
}
