package ifusion.core.crypto.jwt;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JWTEncoder {

    public static String encode(JWTSignatureAlgorithm algorithm, String raw, String secret) {
        try {
            switch (algorithm) {
                case HS256:
                case HS384:
                case HS512:
                    return hmac(algorithm, raw, secret);
                default:
                    throw new IllegalArgumentException("Cannot encode using " + algorithm);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String hmac(JWTSignatureAlgorithm algorithm, String raw, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(algorithm.getValue());
        mac.init(new SecretKeySpec(secret.getBytes(), algorithm.getValue()));
        return Base64.encodeBase64URLSafeString(mac.doFinal(raw.getBytes()));
    }
}
