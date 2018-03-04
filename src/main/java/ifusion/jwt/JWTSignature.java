package ifusion.core.crypto.jwt;

public class JWTSignature {

    private final String signature;

    public JWTSignature(String signature) {
        this.signature = signature;
    }

    public static JWTSignature from(String signature) {
        return new JWTSignature(signature);
    }

    @Override
    public String toString() {
        return signature;
    }
}
