package ifusion.core.crypto.jwt;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

public class JWTToken {

    private final JWTHeader header;
    private final JWTBody body;
    private final JWTSignature signature;

    public JWTToken(Object payload, String secret) {
        this.header = new JWTHeader();
        this.body = new JWTBody(payload);
        this.signature = encode(secret);
    }

    public JWTToken(JWTBody body, String secret) {
        this.header = new JWTHeader();
        this.body = body;
        this.signature = encode(secret);
    }

    public JWTToken(JWTHeader header, JWTBody body, String secret) {
        this.header = header;
        this.body = body;
        this.signature = encode(secret);
    }

    public JWTToken(JWTHeader header, JWTBody body, JWTSignature signature) {
        this.header = header;
        this.body = body;
        this.signature = signature;
    }

    public static JWTToken from(String jwt) {
        String[] components = jwt.split("\\.");
        if (components.length != 3) {
            throw new IllegalArgumentException("Token must have 3 components separated by a .");
        }
        return new JWTToken(
                JWTHeader.from(components[0]),
                JWTBody.from(components[1]),
                JWTSignature.from(components[2])
        );
    }

    private JWTSignature encode(String secret) {
        try {
            String raw = header.toString() + "." + body.toString();
            return new JWTSignature(JWTEncoder.encode(JWTSignatureAlgorithm.valueOf(header.getAlg()), raw, secret));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public JWTHeader getHeader() {
        return header;
    }

    public JWTBody getBody() {
        return body;
    }

    public JWTSignature getSignature() {
        return signature;
    }

    public boolean isValid(String secret) {
        String raw = header.toString() + "." + body.toString();
        return isLive()
                && this.signature != null
                && StringUtils.equals(this.signature.toString(), JWTEncoder.encode(JWTSignatureAlgorithm.valueOf(header.getAlg()), raw, secret));
    }

    public boolean isLive() {
        return body.getExp() == 0 || body.getExp() > System.currentTimeMillis();
    }

    @Override
    public boolean equals(Object o) {
        return EqualsBuilder.reflectionEquals(this, o);
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    @Override
    public String toString() {
        return header.toString() + "." + body.toString() + "." + signature.toString();
    }
}
