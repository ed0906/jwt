package ifusion.core.crypto.jwt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class JWTBody {

    private long exp;
    private Object payload;

    public JWTBody(){}

    public JWTBody(long expiry) {
        this.exp = expiry;
    }

    public JWTBody(Object payload) {
        this.payload = payload;
    }

    public JWTBody(long exp, Object payload) {
        this.exp = exp;
        this.payload = payload;
    }

    public static JWTBody from(String bodyJWT) {
        String decoded = new String(Base64.decodeBase64(bodyJWT));
        try {
            ObjectMapper json = new ObjectMapper();
            JsonNode node = json.readTree(decoded);
            JWTBody jwtBody = new JWTBody();
            if (node.has("exp")) {
                jwtBody.setExp(node.get("exp").asLong());
            }
            if (node.has("payload")) {
                jwtBody.setPayload(json.treeToValue(node.get("payload"), Object.class));
            }
            return jwtBody;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid body", e);
        }
    }

    public long getExp() {
        return exp;
    }

    public void setExp(long exp) {
        this.exp = exp;
    }

    public Object getPayload() {
        return payload;
    }

    public <T> T getPayload(Class<T> clazz) {
        return new ObjectMapper().convertValue(payload, clazz);
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }

    @Override
    public String toString() {
        try {
            return Base64.encodeBase64URLSafeString(new ObjectMapper().writeValueAsString(this).getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
