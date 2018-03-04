package ifusion.core.crypto.jwt;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

import java.io.IOException;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class JWTHeader {

    private String alg = JWTSignatureAlgorithm.HS256.name();
    private String typ = "JWT";

    public JWTHeader(){}

    public JWTHeader(String typ, String alg) {
        if(StringUtils.isEmpty(typ) || StringUtils.isEmpty(alg)){
            throw new IllegalArgumentException("Fields 'typ' and 'alg' are mandatory");
        }
        this.typ = typ;
        this.alg = alg;
    }

    public static JWTHeader from(String headerJWT) {
        String decoded = new String(Base64.decodeBase64(headerJWT));
        try {
            JsonNode node = new ObjectMapper().readTree(decoded);
            if(!node.has("typ") || !node.has("alg")) {
                throw new IllegalArgumentException();
            }
            return new JWTHeader(node.get("typ").asText(), node.get("alg").asText());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid header", e);
        }
    }

    public String getAlg() {
        return alg;
    }

    public String getTyp() {
        return typ;
    }

    public void setAlg(JWTSignatureAlgorithm alg) {
        if(alg == null) {
            throw new IllegalArgumentException("Alg cannot be null");
        }
        this.alg = alg.name();
    }

    public void setTyp(String typ) {
        if(StringUtils.isEmpty(typ)) {
            throw new IllegalArgumentException("typ cannot be empty");
        }
        this.typ = typ;
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
        try {
            return Base64.encodeBase64URLSafeString(new ObjectMapper().writeValueAsString(this).getBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
