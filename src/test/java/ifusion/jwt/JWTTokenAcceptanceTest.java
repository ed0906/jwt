package ifusion.core.crypto.jwt;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTTokenAcceptanceTest {

    private static final String SECRET = "secret";
    private static final String SIGNATURE = "4F95bPgP0BYFS6qva2wpUtpH1uA5bL6e8IfCIkufilc";
    private static final String ENCODED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjAsInBheWxvYWQiOnsiZmllbGQiOiJzb21lIHZhbHVlIn19.4F95bPgP0BYFS6qva2wpUtpH1uA5bL6e8IfCIkufilc";

    @Test
    public void shouldCreateFromPayload() {
        // Given
        SimplePayload payload = new SimplePayload();
        payload.setField("some value");

        // When
        JWTToken token = new JWTToken(payload, SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
        assertThat(token.toString()).isEqualTo(ENCODED);
    }

    @Test
    public void shouldCreateFromBody() {
        // Given
        SimplePayload payload = new SimplePayload();
        payload.setField("some value");
        JWTBody body = new JWTBody(payload);

        // When
        JWTToken token = new JWTToken(body, SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
        assertThat(token.toString()).isEqualTo(ENCODED);
    }

    @Test
    public void shouldCreateFromHeaderAndBody() {
        // Given
        JWTHeader header = new JWTHeader();

        SimplePayload payload = new SimplePayload();
        payload.setField("some value");
        JWTBody body = new JWTBody(payload);

        // When
        JWTToken token = new JWTToken(header, body, SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
        assertThat(token.toString()).isEqualTo(ENCODED);
    }

    @Test
    public void shouldCreateFromHeaderBodyAndSignature() {
        // Given
        JWTHeader header = new JWTHeader();

        SimplePayload payload = new SimplePayload();
        payload.setField("some value");
        JWTBody body = new JWTBody(payload);

        JWTSignature signature = new JWTSignature(SIGNATURE);

        // When
        JWTToken token = new JWTToken(header, body, signature);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
        assertThat(token.toString()).isEqualTo(ENCODED);
    }

    @Test
    public void shouldFailToValidateInvalidSignature() {
        // Given
        JWTHeader header = new JWTHeader();

        SimplePayload payload = new SimplePayload();
        payload.setField("some value");
        JWTBody body = new JWTBody(payload);

        JWTSignature signature = new JWTSignature("signature");

        // When
        JWTToken token = new JWTToken(header, body, signature);

        // Then
        assertThat(token.isValid(SECRET)).isFalse();
        assertThat(token.toString()).endsWith("signature");
    }

    @Test
    public void shouldDecodeValidToken() {
        // When
        JWTToken token = JWTToken.from(ENCODED);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
        assertThat(token.getHeader().getAlg()).isEqualTo("HS256");
        assertThat(token.getHeader().getTyp()).isEqualTo("JWT");
        assertThat(token.getBody().getExp()).isEqualTo(0l);
        assertThat(token.getBody().getPayload(SimplePayload.class).getField()).isEqualTo("some value");
    }
}