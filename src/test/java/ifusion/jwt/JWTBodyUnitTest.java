package ifusion.core.crypto.jwt;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTBodyUnitTest {

    private final static String ENCODED = "eyJleHAiOjEsInBheWxvYWQiOnsiZmllbGQiOiJ2YWx1ZSJ9fQ";

    @Test
    public void shouldDecodeOnConstruction() {
        // When
        JWTBody body = JWTBody.from(ENCODED);

        // Then
        assertThat(body.getExp()).isEqualTo(1l);

        SimplePayload payload = body.getPayload(SimplePayload.class);
        assertThat(payload.getField()).isEqualTo("value");
    }

    @Test
    public void toStringShouldEncode() {
        // Given
        long exp = 1l;
        SimplePayload payload = new SimplePayload();
        payload.setField("value");

        // When
        JWTBody body = new JWTBody(exp, payload);

        // Then
        assertThat(body.toString()).isEqualTo(ENCODED);
    }

}