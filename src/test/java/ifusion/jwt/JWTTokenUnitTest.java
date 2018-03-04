package ifusion.core.crypto.jwt;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class JWTTokenUnitTest {

    private static final String ENCODED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjF9.8onrqJhmsoas7S-2eOXSmQe1UZfbsK0zZyIw7ik8gZE";
    private static final String HEADER = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    private static final String BODY = "eyJleHAiOjF9";
    private static final String SIGNATURE = "8onrqJhmsoas7S-2eOXSmQe1UZfbsK0zZyIw7ik8gZE";
    private static final String SECRET = "secret";
    public static final long FUTURE_DATE = Long.MAX_VALUE;
    public static final long PAST_DATE = 1l;

    @Mock private JWTHeader header;
    @Mock private JWTBody body;
    @Mock private SimplePayload payload;

    @Test
    public void shouldDecodeOnConstruction() {
        // When
        JWTToken token = JWTToken.from(ENCODED);

        // Then
        assertThat(token.getHeader().toString()).isEqualTo(HEADER);
        assertThat(token.getBody().toString()).isEqualTo(BODY);
        assertThat(token.getSignature().toString()).isEqualTo(SIGNATURE);
    }

    @Test
    public void toStringShouldEncode() {
        // Given
        when(header.toString()).thenReturn(HEADER);
        when(header.getAlg()).thenReturn("HS256");
        when(header.getTyp()).thenReturn("JWT");
        when(body.toString()).thenReturn(BODY);

        // When
        JWTToken token = new JWTToken(header, body, SECRET);

        // Then
        assertThat(token.toString()).isEqualTo(ENCODED);
    }

    @Test
    public void shouldVerifyGivenCorrectSecretAndNotExpired() {
        // Given
        when(header.getAlg()).thenReturn(JWTSignatureAlgorithm.HS256.name());
        when(body.getExp()).thenReturn(FUTURE_DATE);
        JWTToken token = new JWTToken(header, body, SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isTrue();
    }

    @Test
    public void shouldFailToVerifyGivenIncorrectSecret() {
        // Given
        when(header.getAlg()).thenReturn(JWTSignatureAlgorithm.HS256.name());
        when(body.getExp()).thenReturn(FUTURE_DATE);
        JWTToken token = new JWTToken(header, body, SECRET);

        // Then
        assertThat(token.isValid("other secret")).isFalse();
    }

    @Test
    public void shouldFailToVerifyGivenWhenExpired() {
        // Given
        when(header.getAlg()).thenReturn(JWTSignatureAlgorithm.HS256.name());
        when(body.getExp()).thenReturn(PAST_DATE);
        JWTToken token = new JWTToken(header, body, SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isFalse();
    }

    @Test
    public void shouldFailToVerifyGivenTamperedToken() {
        // Given
        JWTToken token = JWTToken.from(HEADER + ".eyJleHAiOjJ9." + SECRET);

        // Then
        assertThat(token.isValid(SECRET)).isFalse();
    }

    @Test
    public void shouldFailToVerifyGivenTamperedTokenAndSecret() {
        // Given
        JWTToken token = JWTToken.from(HEADER + ".eyJleHAiOjJ9.a2L-k1QziICYhk2iaB1256ZoYy3ycelwy_U6_gQnUOs");

        // Then
        assertThat(token.isValid(SECRET)).isFalse();
    }

}