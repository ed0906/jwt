package ifusion.core.crypto.jwt;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class JWTHeaderUnitTest {

    private static final String TYPE = "JWT";
    private static final String ALGORITHM = "HS256";
    private static final String ENCODED = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    @Test
    public void shouldDecodeOnConstruction() {
        // When
        JWTHeader header = JWTHeader.from(ENCODED);

        // Then
        assertThat(header.getTyp()).isEqualTo(TYPE);
        assertThat(header.getAlg()).isEqualTo(ALGORITHM);
    }

    @Test
    public void toStringShouldEncode() {
        // When
        JWTHeader header = new JWTHeader(TYPE, ALGORITHM);

        // Then
        assertThat(header.toString()).isEqualTo(ENCODED);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionIfTypeIsNull() {
        // When
        new JWTHeader(null, ALGORITHM);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionIfAlgIsNull() {
        // When
        new JWTHeader(TYPE, null);
    }

}