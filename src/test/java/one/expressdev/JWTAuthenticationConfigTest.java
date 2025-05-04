package one.expressdev.geekmer_hub;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority; 
import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static one.expressdev.geekmer_hub.Constants.*;  
import static org.assertj.core.api.Assertions.*; 

/**
 * Unit tests for the JWTAuthenticationConfig class, focusing on token generation.
 */
class JWTAuthenticationConfigTest {

    private JWTAuthenticationConfig jwtAuthenticationConfig;
    private SecretKey signingKey; 
    private final String testUsername = "testUser123";
    private final long EXPECTED_EXPIRATION_MINUTES = 1440; 

    @BeforeEach
    void setUp() {
        
        jwtAuthenticationConfig = new JWTAuthenticationConfig();
        
        
        signingKey = (SecretKey) getSigningKey(SUPER_SECRET_KEY);
        assertThat(signingKey).isNotNull(); 
    }

    
    private Claims parseTokenAndGetClaims(String bearerToken) {
        assertThat(bearerToken).isNotNull().startsWith(TOKEN_BEARER_PREFIX);
        String token = bearerToken.replace(TOKEN_BEARER_PREFIX, "");

        
        return Jwts.parser()
                .verifyWith(signingKey) 
                .build()
                .parseSignedClaims(token)
                .getPayload(); 
    }

    @Test
    @DisplayName("getJWTToken should return a non-null string starting with 'Bearer '")
    void getJWTToken_ReturnsValidBearerTokenFormat() {
        
        String bearerToken = jwtAuthenticationConfig.getJWTToken(testUsername);

        
        assertThat(bearerToken).isNotNull().isNotEmpty();
        assertThat(bearerToken).startsWith(TOKEN_BEARER_PREFIX);

        
        String tokenPart = bearerToken.replace(TOKEN_BEARER_PREFIX, "");
        assertThat(tokenPart.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("Generated token should contain the correct username as subject")
    void getJWTToken_TokenContainsCorrectSubject() {
        
        String bearerToken = jwtAuthenticationConfig.getJWTToken(testUsername);
        Claims claims = parseTokenAndGetClaims(bearerToken);

        
        assertThat(claims.getSubject()).isEqualTo(testUsername);
    }

    @Test
    @DisplayName("Generated token should contain 'ROLE_USER' in authorities claim")
    void getJWTToken_TokenContainsCorrectAuthorities() {
        
        String bearerToken = jwtAuthenticationConfig.getJWTToken(testUsername);
        Claims claims = parseTokenAndGetClaims(bearerToken);

        
        
        List<String> authorities = claims.get("authorities", List.class);
        assertThat(authorities).isNotNull();
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("Generated token should have valid issuedAt and expiration timestamps")
    void getJWTToken_TokenHasCorrectTimestamps() {
        
        long timeBeforeGeneration = System.currentTimeMillis();
        long acceptableTimeBufferMillis = 2000; 

        
        String bearerToken = jwtAuthenticationConfig.getJWTToken(testUsername);
        long timeAfterGeneration = System.currentTimeMillis();
        Claims claims = parseTokenAndGetClaims(bearerToken);

        
        Date issuedAt = claims.getIssuedAt();
        Date expiration = claims.getExpiration();

        assertThat(issuedAt).isNotNull();
        assertThat(expiration).isNotNull();
        assertThat(expiration).isAfter(issuedAt); 

        
        assertThat(issuedAt.getTime()).isBetween(timeBeforeGeneration - acceptableTimeBufferMillis, timeAfterGeneration + acceptableTimeBufferMillis);

        
        long expectedDurationMillis = TimeUnit.MINUTES.toMillis(EXPECTED_EXPIRATION_MINUTES);
        long actualDurationMillis = expiration.getTime() - issuedAt.getTime();

        assertThat(actualDurationMillis).isCloseTo(expectedDurationMillis, within(acceptableTimeBufferMillis)); 
    }

    @Test
    @DisplayName("Generated token should be verifiable with the correct signing key")
    void getJWTToken_TokenIsSignedCorrectlyAndParsable() {
        
        String bearerToken = jwtAuthenticationConfig.getJWTToken(testUsername);
        String token = bearerToken.replace(TOKEN_BEARER_PREFIX, "");

        
        
        
        assertThatCode(() -> {
            Jwts.parser()
                .verifyWith(signingKey) 
                .build()
                .parseSignedClaims(token); 
        }).doesNotThrowAnyException();
    }
}
