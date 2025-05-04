package one.expressdev.geekmer_hub;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority; 
import org.springframework.security.core.context.SecurityContextHolder;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.util.Arrays;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static one.expressdev.geekmer_hub.Constants.*; 
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class) 
class JWTAuthorizationFilterTest {

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @InjectMocks 
    private JWTAuthorizationFilter jwtAuthorizationFilter;

    private final String testUser = "testUser";
    private final List<String> testAuthorities = Arrays.asList("ROLE_USER", "ROLE_ADMIN");
    private SecretKey testSigningKey;

    @BeforeEach
    void setUp() {
        testSigningKey = (SecretKey) getSigningKey(SUPER_SECRET_KEY); 
        
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        
        SecurityContextHolder.clearContext();
    }

    
    private String generateValidToken(String username, List<String> authorities, long expirationMillis) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date exp = new Date(nowMillis + expirationMillis);
        SignatureAlgorithm algorithm = SignatureAlgorithm.HS512; 

        return Jwts.builder()
                .setSubject(username)
                .claim("authorities", authorities)
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(testSigningKey, algorithm)
                .compact();
    }

     
    private String generateTokenWithoutAuthorities(String username, long expirationMillis) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date exp = new Date(nowMillis + expirationMillis);
        SignatureAlgorithm algorithm = SignatureAlgorithm.HS512; 

        return Jwts.builder()
                .setSubject(username)
                
                .setIssuedAt(now)
                .setExpiration(exp)
                .signWith(testSigningKey, algorithm)
                .compact();
    }

    @Test
    void doFilterInternal_ValidToken_ShouldSetAuthenticationAndProceed() throws ServletException, IOException {
        
        String validToken = generateValidToken(testUser, testAuthorities, 3600000); 
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(TOKEN_BEARER_PREFIX + validToken);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNotNull();
        assertThat(authentication.getName()).isEqualTo(testUser);
        assertThat(authentication.getCredentials()).isNull();

        
        assertThat(authentication.getAuthorities())
                .extracting(GrantedAuthority::getAuthority) 
                .containsExactlyInAnyOrderElementsOf(testAuthorities); 
        


        
        verify(filterChain, times(1)).doFilter(request, response);
        
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void doFilterInternal_NoAuthorizationHeader_ShouldClearContextAndProceed() throws ServletException, IOException {
        
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(null);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull(); 

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void doFilterInternal_InvalidPrefix_ShouldClearContextAndProceed() throws ServletException, IOException {
        
        String validToken = generateValidToken(testUser, testAuthorities, 3600000);
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn("InvalidPrefix " + validToken); 

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull(); 

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).sendError(anyInt(), anyString());
    }

    @Test
    void doFilterInternal_ExpiredToken_ShouldReturnForbidden() throws ServletException, IOException {
        
        String expiredToken = generateValidToken(testUser, testAuthorities, -1000); 
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(TOKEN_BEARER_PREFIX + expiredToken);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull(); 

        verify(response, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString()); 
        verify(filterChain, never()).doFilter(request, response); 
    }

     @Test
    void doFilterInternal_MalformedToken_ShouldReturnForbidden() throws ServletException, IOException {
        
        String malformedToken = "thisIsNotAValidJWTStructure";
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(TOKEN_BEARER_PREFIX + malformedToken);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(response, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(filterChain, never()).doFilter(request, response);
    }

    @Test
    void doFilterInternal_InvalidSignatureToken_ShouldReturnForbidden() throws ServletException, IOException {
        
        SecretKey wrongKey = Jwts.SIG.HS512.key().build();
        SignatureAlgorithm algorithm = SignatureAlgorithm.HS512;

        String tokenWithWrongSig = Jwts.builder()
                .setSubject(testUser)
                .claim("authorities", testAuthorities)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(wrongKey, algorithm) 
                .compact();

        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(TOKEN_BEARER_PREFIX + tokenWithWrongSig);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(response, times(1)).setStatus(HttpServletResponse.SC_FORBIDDEN);
        verify(response, times(1)).sendError(eq(HttpServletResponse.SC_FORBIDDEN), anyString());
        verify(filterChain, never()).doFilter(request, response);
    }


    @Test
    void doFilterInternal_ValidToken_MissingAuthoritiesClaim_ShouldClearContextAndProceed() throws ServletException, IOException {
         
        String tokenWithoutAuthorities = generateTokenWithoutAuthorities(testUser, 3600000); 
        when(request.getHeader(HEADER_AUTHORIZACION_KEY)).thenReturn(TOKEN_BEARER_PREFIX + tokenWithoutAuthorities);

        
        jwtAuthorizationFilter.doFilterInternal(request, response, filterChain);

        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull(); 

        verify(filterChain, times(1)).doFilter(request, response);
        verify(response, never()).setStatus(anyInt());
        verify(response, never()).sendError(anyInt(), anyString());
    }
}
