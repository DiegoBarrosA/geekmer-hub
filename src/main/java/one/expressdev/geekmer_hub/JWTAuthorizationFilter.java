package one.expressdev.geekmer_hub;

import static one.expressdev.geekmer_hub.Constants.*;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException; // <-- Import added (or ensure io.jsonwebtoken.* is used)
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JWTAuthorizationFilter extends OncePerRequestFilter {

    // Consider adding logging (e.g., using SLF4J)
    // import org.slf4j.Logger;
    // import org.slf4j.LoggerFactory;
    // private static final Logger log = LoggerFactory.getLogger(JWTAuthorizationFilter.class);


    private Claims setSigningKey(HttpServletRequest request) {
        String jwtToken = request
                .getHeader(HEADER_AUTHORIZACION_KEY)
                .replace(TOKEN_BEARER_PREFIX, "");

        return Jwts.parser()
                .verifyWith((SecretKey) getSigningKey(SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(jwtToken) // This line can throw ExpiredJwtException, MalformedJwtException, SignatureException, etc.
                .getPayload();
    }

    private void setAuthentication(Claims claims) {
        // Consider adding null checks and more robust type checking for claims
        @SuppressWarnings("unchecked") // Suppress warning for this specific cast, but be aware of potential ClassCastException
        List<String> authorities = (List<String>) claims.get("authorities");

        // Handle case where authorities might be null or empty in the token
        if (authorities == null) {
             authorities = List.of(); // Assign empty list if null
             // log.warn("Authorities claim missing or null for user: {}", claims.getSubject());
        }


        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        claims.getSubject(),
                        null, // Credentials are not needed here as JWT is validated
                        authorities
                                .stream()
                                .map(SimpleGrantedAuthority::new) // Use constructor reference
                                .collect(Collectors.toList())
                );

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private boolean isJWTValid(
            HttpServletRequest request,
            HttpServletResponse res // Parameter 'res' is unused, consider removing if not needed
    ) {
        String authenticationHeader = request.getHeader(
                HEADER_AUTHORIZACION_KEY
        );
        // Check for non-null AND correct prefix
        return authenticationHeader != null &&
               authenticationHeader.startsWith(TOKEN_BEARER_PREFIX);
    }

    @Override
    protected void doFilterInternal(
            @SuppressWarnings("null") HttpServletRequest request, // Consider removing @SuppressWarnings if using modern Java/IDE checks
            @SuppressWarnings("null") HttpServletResponse response,
            @SuppressWarnings("null") FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            if (isJWTValid(request, response)) { // Pass response only if needed by isJWTValid
                Claims claims = setSigningKey(request);
                // Check authorities claim exists *before* calling setAuthentication
                if (claims.get("authorities") != null) {
                    setAuthentication(claims);
                    // log.debug("User authenticated via JWT: {}", claims.getSubject());
                } else {
                    // Valid token structure/signature, but missing required claim for authorization
                     // log.warn("Valid JWT received for user {} but missing 'authorities' claim.", claims.getSubject());
                    SecurityContextHolder.clearContext();
                }
            } else {
                // No valid JWT header found, clear context
                SecurityContextHolder.clearContext();
            }
            // Proceed with the filter chain ONLY if no JWT exceptions occurred
            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            // Catch JWT-specific exceptions (including SignatureException)
             // log.warn("Invalid JWT received: Type={}, Message={}", e.getClass().getSimpleName(), e.getMessage());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            // Providing the raw exception message might leak info; consider a generic message
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or expired token."); // Use a generic message
            // Do NOT proceed with the filter chain (return is implicit here as sendError was called)

        } catch (Exception e) {
            // Catch any other unexpected exceptions during processing
             // log.error("Unexpected error in JWTAuthorizationFilter", e);
             SecurityContextHolder.clearContext(); // Ensure context is cleared on unexpected errors too
             response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
             response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error during authentication processing.");
             // Do NOT proceed with the filter chain
        }
        // Note: If an exception occurs in the catch blocks above AND sendError is called,
        // the filter chain execution stops implicitly for servlet containers.
        // If you didn't call sendError, you might need an explicit 'return;' in the catch blocks
        // where you don't want the filterChain.doFilter to execute.
        // However, since the filterChain.doFilter call is now outside the first try-catch for JWT exceptions,
        // it won't run if those specific exceptions occur. Added a broader catch for safety.
    }
}
