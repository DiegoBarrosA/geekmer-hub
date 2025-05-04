package one.expressdev.geekmer_hub;

import static one.expressdev.geekmer_hub.Constants.*;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException; 
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

    
    
    
    


    private Claims setSigningKey(HttpServletRequest request) {
        String jwtToken = request
                .getHeader(HEADER_AUTHORIZACION_KEY)
                .replace(TOKEN_BEARER_PREFIX, "");

        return Jwts.parser()
                .verifyWith((SecretKey) getSigningKey(SUPER_SECRET_KEY))
                .build()
                .parseSignedClaims(jwtToken) 
                .getPayload();
    }

    private void setAuthentication(Claims claims) {
        
        @SuppressWarnings("unchecked") 
        List<String> authorities = (List<String>) claims.get("authorities");

        
        if (authorities == null) {
             authorities = List.of(); 
             
        }


        UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        claims.getSubject(),
                        null, 
                        authorities
                                .stream()
                                .map(SimpleGrantedAuthority::new) 
                                .collect(Collectors.toList())
                );

        SecurityContextHolder.getContext().setAuthentication(auth);
    }

    private boolean isJWTValid(
            HttpServletRequest request,
            HttpServletResponse res 
    ) {
        String authenticationHeader = request.getHeader(
                HEADER_AUTHORIZACION_KEY
        );
        
        return authenticationHeader != null &&
               authenticationHeader.startsWith(TOKEN_BEARER_PREFIX);
    }

    @Override
    protected void doFilterInternal(
            @SuppressWarnings("null") HttpServletRequest request, 
            @SuppressWarnings("null") HttpServletResponse response,
            @SuppressWarnings("null") FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            if (isJWTValid(request, response)) { 
                Claims claims = setSigningKey(request);
                
                if (claims.get("authorities") != null) {
                    setAuthentication(claims);
                    
                } else {
                    
                     
                    SecurityContextHolder.clearContext();
                }
            } else {
                
                SecurityContextHolder.clearContext();
            }
            
            filterChain.doFilter(request, response);

        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            
             
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or expired token."); 
            

        } catch (Exception e) {
            
             
             SecurityContextHolder.clearContext(); 
             response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
             response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Internal server error during authentication processing.");
             
        }
        
        
        
        
        
        
    }
}
