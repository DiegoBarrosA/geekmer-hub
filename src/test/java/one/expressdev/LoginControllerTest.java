package one.expressdev.geekmer_hub;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;

import java.util.ArrayList;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;


import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(LoginController.class)
class LoginControllerTest {

    @TestConfiguration
    static class TestSecurityConfig {
        @Bean
        public SecurityFilterChain testFilterChain(HttpSecurity http) throws Exception {
            http
                .csrf(AbstractHttpConfigurer::disable) 
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll() 
                        .anyRequest().authenticated()
                );
            return http.build();
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private MyUserDetailsService userDetailsService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JWTAuthenticationConfig jwtAuthenticationConfig;

    @Test
    void login_Success() throws Exception {
        String username = "testuser";
        String password = "password123";
        String encodedPassword = "encodedPassword";
        String expectedToken = "mock.jwt.token";
        UserDetails mockUserDetails = new User(username, encodedPassword, new ArrayList<>());

        when(userDetailsService.loadUserByUsername(username)).thenReturn(mockUserDetails);
        when(passwordEncoder.matches(password, encodedPassword)).thenReturn(true);
        when(jwtAuthenticationConfig.getJWTToken(username)).thenReturn(expectedToken);

        mockMvc.perform(post("/login")
                        .param("user", username)
                        .param("password", password)
                        
                        )
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.username").value(username))
                .andExpect(jsonPath("$.token").value(expectedToken));
    }

    @Test
    void login_UserNotFound() throws Exception {
        String username = "unknownuser";
        String password = "password123";
        when(userDetailsService.loadUserByUsername(username))
                .thenThrow(new UsernameNotFoundException("User not found"));

        mockMvc.perform(post("/login")
                        .param("user", username)
                        .param("password", password)
                        
                        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("Authentication failed"))
                .andExpect(jsonPath("$.message").value("Invalid username or password"));
    }

    @Test
    void login_InvalidPassword() throws Exception {
        String username = "testuser";
        String password = "wrongpassword";
        String encodedPassword = "encodedPassword";
        UserDetails mockUserDetails = new User(username, encodedPassword, new ArrayList<>());

        when(userDetailsService.loadUserByUsername(username)).thenReturn(mockUserDetails);
        when(passwordEncoder.matches(password, encodedPassword)).thenReturn(false);

        mockMvc.perform(post("/login")
                        .param("user", username)
                        .param("password", password)
                        
                        )
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("Authentication failed"))
                .andExpect(jsonPath("$.message").value("Invalid password"));
    }

    @Test
    void login_JwtGenerationError() throws Exception {
        String username = "testuser";
        String password = "password123";
        String encodedPassword = "encodedPassword";
        UserDetails mockUserDetails = new User(username, encodedPassword, new ArrayList<>());

        when(userDetailsService.loadUserByUsername(username)).thenReturn(mockUserDetails);
        when(passwordEncoder.matches(password, encodedPassword)).thenReturn(true);
        when(jwtAuthenticationConfig.getJWTToken(username)).thenThrow(new RuntimeException("JWT Service Unavailable"));

        mockMvc.perform(post("/login")
                        .param("user", username)
                        .param("password", password)
                        
                        )
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.error").value("Server error"))
.andExpect(jsonPath("$.message").value("An unexpected error occurred"))
	    ;
    }

    @Test
    void login_MissingUserParameter() throws Exception {
        String password = "password123";
        mockMvc.perform(post("/login")
                        .param("password", password)
                        
                        )
                .andExpect(status().isBadRequest());
    }

     @Test
    void login_MissingPasswordParameter() throws Exception {
        String username = "testuser";
        mockMvc.perform(post("/login")
                        .param("user", username)
                        
                        )
                .andExpect(status().isBadRequest());
    }
}
