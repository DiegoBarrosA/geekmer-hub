package one.expressdev.geekmer_hub;

import one.expressdev.geekmer_hub.JWTAuthenticationConfig;
import one.expressdev.geekmer_hub.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @Autowired
    JWTAuthenticationConfig jwtAuthtenticationConfig;

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("login")
    public String login(
        @RequestParam("user") String username,
        @RequestParam("password") String password
    ) {
        final UserDetails userDetails = userDetailsService.loadUserByUsername(
            username
        );

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            throw new RuntimeException("Invalid login");
        }

        String token = jwtAuthtenticationConfig.getJWTToken(username);

        return token;
    }
}
