package one.expressdev.geekmer_hub;

import io.github.cdimascio.dotenv.Dotenv;
import one.expressdev.geekmer_hub.PasswordEncoderConfiguration;
import one.expressdev.geekmer_hub.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(
        MyUserDetailsService.class
    );

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    
    private static final Dotenv dotenv = Dotenv.load();
    private String defaultUsername = System.getenv("DEFAULT_USERNAME");
    private String defaultRole = System.getenv("DEFAULT_ROLE");

    {
        logger.info(
            "Default credentials loaded - Username: {}, Role: {}",
            defaultUsername,
            defaultRole
        );
    }

    private String defaultPassword = dotenv.get("DEFAULT_PASSWORD");

    @Override
    public UserDetails loadUserByUsername(String username)
        throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if (user == null) {
            
            User defaultUser = new User();
            defaultUser.setUsername(defaultUsername);
            defaultUser.setPassword(passwordEncoder.encode(defaultPassword));
            userRepository.save(defaultUser);
            logger.info(
                "Default user created and saved: {}",
                defaultUser.getUsername()
            );
            return defaultUser;
        }
        return user;
    }
}
