package one.expressdev.geekmer_hub;

import io.github.cdimascio.dotenv.Dotenv;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private static final Dotenv dotenv = Dotenv.configure().ignoreIfMissing().load();

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private final String commonDefaultRole = getEnvVar("DEFAULT_ROLE", "USER");

    
    
    private final String username1 = getEnvVar("DEFAULT_USERNAME", "admin");
    
    private final String password_1 = getEnvVar("DEFAULT_PASSWORD", "password"); 

    
    
    private final String username2 = getEnvVar("DEFAULT_USERNAME_2", "user1");
    
    private final String password_2 = getEnvVar("DEFAULT_PASSWORD_2", "password"); 

    
    
    private final String username3 = getEnvVar("DEFAULT_USERNAME_3", "user2");
    
    private final String password_3 = getEnvVar("DEFAULT_PASSWORD_3", "password"); 
    


    @Override
    public void run(String... args) throws Exception {
        logger.info("Checking and creating default users if necessary...");
        logger.info("Assigning common role '{}' to all default users.", commonDefaultRole);

        
        createDefaultUserIfNotExists(username1, password_1, commonDefaultRole);
        createDefaultUserIfNotExists(username2, password_2, commonDefaultRole);
        createDefaultUserIfNotExists(username3, password_3, commonDefaultRole);

        logger.info("Default user initialization finished.");
    }

    /**
     * Checks if a user exists and creates them if they don't, assigning the specified role.
     *
     * @param username The username for the default user.
     * @param rawPassword The raw (unencoded) password.
     * @param roleToAssign The single role string to assign to the user.
     */
    private void createDefaultUserIfNotExists(String username, String rawPassword, String roleToAssign) {
         if (username == null || username.trim().isEmpty() || rawPassword == null || rawPassword.isEmpty()) {
             
             logger.warn("Skipping creation of default user due to missing username or password. Check configuration and defaults.");
             return;
        }
         if (roleToAssign == null || roleToAssign.trim().isEmpty()) {
             
              logger.warn("Skipping creation of default user '{}' due to missing role configuration.", username);
              return;
         }

        if (userRepository.findByUsername(username) == null) {
            User defaultUser = new User();
            defaultUser.setUsername(username);
            defaultUser.setPassword(passwordEncoder.encode(rawPassword));

            
            
            

            
            
            

            
            
            

            
            
            
            
            
            
            
            
            
            

            
            logger.warn("Role setting logic for user '{}' needs to be implemented/verified in DataInitializer using role '{}' based on User entity structure.", username, roleToAssign);


            userRepository.save(defaultUser);
            logger.info("Created default user: '{}' with assigned role configuration: '{}'", username, roleToAssign); 
        } else {
            logger.info("Default user '{}' already exists. Skipping creation.", username);
        }
    }

    /**
     * Helper to get environment variables, falling back to .env file, then to a default value.
     * Also logs the loaded value (masking passwords).
     */
    private static String getEnvVar(String key, String defaultValue) {
        String value = System.getenv(key); 
        if (value == null || value.trim().isEmpty()) {
            value = dotenv.get(key); 
        }

        if (value == null || value.trim().isEmpty()) {
            
            logger.warn("Environment variable or .env entry for '{}' not found. Using default value: '{}'", key, defaultValue);
            return defaultValue;
        } else {
            
            String loggedValue = key.toLowerCase().contains("password") ? "****" : value; 
            logger.info("Loaded credential from environment/dotenv: {} = {}", key, loggedValue);
            return value;
        }
    }
}
