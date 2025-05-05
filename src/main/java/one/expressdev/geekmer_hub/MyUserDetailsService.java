package one.expressdev.geekmer_hub;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;





import org.springframework.stereotype.Service;


@Service
public class MyUserDetailsService implements UserDetailsService {

    
    private static final Logger logger = LoggerFactory.getLogger(MyUserDetailsService.class);

    @Autowired
    private UserRepository userRepository;

    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Attempting to load user details for username: {}", username);

        
        User user = userRepository.findByUsername(username);

        
        if (user == null) {
            logger.warn("User not found with username: {}", username);
            
            throw new UsernameNotFoundException("User not found with username: " + username);
        }

        logger.info("User found with username: {}", username); 

        
        
        return user;

        
        
            }

    
    
       

}
