package one.expressdev.geekmer_hub;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;  

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for the MyUserDetailsService class.
 * Uses ReflectionTestUtils to inject test values for default credentials,
 * bypassing the Dotenv/System.getenv initialization within the test context.
 */
@ExtendWith(MockitoExtension.class)  
class MyUserDetailsServiceTest {

     
    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

     
    @InjectMocks
    private MyUserDetailsService myUserDetailsService;

     
    private final String TEST_DEFAULT_USERNAME = "testDefaultUserFromTest";
    private final String TEST_DEFAULT_PASSWORD = "testDefaultPasswordFromTest";
    private final String ENCODED_DEFAULT_PASSWORD = "encodedTestDefaultPassword";  

    @BeforeEach
    void setUp() {
         
         
         
         
        ReflectionTestUtils.setField(myUserDetailsService, "defaultUsername", TEST_DEFAULT_USERNAME);
        ReflectionTestUtils.setField(myUserDetailsService, "defaultPassword", TEST_DEFAULT_PASSWORD);
         
    }

    @Test
    @DisplayName("loadUserByUsername: Should return existing user when found in repository")
    void loadUserByUsername_UserExists_ReturnsUser() {
         
        String existingUsername = "existingTestUser";
         
        User mockUser = new User();
        mockUser.setUsername(existingUsername);
        mockUser.setPassword("someEncodedPassword");
         

         
        when(userRepository.findByUsername(existingUsername)).thenReturn(mockUser);

         
         
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(existingUsername);

         
         
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo(existingUsername);
        assertThat(userDetails.getPassword()).isEqualTo("someEncodedPassword");
        assertThat(userDetails).isSameAs(mockUser);  

         
         
        verify(userRepository, times(1)).findByUsername(existingUsername);
         
        verify(passwordEncoder, never()).encode(anyString());
         
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("loadUserByUsername: Should create, save, and return default user when username not found")
    void loadUserByUsername_UserNotFound_CreatesSavesReturnsDefaultUser() {
         
        String nonExistentUsername = "newUserNotInRepo";

         
        when(userRepository.findByUsername(nonExistentUsername)).thenReturn(null);
         
        when(passwordEncoder.encode(TEST_DEFAULT_PASSWORD)).thenReturn(ENCODED_DEFAULT_PASSWORD);
         

         
         
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(nonExistentUsername);

         
         
        assertThat(userDetails).isNotNull();
        assertThat(userDetails.getUsername()).isEqualTo(TEST_DEFAULT_USERNAME);  
        assertThat(userDetails.getPassword()).isEqualTo(ENCODED_DEFAULT_PASSWORD);  
         

         
         
        verify(userRepository, times(1)).findByUsername(nonExistentUsername);
         
        verify(passwordEncoder, times(1)).encode(TEST_DEFAULT_PASSWORD);

         
        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
         
        verify(userRepository, times(1)).save(userCaptor.capture());

         
        User savedUser = userCaptor.getValue();
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getUsername()).isEqualTo(TEST_DEFAULT_USERNAME);
        assertThat(savedUser.getPassword()).isEqualTo(ENCODED_DEFAULT_PASSWORD);
         
    }

    @Test
    @DisplayName("loadUserByUsername: Should NOT throw UsernameNotFoundException when user is not found")
    void loadUserByUsername_UserNotFound_DoesNotThrowUsernameNotFoundException() {
         
        String nonExistentUsername = "anotherNewUser";
         
        when(userRepository.findByUsername(nonExistentUsername)).thenReturn(null);
         
        when(passwordEncoder.encode(TEST_DEFAULT_PASSWORD)).thenReturn(ENCODED_DEFAULT_PASSWORD);

         
         
        assertThatCode(() -> myUserDetailsService.loadUserByUsername(nonExistentUsername))
                .doesNotThrowAnyException();

         
        verify(userRepository, times(1)).save(any(User.class));
    }
}
