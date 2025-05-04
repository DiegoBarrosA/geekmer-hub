package one.expressdev.geekmer_hub;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;  

import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Unit tests for the User entity class.
 */
class UserTest {

    private User user;

    @BeforeEach
    void setUp() {
        user = new User();
    }

    @Test
    @DisplayName("Getter and Setter for Id should work correctly")
    void testIdGetterSetter() {
        Integer testId = 123;
        user.setId(testId);
        Integer actualId = user.getId();

        assertThat(actualId).isEqualTo(testId);
    }

    @Test
    @DisplayName("Getter and Setter for Username should work correctly")
    void testUsernameGetterSetter() {
        String testUsername = "testUser";

        user.setUsername(testUsername);
        String actualUsername = user.getUsername(); 
        assertThat(actualUsername).isEqualTo(testUsername);
    }

    @Test
    @DisplayName("Getter and Setter for Email should work correctly")
    void testEmailGetterSetter() {
        String testEmail = "test@example.com";

        user.setEmail(testEmail);
        String actualEmail = user.getEmail();
        assertThat(actualEmail).isEqualTo(testEmail);
    }

    @Test
    @DisplayName("Getter and Setter for Password should work correctly")
    void testPasswordGetterSetter() {
        String testPassword = "password123";

        user.setPassword(testPassword);
        String actualPassword = user.getPassword(); 
        assertThat(actualPassword).isEqualTo(testPassword);
    }


    @Test
    @DisplayName("getAuthorities should throw UnsupportedOperationException")
    void getAuthorities_ShouldThrowUnsupportedOperationException() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> user.getAuthorities())
                .withMessageContaining("Unimplemented method 'getAuthorities'");
    }

    @Test
    @DisplayName("isAccountNonExpired should throw UnsupportedOperationException")
    void isAccountNonExpired_ShouldThrowUnsupportedOperationException() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> user.isAccountNonExpired())
                .withMessageContaining("Unimplemented method 'isAccountNonExpired'");
    }

    @Test
    @DisplayName("isAccountNonLocked should throw UnsupportedOperationException")
    void isAccountNonLocked_ShouldThrowUnsupportedOperationException() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> user.isAccountNonLocked())
                .withMessageContaining("Unimplemented method 'isAccountNonLocked'");
    }

    @Test
    @DisplayName("isCredentialsNonExpired should throw UnsupportedOperationException")
    void isCredentialsNonExpired_ShouldThrowUnsupportedOperationException() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> user.isCredentialsNonExpired())
                .withMessageContaining("Unimplemented method 'isCredentialsNonExpired'");
    }

    @Test
    @DisplayName("isEnabled should throw UnsupportedOperationException")
    void isEnabled_ShouldThrowUnsupportedOperationException() {
        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> user.isEnabled())
                .withMessageContaining("Unimplemented method 'isEnabled'");
    }
}
