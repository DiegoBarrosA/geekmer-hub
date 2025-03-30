package one.expressdev.geekmer_hub;

import org.springframework.stereotype.Component;

@Component
public class TokenStore {

    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
